package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
)

// AuthMethodConsumer is the auth_method written by native agy 1.5.10 OAuth storage.
const AuthMethodConsumer = "consumer"

// ErrMissingToken indicates decoded token data contains neither an access token nor a refresh token.
var ErrMissingToken = errors.New("missing OAuth token: access_token or refresh_token required")

// AgyStoredToken matches the nested token object in agy 1.5.10's antigravity-oauth-token file.
type AgyStoredToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Expiry       string `json:"expiry,omitempty"`
}

// AgyStoredTokenFile matches agy 1.5.10's exact antigravity-oauth-token JSON schema.
type AgyStoredTokenFile struct {
	Token        AgyStoredToken `json:"token"`
	AuthMethod   string         `json:"auth_method"`
	IDToken      string         `json:"id_token,omitempty"`
	IDTokenEmail string         `json:"id_token_email,omitempty"`
}

// EncodeAgyTokenFile serializes credentials in agy 1.5.10's native antigravity-oauth-token format.
func EncodeAgyTokenFile(email string, creds domain.AccountCredentials) ([]byte, error) {
	accessToken := strings.TrimSpace(creds.AccessToken)
	refreshToken := strings.TrimSpace(creds.RefreshToken)
	if accessToken == "" && refreshToken == "" {
		return nil, ErrMissingToken
	}

	tokenType := strings.TrimSpace(creds.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	var expiry string
	if !creds.Expiry.IsZero() {
		expiry = creds.Expiry.UTC().Format(time.RFC3339Nano)
	}

	idToken := strings.TrimSpace(creds.IDToken)
	idTokenEmail := strings.TrimSpace(email)
	if idTokenEmail == "" && idToken != "" {
		idTokenEmail, _ = ExtractIDTokenClaims(idToken)
	}

	doc := AgyStoredTokenFile{
		Token: AgyStoredToken{
			AccessToken:  accessToken,
			TokenType:    tokenType,
			RefreshToken: refreshToken,
			Expiry:       expiry,
		},
		AuthMethod:   AuthMethodConsumer,
		IDToken:      idToken,
		IDTokenEmail: idTokenEmail,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal agy token file: %w", err)
	}
	return append(data, '\n'), nil
}

// NeedsRefresh reports whether creds lacks an access token or expires within skew of now.
func NeedsRefresh(creds domain.AccountCredentials, skew time.Duration, now time.Time) bool {
	if strings.TrimSpace(creds.AccessToken) == "" || creds.Expiry.IsZero() {
		return true
	}
	return !creds.Expiry.After(now.Add(skew))
}

// EncodeVerifiedAgyToken encodes acc credentials into agy format and verifies decoded ownership matches acc.
func EncodeVerifiedAgyToken(acc domain.Account, creds domain.AccountCredentials) ([]byte, error) {
	encoded, err := EncodeAgyTokenFile(acc.Email, creds)
	if err != nil {
		return nil, fmt.Errorf("encode token for %q: %w", acc.Key, err)
	}
	id, _, err := DecodeAgyTokenFile(encoded)
	if err != nil {
		return nil, fmt.Errorf("verify encoded token for %q: %w", acc.Key, err)
	}
	if email := strings.TrimSpace(acc.Email); email != "" {
		if !strings.EqualFold(strings.TrimSpace(id.Email), email) {
			return nil, fmt.Errorf("staged token email mismatch: got %q, want %q", id.Email, email)
		}
		return encoded, nil
	}
	if id.Key != acc.Key {
		return nil, fmt.Errorf("staged token key mismatch: got %q, want %q", id.Key, acc.Key)
	}
	return encoded, nil
}

type rawTokenFile struct {
	Token *struct {
		AccessToken  string          `json:"access_token"`
		TokenType    string          `json:"token_type"`
		RefreshToken string          `json:"refresh_token"`
		Expiry       json.RawMessage `json:"expiry"`
	} `json:"token"`
	AuthMethod   string          `json:"auth_method"`
	IDToken      string          `json:"id_token"`
	IDTokenEmail string          `json:"id_token_email"`
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	Expiry       json.RawMessage `json:"expiry"`
	ExpiresAt    json.RawMessage `json:"expires_at"`
	ExpiryDate   json.RawMessage `json:"expiry_date"`
	Email        string          `json:"email"`
	AccountID    string          `json:"account_id"`
	Sub          string          `json:"sub"`
	DisplayName  string          `json:"display_name"`
	Name         string          `json:"name"`
	ClientID     string          `json:"client_id"`
}

// DecodeAgyTokenFile parses native agy 1.5.10 token files as well as flat OAuth JSON fallbacks
// and packed "refresh_token|projectId" strings.
func DecodeAgyTokenFile(data []byte) (domain.AccountIdentity, domain.AccountCredentials, error) {
	var raw rawTokenFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("parse agy token file: %w", err)
	}

	var nestedAccess, nestedType, nestedRefresh string
	var nestedExpiry json.RawMessage
	if raw.Token != nil {
		nestedAccess = raw.Token.AccessToken
		nestedType = raw.Token.TokenType
		nestedRefresh = raw.Token.RefreshToken
		nestedExpiry = raw.Token.Expiry
	}

	accessToken := firstNonEmpty(nestedAccess, raw.AccessToken)
	refreshToken := unpackRefreshToken(firstNonEmpty(nestedRefresh, raw.RefreshToken))
	if accessToken == "" && refreshToken == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, ErrMissingToken
	}

	tokenType := firstNonEmpty(nestedType, raw.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}

	expiry, err := parseFirstExpiry(nestedExpiry, raw.Expiry, raw.ExpiresAt, raw.ExpiryDate)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}

	idToken := strings.TrimSpace(raw.IDToken)
	jwtEmail, jwtSub, jwtName := extractIDTokenClaims(idToken)

	email := firstNonEmpty(raw.IDTokenEmail, raw.Email, jwtEmail)
	accountID := firstNonEmpty(raw.AccountID, raw.Sub, jwtSub)
	displayName := firstNonEmpty(raw.DisplayName, raw.Name, jwtName)

	key, err := domain.NormalizeAccountKey(email, accountID)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}

	identity := domain.AccountIdentity{
		Key:         key,
		Email:       email,
		AccountID:   accountID,
		DisplayName: displayName,
	}
	creds := domain.AccountCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Expiry:       expiry,
		IDToken:      idToken,
		ClientID:     strings.TrimSpace(raw.ClientID),
	}
	return identity, creds, nil
}

// ExtractIDTokenClaims decodes unverified JWT claims to read email and sub.
func ExtractIDTokenClaims(idToken string) (email, sub string) {
	email, sub, _ = extractIDTokenClaims(idToken)
	return email, sub
}

func extractIDTokenClaims(idToken string) (email, sub, name string) {
	parts := strings.Split(strings.TrimSpace(idToken), ".")
	if len(parts) < 2 || parts[1] == "" {
		return "", "", ""
	}
	payload := strings.TrimRight(parts[1], "=")
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", ""
	}
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", "", ""
	}
	return strings.TrimSpace(claims.Email), strings.TrimSpace(claims.Sub), strings.TrimSpace(claims.Name)
}

func unpackRefreshToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	// Some third-party Antigravity tools append "|projectId" to the refresh token.
	if head, _, ok := strings.Cut(trimmed, "|"); ok {
		return strings.TrimSpace(head)
	}
	return trimmed
}

func parseFirstExpiry(candidates ...json.RawMessage) (time.Time, error) {
	for _, raw := range candidates {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" || trimmed == "null" || trimmed == `""` {
			continue
		}
		t, err := parseExpiryValue(raw)
		if err != nil {
			return time.Time{}, err
		}
		if !t.IsZero() {
			return t.UTC(), nil
		}
	}
	return time.Time{}, nil
}

func parseExpiryValue(raw json.RawMessage) (time.Time, error) {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		if str == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339Nano, str); err == nil {
			return t.UTC(), nil
		}
		if t, err := time.Parse(time.RFC3339, str); err == nil {
			return t.UTC(), nil
		}
		if num, err := strconv.ParseFloat(str, 64); err == nil {
			return unixNumberToTime(num)
		}
		return time.Time{}, fmt.Errorf("parse expiry %q: unsupported format", str)
	}

	var num float64
	if err := json.Unmarshal(raw, &num); err == nil {
		return unixNumberToTime(num)
	}
	return time.Time{}, fmt.Errorf("parse expiry %s: unsupported JSON value", string(raw))
}

const unixMillisThreshold = 1e12

func unixNumberToTime(v float64) (time.Time, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return time.Time{}, nil
	}
	if v >= unixMillisThreshold {
		sec := int64(v / 1000)
		nsec := int64((v - float64(sec*1000)) * 1e6)
		return time.Unix(sec, nsec).UTC(), nil
	}
	sec, frac := math.Modf(v)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
