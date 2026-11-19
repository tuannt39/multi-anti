package oauth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
)

const (
	DefaultCallbackPort     = 51121
	DefaultAuthEndpoint     = "https://accounts.google.com/o/oauth2/v2/auth"
	DefaultTokenEndpoint    = "https://oauth2.googleapis.com/token"
	DefaultUserInfoEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"
)

var (
	// DefaultClientID is the build-time default OAuth client ID (injectable via -ldflags -X).
	DefaultClientID = ""
	// DefaultClientSecret is the build-time default OAuth client secret (injectable via -ldflags -X).
	DefaultClientSecret = ""
)

// DefaultScopes lists the OAuth scopes requested by native agy 1.5.10.
var DefaultScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/cclog",
	"https://www.googleapis.com/auth/experimentsandconfigs",
	"https://www.googleapis.com/auth/aicode",
	"openid",
}

// ErrMissingClientID indicates no OAuth client_id was configured via Config, environment, or build flags.
var ErrMissingClientID = errors.New("missing OAuth client_id: set MULTI_ANTI_OAUTH_CLIENT_ID or build with -ldflags")

// ErrRefreshRevoked indicates the OAuth server permanently rejected the refresh token or client.
var ErrRefreshRevoked = errors.New("oauth refresh revoked")

// ErrMissingAuthCode indicates no authorization code was provided in the callback or manual input.
var ErrMissingAuthCode = errors.New("missing authorization code")

// Config configures GoogleOAuthClient endpoints, loopback address, and transport hooks.
type Config struct {
	ClientID         string
	ClientSecret     string
	Scopes           []string
	AuthEndpoint     string
	TokenEndpoint    string
	UserInfoEndpoint string
	CallbackAddr     string
	HTTPClient       *http.Client
	OpenBrowserFn    func(url string) error
}

// LoginOptions controls interactive vs headless OAuth login behavior.
type LoginOptions struct {
	NoBrowser    bool
	StrictPort   bool
	ManualInput  io.Reader
	PromptOutput io.Writer
	Timeout      time.Duration
}

// OAuthClient performs OAuth login, token refresh, and native token file import.
type OAuthClient interface {
	Login(ctx context.Context, opts LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error)
	Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error)
	ImportNativeToken(ctx context.Context, tokenPath string) (domain.AccountIdentity, domain.AccountCredentials, error)
}

// GoogleOAuthClient implements OAuthClient against Google's OAuth2 endpoints.
type GoogleOAuthClient struct {
	cfg Config
}

// NewGoogleOAuthClient returns a GoogleOAuthClient with defaults applied for omitted Config fields.
func NewGoogleOAuthClient(cfg Config) *GoogleOAuthClient {
	cfg.ClientID = firstNonEmpty(cfg.ClientID, os.Getenv("MULTI_ANTI_OAUTH_CLIENT_ID"), DefaultClientID)
	cfg.ClientSecret = firstNonEmpty(cfg.ClientSecret, os.Getenv("MULTI_ANTI_OAUTH_CLIENT_SECRET"), DefaultClientSecret)
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = slices.Clone(DefaultScopes)
	} else {
		cfg.Scopes = slices.Clone(cfg.Scopes)
	}
	if strings.TrimSpace(cfg.AuthEndpoint) == "" {
		cfg.AuthEndpoint = DefaultAuthEndpoint
	}
	if strings.TrimSpace(cfg.TokenEndpoint) == "" {
		cfg.TokenEndpoint = DefaultTokenEndpoint
	}
	if strings.TrimSpace(cfg.UserInfoEndpoint) == "" {
		cfg.UserInfoEndpoint = DefaultUserInfoEndpoint
	}
	if strings.TrimSpace(cfg.CallbackAddr) == "" {
		cfg.CallbackAddr = fmt.Sprintf("127.0.0.1:%d", DefaultCallbackPort)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.OpenBrowserFn == nil {
		cfg.OpenBrowserFn = openBrowserCrossPlatform
	}
	return &GoogleOAuthClient{cfg: cfg}
}

type authCodeResult struct {
	code string
	err  error
}

// Login executes PKCE OAuth authorization via a local loopback HTTP callback, with manual input fallback.
func (c *GoogleOAuthClient) Login(ctx context.Context, opts LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
	if strings.TrimSpace(c.cfg.ClientID) == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, ErrMissingClientID
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("generate PKCE: %w", err)
	}
	state, err := randomURLToken(24)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("generate state: %w", err)
	}

	ln, listenErr := listenLoopback(c.cfg.CallbackAddr, opts.StrictPort)
	if listenErr != nil {
		if opts.StrictPort || opts.ManualInput == nil {
			return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("listen oauth callback on %q: %w", c.cfg.CallbackAddr, listenErr)
		}
	}

	callbackHost := c.cfg.CallbackAddr
	if ln != nil {
		callbackHost = ln.Addr().String()
	}
	redirectURI := fmt.Sprintf("http://%s/oauth-callback", callbackHost)

	authURL, err := c.buildAuthURL(redirectURI, challenge, state)
	if err != nil {
		if ln != nil {
			_ = ln.Close()
		}
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}

	resultCh := make(chan authCodeResult, 2)
	if ln != nil {
		srv := newCallbackServer(state, resultCh)
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case resultCh <- authCodeResult{err: fmt.Errorf("oauth callback server: %w", err)}:
				default:
				}
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
	}

	needManual := opts.NoBrowser
	if !opts.NoBrowser {
		if browserErr := c.cfg.OpenBrowserFn(authURL); browserErr != nil {
			if opts.ManualInput == nil {
				return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("open browser: %w", browserErr)
			}
			needManual = true
			if opts.PromptOutput != nil {
				fmt.Fprintf(opts.PromptOutput, "Browser launch failed (%v).\n", browserErr)
			}
		} else if opts.PromptOutput != nil {
			fmt.Fprintf(opts.PromptOutput, "Open this URL in a browser if it did not open automatically:\n%s\n", authURL)
			if opts.ManualInput != nil {
				fmt.Fprint(opts.PromptOutput, "Waiting for browser callback (or paste the redirect URL / code and press Enter): ")
			}
		}
	}

	if needManual {
		if opts.PromptOutput != nil {
			fmt.Fprintf(opts.PromptOutput, "Open this URL in a browser to sign in:\n%s\n", authURL)
			if opts.ManualInput != nil {
				fmt.Fprint(opts.PromptOutput, "Paste the redirect URL or authorization code: ")
			}
		}
		if opts.ManualInput == nil && ln == nil {
			return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("oauth login requires either a callback listener or manual input")
		}
	}
	if opts.ManualInput != nil {
		go readManualAuthInput(opts.ManualInput, state, ln != nil, resultCh)
	}

	var code string
	select {
	case res := <-resultCh:
		if res.err != nil {
			return domain.AccountIdentity{}, domain.AccountCredentials{}, res.err
		}
		code = res.code
	case <-ctx.Done():
		return domain.AccountIdentity{}, domain.AccountCredentials{}, ctx.Err()
	}

	creds, err := c.exchangeCode(ctx, code, redirectURI, verifier)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}

	identity, err := c.resolveIdentity(ctx, creds)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}
	return identity, creds, nil
}

// Refresh updates creds if AccessToken is empty or expires within skew of now.
// It returns (creds, false, nil) without making an HTTP request when the token is still fresh.
func (c *GoogleOAuthClient) Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(creds.AccessToken) != "" && !creds.Expiry.IsZero() && creds.Expiry.After(now.Add(skew)) {
		return creds, false, nil
	}
	refreshToken := strings.TrimSpace(creds.RefreshToken)
	if refreshToken == "" {
		return creds, false, fmt.Errorf("%w: refresh token missing", ErrRefreshRevoked)
	}

	clientID := firstNonEmpty(creds.ClientID, c.cfg.ClientID)
	if strings.TrimSpace(clientID) == "" {
		return creds, false, ErrMissingClientID
	}
	form := url.Values{
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	tok, err := c.postTokenForm(ctx, form)
	if err != nil {
		return creds, false, err
	}

	updated := creds
	updated.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		updated.RefreshToken = tok.RefreshToken
	}
	if tok.TokenType != "" {
		updated.TokenType = tok.TokenType
	} else if updated.TokenType == "" {
		updated.TokenType = "Bearer"
	}
	if tok.IDToken != "" {
		updated.IDToken = tok.IDToken
	}
	if tok.ExpiresIn > 0 {
		updated.Expiry = now.UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	if updated.ClientID == "" {
		updated.ClientID = clientID
	}
	return updated, true, nil
}

// ImportNativeToken reads and decodes a native antigravity-oauth-token or compatible JSON token file.
func (c *GoogleOAuthClient) ImportNativeToken(ctx context.Context, tokenPath string) (domain.AccountIdentity, domain.AccountCredentials, error) {
	if err := ctx.Err(); err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("read token file %q: %w", tokenPath, err)
	}
	identity, creds, err := DecodeAgyTokenFile(data)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, err
	}
	if strings.TrimSpace(creds.AccessToken) == "" && strings.TrimSpace(creds.RefreshToken) == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, ErrMissingToken
	}
	if strings.TrimSpace(string(identity.Key)) == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, domain.ErrMissingIdentity
	}
	return identity, creds, nil
}

// ParseAuthCodeInput extracts an authorization code from either a raw code string
// or a pasted OAuth redirect URL (verifying expectedState when non-empty).
func ParseAuthCodeInput(raw, expectedState string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrMissingAuthCode
	}

	var q url.Values
	switch {
	case strings.Contains(trimmed, "://"):
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("parse callback URL: %w", err)
		}
		q = u.Query()
	case strings.Contains(trimmed, "?"):
		_, rawQuery, _ := strings.Cut(trimmed, "?")
		parsed, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", fmt.Errorf("parse callback query: %w", err)
		}
		q = parsed
	case strings.HasPrefix(trimmed, "code=") || strings.Contains(trimmed, "&code=") || strings.HasPrefix(trimmed, "error="):
		parsed, err := url.ParseQuery(trimmed)
		if err != nil {
			return "", fmt.Errorf("parse callback query: %w", err)
		}
		q = parsed
	default:
		return trimmed, nil
	}

	if errCode := strings.TrimSpace(q.Get("error")); errCode != "" {
		desc := strings.TrimSpace(q.Get("error_description"))
		if desc != "" {
			return "", fmt.Errorf("oauth callback error %s: %s", errCode, desc)
		}
		return "", fmt.Errorf("oauth callback error: %s", errCode)
	}
	if expectedState != "" && q.Get("state") != expectedState {
		return "", fmt.Errorf("oauth state mismatch")
	}
	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		return "", ErrMissingAuthCode
	}
	return code, nil
}

func (c *GoogleOAuthClient) buildAuthURL(redirectURI, challenge, state string) (string, error) {
	u, err := url.Parse(c.cfg.AuthEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse auth endpoint %q: %w", c.cfg.AuthEndpoint, err)
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("access_type", "offline")
	q.Set("prompt", "consent select_account")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *GoogleOAuthClient) exchangeCode(ctx context.Context, code, redirectURI, verifier string) (domain.AccountCredentials, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {c.cfg.ClientID},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
		"code_verifier": {verifier},
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	tok, err := c.postTokenForm(ctx, form)
	if err != nil {
		return domain.AccountCredentials{}, err
	}

	tokenType := strings.TrimSpace(tok.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}
	var expiry time.Time
	if tok.ExpiresIn > 0 {
		expiry = time.Now().UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return domain.AccountCredentials{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tokenType,
		Expiry:       expiry,
		IDToken:      tok.IDToken,
		ClientID:     c.cfg.ClientID,
	}, nil
}

type tokenEndpointResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (c *GoogleOAuthClient) postTokenForm(ctx context.Context, form url.Values) (tokenEndpointResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("token endpoint request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return tokenEndpointResponse{}, fmt.Errorf("read token response: %w", err)
	}

	var parsed tokenEndpointResponse
	_ = json.Unmarshal(body, &parsed)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errText := strings.ToLower(parsed.Error + " " + string(body))
		isRevoked := (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized) &&
			(strings.Contains(errText, "invalid_grant") ||
				strings.Contains(errText, "invalid_client") ||
				strings.Contains(errText, "unauthorized_client"))
		summary := formatOAuthErrorSummary(parsed.Error, parsed.ErrorDesc, body)
		if isRevoked {
			return tokenEndpointResponse{}, fmt.Errorf("%w: HTTP %d: %s", ErrRefreshRevoked, resp.StatusCode, summary)
		}
		return tokenEndpointResponse{}, fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, summary)
	}

	if strings.TrimSpace(parsed.AccessToken) == "" {
		return tokenEndpointResponse{}, errors.New("token endpoint returned empty access_token")
	}
	return parsed, nil
}

func (c *GoogleOAuthClient) resolveIdentity(ctx context.Context, creds domain.AccountCredentials) (domain.AccountIdentity, error) {
	jwtEmail, jwtSub, jwtName := extractIDTokenClaims(creds.IDToken)

	var uiEmail, uiSub, uiName string
	var uiErr error
	if strings.TrimSpace(c.cfg.UserInfoEndpoint) != "" && strings.TrimSpace(creds.AccessToken) != "" {
		uiEmail, uiSub, uiName, uiErr = c.fetchUserInfo(ctx, creds.AccessToken)
	}

	email := firstNonEmpty(uiEmail, jwtEmail)
	accountID := firstNonEmpty(uiSub, jwtSub)
	displayName := firstNonEmpty(uiName, jwtName)

	key, err := domain.NormalizeAccountKey(email, accountID)
	if err != nil {
		if uiErr != nil {
			return domain.AccountIdentity{}, fmt.Errorf("fetch userinfo: %w", uiErr)
		}
		return domain.AccountIdentity{}, err
	}
	return domain.AccountIdentity{
		Key:         key,
		Email:       email,
		AccountID:   accountID,
		DisplayName: displayName,
	}, nil
}

func (c *GoogleOAuthClient) fetchUserInfo(ctx context.Context, accessToken string) (email, sub, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.UserInfoEndpoint, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("userinfo HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ui struct {
		ID    string `json:"id"`
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &ui); err != nil {
		return "", "", "", fmt.Errorf("parse userinfo response: %w", err)
	}
	return strings.TrimSpace(ui.Email), firstNonEmpty(ui.ID, ui.Sub), strings.TrimSpace(ui.Name), nil
}

func newCallbackServer(expectedState string, out chan<- authCodeResult) *http.Server {
	mux := http.NewServeMux()
	handle := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth-callback" && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		code, err := ParseAuthCodeInput("?"+r.URL.RawQuery, expectedState)
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "<html><body><h3>Authorization failed</h3><p>%s</p></body></html>", html.EscapeString(err.Error()))
			select {
			case out <- authCodeResult{err: err}:
			default:
			}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html><body><h3>Sign-in complete</h3><p>You may close this tab and return to your terminal.</p></body></html>")
		select {
		case out <- authCodeResult{code: code}:
		default:
		}
	}
	mux.HandleFunc("/oauth-callback", handle)
	mux.HandleFunc("/", handle)
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func listenLoopback(addr string, strictPort bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	if strictPort {
		return nil, err
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	return net.Listen("tcp", net.JoinHostPort(host, "0"))
}

func readManualAuthInput(r io.Reader, expectedState string, ignoreEmptyEOF bool, out chan<- authCodeResult) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			select {
			case out <- authCodeResult{err: fmt.Errorf("read manual auth input: %w", err)}:
			default:
			}
			return
		}
		if ignoreEmptyEOF {
			return
		}
		select {
		case out <- authCodeResult{err: ErrMissingAuthCode}:
		default:
		}
		return
	}

	code, parseErr := ParseAuthCodeInput(trimmed, expectedState)
	select {
	case out <- authCodeResult{code: code, err: parseErr}:
	default:
	}
}

// OpenBrowser opens targetURL in the user's default browser when it uses an HTTP or HTTPS scheme.
func OpenBrowser(targetURL string) error {
	return openBrowserCrossPlatform(targetURL)
}

func openBrowserCrossPlatform(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("refusing to open non-HTTP URL %q", targetURL)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", targetURL)
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		// rundll32 passes the URL directly via CreateProcess; cmd /c start would break on '&'.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		return fmt.Errorf("browser launch unsupported on %s", runtime.GOOS)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case waitErr := <-waitDone:
		return waitErr
	case <-timer.C:
		return nil
	}
}

func generatePKCE() (verifier, challenge string, err error) {
	verifier, err = randomURLToken(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomURLToken(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func formatOAuthErrorSummary(errCode, errDesc string, rawBody []byte) string {
	if errCode != "" && errDesc != "" {
		return errCode + ": " + errDesc
	}
	if errCode != "" {
		return errCode
	}
	text := strings.TrimSpace(string(rawBody))
	if text == "" {
		return "empty response"
	}
	return text
}
