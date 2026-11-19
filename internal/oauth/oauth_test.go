package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/platform"
)

func makeTestJWT(t *testing.T, claims map[string]any, pad bool) string {
	t.Helper()
	headerBytes, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	if pad {
		enc = base64.URLEncoding
	}
	return enc.EncodeToString(headerBytes) + "." + enc.EncodeToString(payloadBytes) + ".sig"
}

func TestEncodeDecodeAgyTokenFile(t *testing.T) {
	t.Parallel()

	loc := time.FixedZone("UTC+7", 7*3600)
	expiry := time.Date(2026, 11, 18, 22, 30, 15, 123456000, loc)
	jwt := makeTestJWT(t, map[string]any{
		"email": "Alice@Example.com",
		"sub":   "sub-123",
		"name":  "Alice Example",
	}, false)

	wantCreds := domain.AccountCredentials{
		AccessToken:  "ya29.access",
		RefreshToken: "1//refresh",
		TokenType:    "Bearer",
		Expiry:       expiry.UTC(),
		IDToken:      jwt,
	}

	raw, err := EncodeAgyTokenFile("Alice@Example.com", wantCreds)
	if err != nil {
		t.Fatalf("EncodeAgyTokenFile() error = %v", err)
	}

	var parsed AgyStoredTokenFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("json.Unmarshal(AgyStoredTokenFile) error = %v", err)
	}
	if parsed.AuthMethod != AuthMethodConsumer {
		t.Fatalf("AuthMethod = %q, want %q", parsed.AuthMethod, AuthMethodConsumer)
	}
	if parsed.Token.Expiry != "2026-11-18T15:30:15.123456Z" {
		t.Fatalf("Token.Expiry = %q, want RFC3339Nano UTC", parsed.Token.Expiry)
	}
	if parsed.IDTokenEmail != "Alice@Example.com" {
		t.Fatalf("IDTokenEmail = %q, want Alice@Example.com", parsed.IDTokenEmail)
	}

	gotID, gotCreds, err := DecodeAgyTokenFile(raw)
	if err != nil {
		t.Fatalf("DecodeAgyTokenFile() error = %v", err)
	}
	if gotID.Key != "alice@example.com" || gotID.AccountID != "sub-123" || gotID.DisplayName != "Alice Example" {
		t.Fatalf("identity = %+v", gotID)
	}
	if gotCreds.AccessToken != wantCreds.AccessToken ||
		gotCreds.RefreshToken != wantCreds.RefreshToken ||
		gotCreds.TokenType != "Bearer" ||
		!gotCreds.Expiry.Equal(wantCreds.Expiry) ||
		gotCreds.IDToken != wantCreds.IDToken {
		t.Fatalf("creds = %+v, want %+v", gotCreds, wantCreds)
	}
}

func TestDecodeAgyTokenFileFallbacks(t *testing.T) {
	t.Parallel()

	t.Run("flat JSON with packed refresh_token|projectId and numeric expiry", func(t *testing.T) {
		t.Parallel()
		data := []byte(`{
			"access_token": "ya29.flat",
			"refresh_token": "1//raw-refresh|cloud-proj-42|managed-99",
			"email": "Bob@Example.com",
			"expiry_date": 1795000000000
		}`)
		id, creds, err := DecodeAgyTokenFile(data)
		if err != nil {
			t.Fatalf("DecodeAgyTokenFile() error = %v", err)
		}
		if id.Key != "bob@example.com" {
			t.Fatalf("Key = %q, want bob@example.com", id.Key)
		}
		if creds.RefreshToken != "1//raw-refresh" {
			t.Fatalf("RefreshToken = %q, want 1//raw-refresh", creds.RefreshToken)
		}
		if creds.AccessToken != "ya29.flat" || creds.TokenType != "Bearer" {
			t.Fatalf("creds = %+v", creds)
		}
		if !creds.Expiry.Equal(time.Unix(1795000000, 0).UTC()) {
			t.Fatalf("Expiry = %v, want %v", creds.Expiry, time.Unix(1795000000, 0).UTC())
		}
	})

	t.Run("derives identity solely from id_token sub when email absent", func(t *testing.T) {
		t.Parallel()
		jwt := makeTestJWT(t, map[string]any{"sub": "google-sub-7"}, true)
		data, err := json.Marshal(map[string]any{
			"refresh_token": "1//only-refresh",
			"id_token":      jwt,
		})
		if err != nil {
			t.Fatal(err)
		}
		id, creds, err := DecodeAgyTokenFile(data)
		if err != nil {
			t.Fatalf("DecodeAgyTokenFile() error = %v", err)
		}
		if id.Key != "id:google-sub-7" || id.AccountID != "google-sub-7" {
			t.Fatalf("identity = %+v", id)
		}
		if creds.RefreshToken != "1//only-refresh" {
			t.Fatalf("RefreshToken = %q", creds.RefreshToken)
		}
	})

	t.Run("rejects missing tokens or missing identity", func(t *testing.T) {
		t.Parallel()
		if _, _, err := DecodeAgyTokenFile([]byte(`{"email":"a@b.com"}`)); !errors.Is(err, ErrMissingToken) {
			t.Fatalf("missing token err = %v, want ErrMissingToken", err)
		}
		if _, _, err := DecodeAgyTokenFile([]byte(`{"access_token":"ya29.x"}`)); !errors.Is(err, domain.ErrMissingIdentity) {
			t.Fatalf("missing identity err = %v, want ErrMissingIdentity", err)
		}
	})
}

func TestExtractIDTokenClaims(t *testing.T) {
	t.Parallel()

	jwt := makeTestJWT(t, map[string]any{"email": "carol@example.com", "sub": "sub-9"}, true)
	email, sub := ExtractIDTokenClaims(jwt)
	if email != "carol@example.com" || sub != "sub-9" {
		t.Fatalf("ExtractIDTokenClaims() = (%q, %q), want (carol@example.com, sub-9)", email, sub)
	}

	if e, s := ExtractIDTokenClaims("not-a-jwt"); e != "" || s != "" {
		t.Fatalf("invalid JWT returned (%q, %q), want empty", e, s)
	}
	if e, s := ExtractIDTokenClaims("a.!!!.c"); e != "" || s != "" {
		t.Fatalf("bad base64 JWT returned (%q, %q), want empty", e, s)
	}
}

func TestParseAuthCodeInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		state   string
		want    string
		wantErr bool
	}{
		{
			name:  "raw code",
			raw:   " 4/0AfJohX_raw_code \n",
			state: "state-1",
			want:  "4/0AfJohX_raw_code",
		},
		{
			name:  "full callback URL",
			raw:   "http://127.0.0.1:51121/oauth-callback?state=state-1&code=4%2F0AfJohX_url&scope=openid",
			state: "state-1",
			want:  "4/0AfJohX_url",
		},
		{
			name:  "schemeless callback URL",
			raw:   "localhost:51121/oauth-callback?code=4%2Fschemeless&state=state-1",
			state: "state-1",
			want:  "4/schemeless",
		},
		{
			name:  "callback query string without state expectation",
			raw:   "?code=abc123",
			state: "",
			want:  "abc123",
		},
		{
			name:    "state mismatch rejected",
			raw:     "http://127.0.0.1:51121/oauth-callback?state=wrong&code=abc",
			state:   "expected",
			wantErr: true,
		},
		{
			name:    "oauth error param rejected",
			raw:     "http://127.0.0.1:51121/oauth-callback?error=access_denied&error_description=denied",
			state:   "expected",
			wantErr: true,
		},
		{
			name:    "empty input rejected",
			raw:     "   ",
			state:   "expected",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAuthCodeInput(tc.raw, tc.state)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseAuthCodeInput() err = %v, wantErr=%v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ParseAuthCodeInput() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGoogleOAuthClientLoginPKCE(t *testing.T) {
	t.Parallel()

	jwt := makeTestJWT(t, map[string]any{
		"email": "Alice@Example.com",
		"sub":   "sub-alice",
	}, false)

	var seenChallenge string
	var seenRedirectURI string
	var seenVerifier string

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "unexpected grant_type", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "auth-code-123" {
			http.Error(w, "unexpected code", http.StatusBadRequest)
			return
		}
		seenVerifier = r.Form.Get("code_verifier")
		if seenRedirectURI != "" && r.Form.Get("redirect_uri") != seenRedirectURI {
			http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "ya29.login-access",
			"refresh_token": "1//login-refresh",
			"expires_in":    3600,
			"token_type":    "Bearer",
			"id_token":      jwt,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ya29.login-access" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "sub-alice",
			"email": "Alice@Example.com",
			"name":  "Alice",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Run("loopback callback verifies S256 PKCE and state", func(t *testing.T) {
		client := NewGoogleOAuthClient(Config{
			ClientID:         "test-client",
			AuthEndpoint:     "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint:    srv.URL + "/token",
			UserInfoEndpoint: srv.URL + "/userinfo",
			CallbackAddr:     "127.0.0.1:0",
			HTTPClient:       srv.Client(),
			OpenBrowserFn: func(authURL string) error {
				u, err := url.Parse(authURL)
				if err != nil {
					return err
				}
				q := u.Query()
				if q.Get("code_challenge_method") != "S256" {
					t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
				}
				seenChallenge = q.Get("code_challenge")
				seenRedirectURI = q.Get("redirect_uri")
				cbURL := seenRedirectURI + "?code=auth-code-123&state=" + url.QueryEscape(q.Get("state"))
				go func() {
					resp, err := http.Get(cbURL)
					if err == nil {
						_ = resp.Body.Close()
					}
				}()
				return nil
			},
		})

		id, creds, err := client.Login(context.Background(), LoginOptions{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if id.Key != "alice@example.com" || id.DisplayName != "Alice" {
			t.Fatalf("identity = %+v", id)
		}
		if creds.AccessToken != "ya29.login-access" || creds.RefreshToken != "1//login-refresh" {
			t.Fatalf("creds = %+v", creds)
		}
		sum := sha256.Sum256([]byte(seenVerifier))
		wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if seenChallenge == "" || seenChallenge != wantChallenge {
			t.Fatalf("PKCE challenge mismatch: got %q, want %q from verifier %q", seenChallenge, wantChallenge, seenVerifier)
		}
	})

	t.Run("NoBrowser manual input accepts raw code", func(t *testing.T) {
		seenRedirectURI = ""
		var promptBuf bytes.Buffer
		client := NewGoogleOAuthClient(Config{
			ClientID:         "test-client",
			TokenEndpoint:    srv.URL + "/token",
			UserInfoEndpoint: srv.URL + "/userinfo",
			CallbackAddr:     "127.0.0.1:0",
			HTTPClient:       srv.Client(),
		})

		id, creds, err := client.Login(context.Background(), LoginOptions{
			NoBrowser:    true,
			ManualInput:  strings.NewReader("auth-code-123\n"),
			PromptOutput: &promptBuf,
			Timeout:      5 * time.Second,
		})
		if err != nil {
			t.Fatalf("Login(NoBrowser) error = %v", err)
		}
		if !strings.Contains(promptBuf.String(), "https://accounts.google.com/o/oauth2/v2/auth") {
			t.Fatalf("prompt output missing auth URL: %q", promptBuf.String())
		}
		if id.Key != "alice@example.com" || creds.RefreshToken != "1//login-refresh" {
			t.Fatalf("unexpected result id=%+v creds=%+v", id, creds)
		}
	})

	t.Run("browser failure falls back to manual input and busy port respects StrictPort", func(t *testing.T) {
		seenRedirectURI = ""
		busyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer busyLn.Close()

		client := NewGoogleOAuthClient(Config{
			ClientID:         "test-client",
			TokenEndpoint:    srv.URL + "/token",
			UserInfoEndpoint: srv.URL + "/userinfo",
			CallbackAddr:     busyLn.Addr().String(),
			HTTPClient:       srv.Client(),
			OpenBrowserFn: func(string) error {
				return errors.New("no display available")
			},
		})

		if _, _, err := client.Login(context.Background(), LoginOptions{
			StrictPort:  true,
			ManualInput: strings.NewReader("auth-code-123\n"),
			Timeout:     5 * time.Second,
		}); err == nil {
			t.Fatalf("expected StrictPort error when port is busy")
		}

		var promptBuf bytes.Buffer
		id, _, err := client.Login(context.Background(), LoginOptions{
			StrictPort:   false,
			ManualInput:  strings.NewReader("auth-code-123\n"),
			PromptOutput: &promptBuf,
			Timeout:      5 * time.Second,
		})
		if err != nil {
			t.Fatalf("Login() fallback error = %v", err)
		}
		if id.Key != "alice@example.com" {
			t.Fatalf("identity = %+v", id)
		}
	})
}

func TestGoogleOAuthClientRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	t.Run("skips HTTP call when token is still fresh", func(t *testing.T) {
		t.Parallel()

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		}))
		defer srv.Close()

		client := NewGoogleOAuthClient(Config{
			TokenEndpoint: srv.URL,
			HTTPClient:    srv.Client(),
		})
		creds := domain.AccountCredentials{
			AccessToken:  "ya29.fresh",
			RefreshToken: "1//refresh",
			Expiry:       now.Add(10 * time.Minute),
		}

		got, refreshed, err := client.Refresh(context.Background(), creds, 5*time.Minute, now)
		if err != nil || refreshed {
			t.Fatalf("Refresh() = (%+v, %v, %v), want refreshed=false err=nil", got, refreshed, err)
		}
		if got.AccessToken != "ya29.fresh" || hits.Load() != 0 {
			t.Fatalf("expected zero HTTP calls, hits=%d", hits.Load())
		}
	})

	t.Run("rotates expiring token and preserves existing refresh_token when omitted", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "1//keep-me" {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.new",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
		}))
		defer srv.Close()

		client := NewGoogleOAuthClient(Config{
			ClientID:      "test-client",
			TokenEndpoint: srv.URL,
			HTTPClient:    srv.Client(),
		})
		creds := domain.AccountCredentials{
			AccessToken:  "ya29.old",
			RefreshToken: "1//keep-me",
			Expiry:       now.Add(2 * time.Minute),
			IDToken:      "existing.jwt",
		}

		got, refreshed, err := client.Refresh(context.Background(), creds, 5*time.Minute, now)
		if err != nil || !refreshed {
			t.Fatalf("Refresh() = (%+v, %v, %v), want refreshed=true err=nil", got, refreshed, err)
		}
		if got.AccessToken != "ya29.new" || got.RefreshToken != "1//keep-me" || got.IDToken != "existing.jwt" {
			t.Fatalf("updated creds = %+v", got)
		}
		if !got.Expiry.Equal(now.Add(time.Hour)) {
			t.Fatalf("Expiry = %v, want %v", got.Expiry, now.Add(time.Hour))
		}
	})

	t.Run("wraps ErrRefreshRevoked on 400/401 revoked errors", func(t *testing.T) {
		t.Parallel()

		for _, code := range []string{"invalid_grant", "invalid_client", "unauthorized_client"} {
			t.Run(code, func(t *testing.T) {
				t.Parallel()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":             code,
						"error_description": "Token has been expired or revoked.",
					})
				}))
				defer srv.Close()

				client := NewGoogleOAuthClient(Config{ClientID: "test-client", TokenEndpoint: srv.URL, HTTPClient: srv.Client()})
				_, refreshed, err := client.Refresh(context.Background(), domain.AccountCredentials{
					RefreshToken: "1//revoked",
				}, 5*time.Minute, now)
				if refreshed || !errors.Is(err, ErrRefreshRevoked) {
					t.Fatalf("Refresh() = (%v, %v), want ErrRefreshRevoked", refreshed, err)
				}
			})
		}

		t.Run("transient 500 does not wrap ErrRefreshRevoked", func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "invalid_grant temporary proxy glitch", http.StatusInternalServerError)
			}))
			defer srv.Close()

			client := NewGoogleOAuthClient(Config{ClientID: "test-client", TokenEndpoint: srv.URL, HTTPClient: srv.Client()})
			_, _, err := client.Refresh(context.Background(), domain.AccountCredentials{
				RefreshToken: "1//ok",
			}, 5*time.Minute, now)
			if err == nil || errors.Is(err, ErrRefreshRevoked) {
				t.Fatalf("500 err = %v, should not wrap ErrRefreshRevoked", err)
			}
		})
	})
}

func TestImportNativeToken(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	client := NewGoogleOAuthClient(Config{})

	t.Run("imports valid native agy token file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(tmp, "antigravity-oauth-token")
		raw, err := EncodeAgyTokenFile("user@example.com", domain.AccountCredentials{
			AccessToken:  "ya29.native",
			RefreshToken: "1//native-refresh",
			Expiry:       time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(path, raw, true); err != nil {
			t.Fatal(err)
		}

		id, creds, err := client.ImportNativeToken(context.Background(), path)
		if err != nil {
			t.Fatalf("ImportNativeToken() error = %v", err)
		}
		if id.Key != "user@example.com" || creds.RefreshToken != "1//native-refresh" {
			t.Fatalf("imported = (%+v, %+v)", id, creds)
		}
	})

	t.Run("rejects file missing identity", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(tmp, "no-id.json")
		if err := platform.WriteFileAtomic(path, []byte(`{"access_token":"ya29.x","refresh_token":"1//r"}`), true); err != nil {
			t.Fatal(err)
		}
		if _, _, err := client.ImportNativeToken(context.Background(), path); !errors.Is(err, domain.ErrMissingIdentity) {
			t.Fatalf("ImportNativeToken() err = %v, want ErrMissingIdentity", err)
		}
	})
}

func TestLoginBrowserModePrintsURLAndAllowsFallbackWithoutEOFError(t *testing.T) {
	t.Parallel()

	idTok := makeTestJWT(t, map[string]any{"email": "loopback@example.com", "sub": "sub-lb"}, false)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "ya29.lb",
			"refresh_token": "1//lb",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"id_token":      idTok,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	t.Run("empty stdin EOF does not abort browser loopback callback", func(t *testing.T) {
		t.Parallel()
		var promptBuf bytes.Buffer
		client := NewGoogleOAuthClient(Config{
			ClientID:      "test-client",
			TokenEndpoint: tokenSrv.URL,
			CallbackAddr:  "127.0.0.1:0",
			HTTPClient:    tokenSrv.Client(),
			OpenBrowserFn: func(authURL string) error {
				u, err := url.Parse(authURL)
				if err != nil {
					return err
				}
				cb := u.Query().Get("redirect_uri")
				st := u.Query().Get("state")
				go func() {
					time.Sleep(25 * time.Millisecond)
					resp, err := http.Get(cb + "?code=code-lb&state=" + url.QueryEscape(st))
					if err == nil {
						_ = resp.Body.Close()
					}
				}()
				return nil
			},
		})

		id, creds, err := client.Login(context.Background(), LoginOptions{
			ManualInput:  strings.NewReader(""),
			PromptOutput: &promptBuf,
			Timeout:      5 * time.Second,
		})
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if id.Key != "loopback@example.com" || creds.AccessToken != "ya29.lb" {
			t.Fatalf("unexpected login result: id=%+v creds=%+v", id, creds)
		}
		if !strings.Contains(promptBuf.String(), "https://accounts.google.com") {
			t.Fatalf("expected auth URL printed in browser mode, got %q", promptBuf.String())
		}
	})

	t.Run("manual paste works even if OpenBrowserFn returned nil silently", func(t *testing.T) {
		t.Parallel()
		pr, pw := io.Pipe()
		defer pr.Close()
		var promptBuf bytes.Buffer
		client := NewGoogleOAuthClient(Config{
			ClientID:      "test-client",
			TokenEndpoint: tokenSrv.URL,
			CallbackAddr:  "127.0.0.1:0",
			HTTPClient:    tokenSrv.Client(),
			OpenBrowserFn: func(authURL string) error {
				u, err := url.Parse(authURL)
				if err != nil {
					return err
				}
				st := u.Query().Get("state")
				go func() {
					_, _ = fmt.Fprintf(pw, "http://127.0.0.1:51121/oauth-callback?code=code-manual&state=%s\n", st)
					_ = pw.Close()
				}()
				return nil
			},
		})

		id, creds, err := client.Login(context.Background(), LoginOptions{
			ManualInput:  pr,
			PromptOutput: &promptBuf,
			Timeout:      5 * time.Second,
		})
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if id.Key != "loopback@example.com" || creds.AccessToken != "ya29.lb" {
			t.Fatalf("unexpected login result: id=%+v creds=%+v", id, creds)
		}
	})
}

func setDefaultClientCredentialsForTest(t *testing.T, id, secret string) {
	t.Helper()
	origID, origSecret := DefaultClientID, DefaultClientSecret
	DefaultClientID, DefaultClientSecret = id, secret
	t.Cleanup(func() {
		DefaultClientID = origID
		DefaultClientSecret = origSecret
	})
}

func TestNewGoogleOAuthClientEnvAndConfigPrecedence(t *testing.T) {
	t.Run("reads env credentials when omitted in Config", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "default-id", "default-secret")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", " env-client-id ")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", " env-client-secret ")

		client := NewGoogleOAuthClient(Config{})
		if client.cfg.ClientID != "env-client-id" || client.cfg.ClientSecret != "env-client-secret" {
			t.Fatalf("resolved credentials = (%q, %q), want (env-client-id, env-client-secret)", client.cfg.ClientID, client.cfg.ClientSecret)
		}
	})

	t.Run("explicit Config overrides env credentials", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "default-id", "default-secret")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "env-client-id")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "env-client-secret")

		client := NewGoogleOAuthClient(Config{
			ClientID:     "cfg-client-id",
			ClientSecret: "cfg-client-secret",
		})
		if client.cfg.ClientID != "cfg-client-id" || client.cfg.ClientSecret != "cfg-client-secret" {
			t.Fatalf("resolved credentials = (%q, %q), want (cfg-client-id, cfg-client-secret)", client.cfg.ClientID, client.cfg.ClientSecret)
		}
	})

	t.Run("falls back to DefaultClientID and DefaultClientSecret when Config and env are empty", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "default-id", "default-secret")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "")

		client := NewGoogleOAuthClient(Config{})
		if client.cfg.ClientID != "default-id" || client.cfg.ClientSecret != "default-secret" {
			t.Fatalf("resolved credentials = (%q, %q), want (default-id, default-secret)", client.cfg.ClientID, client.cfg.ClientSecret)
		}
	})
}

func TestGoogleOAuthClientLoginFailsFastWithoutClientID(t *testing.T) {
	setDefaultClientCredentialsForTest(t, "", "")
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "")

	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busyLn.Close()

	var browserCalled atomic.Bool
	client := NewGoogleOAuthClient(Config{
		CallbackAddr: busyLn.Addr().String(),
		OpenBrowserFn: func(string) error {
			browserCalled.Store(true)
			return nil
		},
	})

	_, _, err = client.Login(context.Background(), LoginOptions{
		StrictPort: true,
		Timeout:    5 * time.Second,
	})
	if !errors.Is(err, ErrMissingClientID) {
		t.Fatalf("Login() error = %v, want ErrMissingClientID", err)
	}
	if browserCalled.Load() {
		t.Fatalf("OpenBrowserFn should not be invoked when client_id is missing")
	}
}

func TestGoogleOAuthClientRefreshClientIDResolution(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	t.Run("returns ErrMissingClientID and not ErrRefreshRevoked when both creds and config are empty", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "")

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		}))
		defer srv.Close()

		client := NewGoogleOAuthClient(Config{
			TokenEndpoint: srv.URL,
			HTTPClient:    srv.Client(),
		})
		creds := domain.AccountCredentials{
			AccessToken:  "ya29.old",
			RefreshToken: "1//keep-me",
			Expiry:       now.Add(2 * time.Minute),
		}

		got, refreshed, err := client.Refresh(context.Background(), creds, 5*time.Minute, now)
		if refreshed {
			t.Fatalf("refreshed = true, want false")
		}
		if !errors.Is(err, ErrMissingClientID) {
			t.Fatalf("Refresh() error = %v, want ErrMissingClientID", err)
		}
		if errors.Is(err, ErrRefreshRevoked) {
			t.Fatalf("Refresh() error = %v, must not wrap ErrRefreshRevoked", err)
		}
		if hits.Load() != 0 {
			t.Fatalf("expected zero HTTP calls, hits=%d", hits.Load())
		}
		if got.AccessToken != creds.AccessToken {
			t.Fatalf("creds = %+v, want unchanged %+v", got, creds)
		}
	})

	t.Run("succeeds when creds.ClientID is present", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "")

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != "creds-client" {
				http.Error(w, "unexpected client_id", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.from-creds",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
		}))
		defer srv.Close()

		client := NewGoogleOAuthClient(Config{
			TokenEndpoint: srv.URL,
			HTTPClient:    srv.Client(),
		})
		creds := domain.AccountCredentials{
			AccessToken:  "ya29.old",
			RefreshToken: "1//keep-me",
			Expiry:       now.Add(2 * time.Minute),
			ClientID:     "creds-client",
		}

		got, refreshed, err := client.Refresh(context.Background(), creds, 5*time.Minute, now)
		if err != nil || !refreshed {
			t.Fatalf("Refresh() = (%+v, %v, %v), want refreshed=true err=nil", got, refreshed, err)
		}
		if got.AccessToken != "ya29.from-creds" || got.ClientID != "creds-client" {
			t.Fatalf("updated creds = %+v", got)
		}
	})

	t.Run("succeeds when MULTI_ANTI_OAUTH_CLIENT_ID is set", func(t *testing.T) {
		setDefaultClientCredentialsForTest(t, "", "")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "env-client")
		t.Setenv("MULTI_ANTI_OAUTH_CLIENT_SECRET", "env-secret")

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != "env-client" || r.Form.Get("client_secret") != "env-secret" {
				http.Error(w, "unexpected client credentials", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.from-env",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
		}))
		defer srv.Close()

		client := NewGoogleOAuthClient(Config{
			TokenEndpoint: srv.URL,
			HTTPClient:    srv.Client(),
		})
		creds := domain.AccountCredentials{
			AccessToken:  "ya29.old",
			RefreshToken: "1//keep-me",
			Expiry:       now.Add(2 * time.Minute),
		}

		got, refreshed, err := client.Refresh(context.Background(), creds, 5*time.Minute, now)
		if err != nil || !refreshed {
			t.Fatalf("Refresh() = (%+v, %v, %v), want refreshed=true err=nil", got, refreshed, err)
		}
		if got.AccessToken != "ya29.from-env" || got.ClientID != "env-client" {
			t.Fatalf("updated creds = %+v", got)
		}
	})
}

func TestOpenBrowserRejectsNonHTTPURLs(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "file:///etc/passwd", "javascript:alert(1)", "ftp://example.com"} {
		if err := OpenBrowser(raw); err == nil {
			t.Fatalf("OpenBrowser(%q) = nil, want non-HTTP error", raw)
		}
	}
}
