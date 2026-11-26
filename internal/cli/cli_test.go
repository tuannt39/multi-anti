package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/store"
)

type stubOAuth struct {
	loginFn   func(ctx context.Context, opts oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error)
	refreshFn func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error)
	importFn  func(ctx context.Context, tokenPath string) (domain.AccountIdentity, domain.AccountCredentials, error)
}

func (s *stubOAuth) Login(ctx context.Context, opts oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
	if s.loginFn != nil {
		return s.loginFn(ctx, opts)
	}
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("unexpected Login call")
}

func (s *stubOAuth) Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error) {
	if s.refreshFn != nil {
		return s.refreshFn(ctx, creds, skew, now)
	}
	return creds, false, nil
}

func (s *stubOAuth) ImportNativeToken(ctx context.Context, tokenPath string) (domain.AccountIdentity, domain.AccountCredentials, error) {
	if s.importFn != nil {
		return s.importFn(ctx, tokenPath)
	}
	return oauth.NewGoogleOAuthClient(oauth.Config{}).ImportNativeToken(ctx, tokenPath)
}

type stubFetcher struct {
	fetchFn func(ctx context.Context, accessToken string, opts quota.FetchOptions) (domain.QuotaSnapshot, error)
}

func (f *stubFetcher) Fetch(ctx context.Context, accessToken string, opts quota.FetchOptions) (domain.QuotaSnapshot, error) {
	if f.fetchFn != nil {
		return f.fetchFn(ctx, accessToken, opts)
	}
	return domain.QuotaSnapshot{
		FetchedAt: opts.Now,
		Source:    domain.QuotaSourceSummary,
		Tier:      domain.TierPro,
		Buckets: []domain.QuotaBucket{
			{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.75},
		},
	}, nil
}

func setupCLIEnv(t *testing.T) (platform.Paths, *store.FileStore) {
	t.Helper()
	tmp := t.TempDir()
	realHome := filepath.Join(tmp, "real-home")
	if err := os.MkdirAll(realHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", realHome)
	t.Setenv("USERPROFILE", realHome)
	t.Setenv("MULTI_ANTI_HOME", filepath.Join(tmp, "data"))
	t.Setenv("MULTI_ANTI_AGY_HOME", filepath.Join(tmp, "agy-home"))
	t.Setenv("MULTI_ANTI_ACCOUNT", "")
	t.Setenv("MULTI_ANTI_ISOLATED", "")
	t.Setenv("MULTI_ANTI_MANAGED", "")
	t.Setenv("MULTI_ANTI_RUN_ID", "")
	t.Setenv("SSH_TTY", "")

	paths, err := platform.ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths() error = %v", err)
	}
	return paths, store.NewFileStore(paths)
}

func makeAccount(email string, gemRem, threePRem float64, accessTok, refreshTok string, expiry time.Time) domain.Account {
	return domain.Account{
		Key:   domain.AccountKey(strings.ToLower(email)),
		Email: email,
		Health: domain.AccountHealth{
			Status: domain.HealthReady,
		},
		Creds: domain.AccountCredentials{
			AccessToken:  accessTok,
			RefreshToken: refreshTok,
			TokenType:    "Bearer",
			Expiry:       expiry,
			IDToken:      "id-secret-" + email,
			ClientID:     "client-123",
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: expiry.Add(-5 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", DisplayName: "Gemini 5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: gemRem},
				{GroupID: "3p-5h", DisplayName: "3P 5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: threePRem},
			},
		},
		AddedAt: expiry.Add(-24 * time.Hour),
	}
}

func assertNoSecrets(t *testing.T, output string, secrets ...string) {
	t.Helper()
	lower := strings.ToLower(output)
	for _, key := range []string{`"access_token"`, `"refresh_token"`, `"id_token"`} {
		if strings.Contains(lower, key) {
			t.Fatalf("output unexpectedly contains credential JSON key %s:\n%s", key, output)
		}
	}
	for _, sec := range secrets {
		if sec != "" && strings.Contains(output, sec) {
			t.Fatalf("output leaked secret %q:\n%s", sec, output)
		}
	}
}

var sharedFakeAgyPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "multi-anti-cli-fake-agy-*")
	if err != nil {
		panic(err)
	}
	bin, err := compileFakeAgy(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		panic(err)
	}
	sharedFakeAgyPath = bin
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildFakeAgyBinary(t *testing.T) string {
	t.Helper()
	return sharedFakeAgyPath
}

func compileFakeAgy(dir string) (string, error) {
	srcPath := filepath.Join(dir, "main.go")
	binName := "agy"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(dir, binName)

	src := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("1.5.11")
		return
	}
	if len(args) >= 2 && args[0] == "plugin" && args[1] == "validate" {
		if os.Getenv("FAKE_AGY_VALIDATE_FAIL") == "1" {
			fmt.Println(` + "`" + `{"findings":[{"severity":"error","message":"bad plugin"}]}` + "`" + `)
			os.Exit(1)
		}
		fmt.Println(` + "`" + `{"findings":[]}` + "`" + `)
		return
	}
	if loginMode := os.Getenv("FAKE_AGY_LOGIN_MODE"); loginMode != "" {
		homeDir := os.Getenv("HOME")
		if envLog := os.Getenv("FAKE_AGY_LOGIN_ENV_LOG"); envLog != "" {
			payload := map[string]any{
				"args":                args,
				"home":                homeDir,
				"userprofile":         os.Getenv("USERPROFILE"),
				"ssh_tty":             os.Getenv("SSH_TTY"),
				"xdg_config_home":     os.Getenv("XDG_CONFIG_HOME"),
				"xdg_data_home":       os.Getenv("XDG_DATA_HOME"),
				"xdg_cache_home":      os.Getenv("XDG_CACHE_HOME"),
				"multi_anti_managed":  os.Getenv("MULTI_ANTI_MANAGED"),
				"multi_anti_account":  os.Getenv("MULTI_ANTI_ACCOUNT"),
				"multi_anti_isolated": os.Getenv("MULTI_ANTI_ISOLATED"),
				"multi_anti_home":     os.Getenv("MULTI_ANTI_HOME"),
				"multi_anti_agy_home": os.Getenv("MULTI_ANTI_AGY_HOME"),
			}
			if b, err := json.Marshal(payload); err == nil {
				_ = os.WriteFile(envLog, b, 0o600)
			}
		}
		switch loginMode {
		case "prompt":
			fmt.Fprint(os.Stderr, "Authentication required. Please visit the URL to log in:\n  https://accounts.google.com/o/oauth2/auth?state=s1\nOr, paste the authorization code here and press Enter:")
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			if codeLog := os.Getenv("FAKE_AGY_LOGIN_CODE_LOG"); codeLog != "" {
				_ = os.WriteFile(codeLog, []byte(strings.TrimSpace(line)), 0o600)
			}
			tokDir := filepath.Join(homeDir, ".gemini", "antigravity-cli")
			if err := os.MkdirAll(tokDir, 0o700); err != nil {
				os.Exit(3)
			}
			tokDoc := map[string]any{
				"token": map[string]any{
					"access_token":  "ya29.fake-agy-access-secret",
					"token_type":    "Bearer",
					"refresh_token": "1//fake-agy-refresh-secret",
					"expiry":        "2099-01-01T00:00:00Z",
				},
				"auth_method":    "consumer",
				"id_token":       "hdr.fake-agy-id-secret.sig",
				"id_token_email": "agy-login@example.com",
			}
			raw, err := json.Marshal(tokDoc)
			if err != nil {
				os.Exit(4)
			}
			if err := os.WriteFile(filepath.Join(tokDir, "antigravity-oauth-token"), raw, 0o600); err != nil {
				os.Exit(5)
			}
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			select {
			case <-sigCh:
				fmt.Fprint(os.Stderr, "\nError: authentication interrupted.\nerror: authentication failed or timed out\n")
				os.Exit(1)
			case <-time.After(10 * time.Second):
				return
			}
		case "fail":
			fmt.Fprintln(os.Stderr, "fake agy login error: unauthorized")
			os.Exit(1)
		}
	}

	acct := os.Getenv("MULTI_ANTI_ACCOUNT")
	homeDir := os.Getenv("HOME")
	if logPath := os.Getenv("FAKE_AGY_LOG"); logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(9)
		}
		_, _ = fmt.Fprintf(f, "%s|%s|%s\n", acct, filepath.Base(homeDir), strings.Join(args, " "))
		_ = f.Close()
	}

	if failAcct := os.Getenv("FAKE_AGY_FAIL_ACCOUNT"); failAcct != "" {
		for _, candidate := range strings.Split(failAcct, ",") {
			if strings.TrimSpace(candidate) == acct {
				fmt.Fprintln(os.Stderr, "HTTP 429 RESOURCE_EXHAUSTED: retryDelay: \"30s\"")
				os.Exit(1)
			}
		}
	}
	if codeStr := os.Getenv("FAKE_AGY_EXIT_CODE"); codeStr != "" {
		if code, err := strconv.Atoi(codeStr); err == nil && code != 0 {
			fmt.Fprintln(os.Stderr, "agy failed cleanly")
			os.Exit(code)
		}
	}
	fmt.Printf("ok:%s\n", acct)
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", errors.New("build fake agy failed: " + err.Error() + "\n" + string(out))
	}
	return binPath, nil
}

func TestHelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"version"}, Config{
		Version: "1.2.3",
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if code != 0 || strings.TrimSpace(stdout.String()) != "multi-anti 1.2.3" {
		t.Fatalf("version output = %q, code = %d, stderr = %q", stdout.String(), code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"help", "run"}, Config{Stdout: &stdout, Stderr: &stderr})
	if code != 0 || !strings.Contains(stdout.String(), "--isolate") {
		t.Fatalf("help run = %q, code = %d", stdout.String(), code)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"bogus-cmd"}, Config{Stdout: &stdout, Stderr: &stderr})
	if code != 2 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown cmd code = %d, stderr = %q", code, stderr.String())
	}
}

func TestLoginPreservesMetadataAndRedactsJSON(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)

	const secretAT = "ya29.super-secret-access-token"
	const secretRT = "1//super-secret-refresh-token"
	const secretID = "eyJ.secret.idtoken"

	oauthMock := &stubOAuth{
		loginFn: func(ctx context.Context, opts oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
			return domain.AccountIdentity{
					Key:         "alice@example.com",
					Email:       "alice@example.com",
					DisplayName: "Alice OAuth",
				}, domain.AccountCredentials{
					AccessToken:  secretAT,
					RefreshToken: secretRT,
					TokenType:    "Bearer",
					Expiry:       now.Add(time.Hour),
					IDToken:      secretID,
				}, nil
		},
	}

	fetcherMock := &stubFetcher{
		fetchFn: func(ctx context.Context, accessToken string, opts quota.FetchOptions) (domain.QuotaSnapshot, error) {
			return domain.QuotaSnapshot{
				FetchedAt: opts.Now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierUltra,
				Buckets: []domain.QuotaBucket{
					{GroupID: "g1", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.92},
				},
			}, nil
		},
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   oauthMock,
		Fetcher: fetcherMock,
		Stdin:   strings.NewReader(""),
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	code := Run(ctx, []string{"login", "--no-browser", "--priority", "10", "--alias", "Work", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("login failed code=%d stderr=%s", code, stderr.String())
	}
	assertNoSecrets(t, stdout.String(), secretAT, secretRT, secretID)

	var res ImportResultView
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal login JSON: %v", err)
	}
	if res.ActiveKey != "alice@example.com" || len(res.Imported) != 1 || !res.Imported[0].HasRefreshToken {
		t.Fatalf("unexpected login result: %+v", res)
	}
	if res.Imported[0].Priority != 10 || res.Imported[0].DisplayName != "Work" || res.Imported[0].Tier != domain.TierUltra {
		t.Fatalf("unexpected imported account view: %+v", res.Imported[0])
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"login", "--no-refresh"}, cfg)
	if code != 0 {
		t.Fatalf("re-login failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ := st.Load(ctx)
	acc := state.Accounts["alice@example.com"]
	if acc.Priority != 10 || acc.DisplayName != "Work" {
		t.Fatalf("expected existing priority/alias preserved, got prio=%d alias=%q", acc.Priority, acc.DisplayName)
	}
}

func TestImportNativeAndAccountsJSONRedaction(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	const secretAT = "ya29.native-secret-access"
	const secretRT = "1//native-secret-refresh"
	const secretID = "hdr.native-secret-id.sig"

	nativeBytes, err := oauth.EncodeAgyTokenFile("native@example.com", domain.AccountCredentials{
		AccessToken:  secretAT,
		RefreshToken: secretRT,
		TokenType:    "Bearer",
		Expiry:       now.Add(time.Hour),
		IDToken:      secretID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), nativeBytes, true); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   &stubOAuth{},
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	code := Run(ctx, []string{"import", "--priority", "5", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("import failed code=%d stderr=%s", code, stderr.String())
	}
	assertNoSecrets(t, stdout.String(), secretAT, secretRT, secretID)

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"accounts", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("accounts --json failed code=%d stderr=%s", code, stderr.String())
	}
	assertNoSecrets(t, stdout.String(), secretAT, secretRT, secretID)

	var list AccountsListView
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal accounts --json: %v", err)
	}
	if list.ActiveKey != "native@example.com" || len(list.Accounts) != 1 {
		t.Fatalf("unexpected accounts list: %+v", list)
	}
	if !list.Accounts[0].HasRefreshToken || !list.Accounts[0].Active || list.Accounts[0].Priority != 5 {
		t.Fatalf("unexpected account view: %+v", list.Accounts[0])
	}

	multiPath := filepath.Join(t.TempDir(), "multi.json")
	multiPayload := `[
		{"email": "b1@example.com", "refresh_token": "rt-b1", "access_token": "at-b1", "alias": "Backup1", "priority": 3},
		{"email": "b2@example.com", "refresh_token": "rt-b2", "access_token": "at-b2"}
	]`
	if err := os.WriteFile(multiPath, []byte(multiPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"import", multiPath, "--no-refresh"}, cfg)
	if code != 0 {
		t.Fatalf("multi import failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ := st.Load(ctx)
	if len(state.Accounts) != 3 || state.Accounts["b1@example.com"].DisplayName != "Backup1" || state.Accounts["b1@example.com"].Priority != 3 {
		t.Fatalf("unexpected multi-import state: %+v", state.Accounts)
	}

	stdout.Reset()
	code = Run(ctx, []string{"ls"}, cfg)
	if code != 0 || !strings.Contains(stdout.String(), "native@example.com") || !strings.Contains(stdout.String(), "Backup1") {
		t.Fatalf("ls output unexpected (code=%d):\n%s", code, stdout.String())
	}
}

func TestQuotaLiveCachedModelsWatchAndJSON(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)

	alice := makeAccount("alice@example.com", 0.20, 0.90, "at-alice-secret", "rt-alice-secret", now.Add(time.Hour))
	bob := makeAccount("bob@example.com", 0.85, 0.30, "at-bob-secret", "rt-bob-secret", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var fetchCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		isAlice := strings.Contains(auth, "at-alice-secret")
		switch r.URL.Path {
		case "/v1internal:loadCodeAssist":
			fetchCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cloudaicompanionProject": "proj-1",
				"paidTier":                map[string]string{"id": "g1-pro-tier"},
				"availableCredits": []map[string]any{
					{"creditType": "GOOGLE_ONE_AI", "creditAmount": 250, "unit": "USD"},
				},
			})
		case "/v1internal:retrieveUserQuotaSummary":
			rem := 0.88
			if isAlice {
				rem = 0.42
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"buckets": []map[string]any{
					{"groupId": "gemini-5h", "displayName": "Gemini 5h", "remainingFraction": rem, "resetTime": now.Add(2 * time.Hour).Format(time.RFC3339)},
					{"groupId": "3p-5h", "displayName": "3P 5h", "remainingFraction": 0.95, "resetTime": now.Add(3 * time.Hour).Format(time.RFC3339)},
				},
			})
		case "/v1internal:fetchAvailableModels":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": map[string]any{
					"claude-sonnet-4-6": map[string]any{
						"displayName":      "Claude Sonnet 4.6",
						"supportsThinking": true,
						"quotaInfo": map[string]any{
							"remainingFraction": 0.95,
							"resetTime":         now.Add(3 * time.Hour).Format(time.RFC3339),
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	realFetcher := quota.NewCloudCodeFetcher(quota.FetcherConfig{
		Endpoints:  []string{srv.URL},
		HTTPClient: srv.Client(),
	})

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   &stubOAuth{},
		Fetcher: realFetcher,
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	code := Run(ctx, []string{"quota", "--models", "--pool", "gemini"}, cfg)
	if code != 0 {
		t.Fatalf("quota failed code=%d stderr=%s", code, stderr.String())
	}
	if fetchCalls.Load() != 2 {
		t.Fatalf("expected 2 live fetch calls, got %d", fetchCalls.Load())
	}
	outStr := stdout.String()
	if !strings.Contains(outStr, "88%") || !strings.Contains(outStr, "42%") || !strings.Contains(outStr, "bob@example.com") {
		t.Fatalf("unexpected quota table:\n%s", outStr)
	}

	prevCalls := fetchCalls.Load()
	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"status", "--no-refresh", "--models", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("quota --no-refresh --json failed code=%d stderr=%s", code, stderr.String())
	}
	if fetchCalls.Load() != prevCalls {
		t.Fatalf("expected --no-refresh not to fetch")
	}
	assertNoSecrets(t, stdout.String(), "at-alice-secret", "rt-alice-secret", "at-bob-secret", "rt-bob-secret")

	var report QuotaReportView
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal quota --json: %v", err)
	}
	if len(report.Accounts) != 2 || report.Accounts[0].Key != bob.Key {
		t.Fatalf("expected bob ranked first, got %+v", report.Accounts)
	}
	if report.Accounts[0].Quota == nil || len(report.Accounts[0].Quota.Models) != 1 {
		t.Fatalf("expected models in quota --models --json, got %+v", report.Accounts[0].Quota)
	}

	stdout.Reset()
	watchCtx, cancel := context.WithTimeout(ctx, 45*time.Millisecond)
	defer cancel()
	code = Run(watchCtx, []string{"quota", "--cached", "--watch", "15ms"}, cfg)
	if code != 0 {
		t.Fatalf("quota --watch exited with code %d, stderr=%s", code, stderr.String())
	}
}

func TestSwitchAndNextStagingAndBackup(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	origNative := []byte(`{"token":{"access_token":"orig-at","refresh_token":"orig-rt"},"auth_method":"consumer","id_token_email":"orig@example.com"}`)
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), origNative, true); err != nil {
		t.Fatal(err)
	}

	alice := makeAccount("alice@example.com", 0.40, 0.40, "at-alice", "rt-alice", now.Add(time.Hour))
	bob := makeAccount("bob@example.com", 0.90, 0.90, "", "rt-bob", time.Time{})
	carol := makeAccount("carol@example.com", 0.50, 0.50, "at-carol", "rt-carol", now.Add(time.Hour))
	carol.Health = domain.AccountHealth{Status: domain.HealthDisabled, Reason: "manual"}
	dave := makeAccount("dave@example.com", 0.50, 0.50, "at-dave", "rt-dave", now.Add(time.Hour))
	until := now.Add(10 * time.Minute)
	dave.Health = domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &until, Reason: "429"}

	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		s.Accounts[carol.Key] = carol
		s.Accounts[dave.Key] = dave
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	oauthMock := &stubOAuth{
		refreshFn: func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, n time.Time) (domain.AccountCredentials, bool, error) {
			creds.AccessToken = "at-bob-refreshed"
			creds.Expiry = n.Add(time.Hour)
			return creds, true, nil
		},
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   oauthMock,
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	code := Run(ctx, []string{"next", "--no-refresh", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("next failed code=%d stderr=%s", code, stderr.String())
	}
	assertNoSecrets(t, stdout.String(), "at-bob-refreshed", "rt-bob")

	state, _ := st.Load(ctx)
	if state.ActiveKey != bob.Key || state.NativeBackup == nil || !state.NativeBackup.HadFile {
		t.Fatalf("unexpected state after next: active=%q backup=%+v", state.ActiveKey, state.NativeBackup)
	}
	if state.LastSwitch == nil || state.LastSwitch.Trigger != "cli_switch" || state.LastSwitch.FromKey != alice.Key || state.LastSwitch.ToKey != bob.Key {
		t.Fatalf("unexpected LastSwitch audit: %+v", state.LastSwitch)
	}
	stagedBytes, _ := os.ReadFile(paths.NativeAgyTokenPath())
	stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedBytes)
	if err != nil || stagedID.Email != "bob@example.com" || stagedCreds.AccessToken != "at-bob-refreshed" {
		t.Fatalf("unexpected staged native token: id=%+v creds=%+v err=%v", stagedID, stagedCreds, err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"switch", "carol@example.com"}, cfg)
	if code == 0 || !strings.Contains(stderr.String(), "disabled") {
		t.Fatalf("expected disabled refusal, got code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"switch", "dave@example.com"}, cfg)
	if code == 0 || !strings.Contains(stderr.String(), "cooldown") {
		t.Fatalf("expected cooldown refusal, got code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"switch", "dave@example.com", "--force"}, cfg)
	if code != 0 {
		t.Fatalf("switch --force failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if state.ActiveKey != dave.Key {
		t.Fatalf("expected ActiveKey=dave, got %q", state.ActiveKey)
	}

	bakBytes, err := os.ReadFile(state.NativeBackup.BackupPath)
	if err != nil || !bytes.Equal(bakBytes, origNative) {
		t.Fatalf("native backup tampered or missing: err=%v", err)
	}
}

func TestRunPassthroughFlagsIsolateAndFailover(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	alice := makeAccount("alice@example.com", 0.95, 0.20, "at-alice", "rt-alice", now.Add(time.Hour))
	bob := makeAccount("bob@example.com", 0.15, 0.92, "at-bob", "rt-bob", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "agy-run.log")
	t.Setenv("FAKE_AGY_LOG", logPath)
	t.Setenv("FAKE_AGY_FAIL_ACCOUNT", "")
	t.Setenv("FAKE_AGY_EXIT_CODE", "")

	var stdout, stderr bytes.Buffer
	cfg := Config{
		AgyBinary: fakeAgy,
		Store:     st,
		OAuth:     &stubOAuth{},
		Fetcher:   &stubFetcher{},
		Stdin:     strings.NewReader(""),
		Stdout:    &stdout,
		Stderr:    &stderr,
		Now:       func() time.Time { return now },
	}

	code := Run(ctx, []string{"run", "--no-refresh", "--model", "claude-sonnet-4-6", "-p", "hi"}, cfg)
	if code != 0 {
		t.Fatalf("run without '--' failed code=%d stderr=%s", code, stderr.String())
	}
	logRaw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logRaw), "bob@example.com|real-home|--model claude-sonnet-4-6 -p hi") {
		t.Fatalf("unexpected agy invocation log:\n%s", logRaw)
	}

	_ = os.Remove(logPath)
	stdout.Reset()
	stderr.Reset()
	t.Setenv("FAKE_AGY_FAIL_ACCOUNT", "bob@example.com")
	code = Run(ctx, []string{"run", "--isolate", "--no-refresh", "--model", "claude-sonnet-4-6", "--", "-p", "hi"}, cfg)
	if code != 0 {
		t.Fatalf("run --isolate failover failed code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	logRaw, _ = os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(logRaw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 failover invocations, got %v", lines)
	}
	if !strings.HasPrefix(lines[0], "bob@example.com|") || !strings.Contains(lines[0], "|-p hi --model claude-sonnet-4-6") && !strings.Contains(lines[0], "|--model claude-sonnet-4-6 -p hi") {
		t.Fatalf("unexpected attempt 1 log: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "alice@example.com|") || strings.Contains(lines[1], "|real-home|") {
		t.Fatalf("expected isolated HOME dir on attempt 2, got: %q", lines[1])
	}
	if strings.Contains(lines[0], " -- ") {
		t.Fatalf("separator '--' should not be passed to agy: %q", lines[0])
	}

	t.Setenv("FAKE_AGY_FAIL_ACCOUNT", "")
	t.Setenv("FAKE_AGY_EXIT_CODE", "7")
	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"agy", "--no-refresh", "--", "-p", "check"}, cfg)
	if code != 7 {
		t.Fatalf("expected child exit code 7, got %d (stderr=%q)", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "error:") {
		t.Fatalf("expected no redundant CLI error on child exit, got stderr=%q", stderr.String())
	}
}

func TestPolicyEnableDisablePriorityAndRemove(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	alice := makeAccount("alice@example.com", 0.80, 0.80, "at-alice", "rt-alice", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := platform.EnsurePrivateDir(paths.ProfileDir(alice.Key)); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:  st,
		Stdout: &stdout,
		Stderr: &stderr,
		Now:    func() time.Time { return now },
	}

	code := Run(ctx, []string{"policy", "--mode", "fill_first", "--threshold", "0.15", "--cooldown", "10m", "--refresh-skew", "3m", "--pool", "3p", "--json"}, cfg)
	if code != 0 {
		t.Fatalf("policy update failed code=%d stderr=%s", code, stderr.String())
	}
	var pv PolicyView
	if err := json.Unmarshal(stdout.Bytes(), &pv); err != nil {
		t.Fatalf("unmarshal policy JSON: %v", err)
	}
	if pv.Mode != domain.SwitchFillFirst || pv.TargetPool != domain.Pool3P || pv.MinRemainingThreshold != 0.15 || pv.CooldownDefault != "10m0s" {
		t.Fatalf("unexpected policy view: %+v", pv)
	}

	stdout.Reset()
	code = Run(ctx, []string{"policy", "--pool", "all"}, cfg)
	if code != 0 {
		t.Fatalf("policy --pool all failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ := st.Load(ctx)
	if state.Policy.TargetPool != "" {
		t.Fatalf("expected TargetPool cleared with --pool all, got %q", state.Policy.TargetPool)
	}

	if code := Run(ctx, []string{"disable", "alice@example.com"}, cfg); code != 0 {
		t.Fatalf("disable failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if state.Accounts[alice.Key].Health.Status != domain.HealthDisabled {
		t.Fatalf("expected disabled health, got %+v", state.Accounts[alice.Key].Health)
	}

	if code := Run(ctx, []string{"enable", "alice@example.com"}, cfg); code != 0 {
		t.Fatalf("enable failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if state.Accounts[alice.Key].Health.Status != domain.HealthReady {
		t.Fatalf("expected ready health, got %+v", state.Accounts[alice.Key].Health)
	}

	if code := Run(ctx, []string{"priority", "alice@example.com", "-5"}, cfg); code != 0 {
		t.Fatalf("priority -5 failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if state.Accounts[alice.Key].Priority != -5 {
		t.Fatalf("expected priority -5, got %d", state.Accounts[alice.Key].Priority)
	}

	if code := Run(ctx, []string{"rm", "alice@example.com"}, cfg); code != 0 {
		t.Fatalf("remove failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if len(state.Accounts) != 0 || state.ActiveKey != "" {
		t.Fatalf("expected empty accounts and cleared ActiveKey, got %+v", state)
	}
	if _, err := os.Stat(paths.ProfileDir(alice.Key)); !os.IsNotExist(err) {
		t.Fatalf("expected profile dir removed, stat err=%v", err)
	}
}

func TestPluginHooksStatusLineDoctorAndRestore(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	origNative := []byte(`{"token":{"access_token":"orig-at","refresh_token":"orig-rt"},"auth_method":"consumer","id_token_email":"orig@example.com"}`)
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), origNative, true); err != nil {
		t.Fatal(err)
	}
	origSettings := []byte(`{"statusLine":{"type":"command","command":"custom-status","stack_with_default":false}}`)
	if err := platform.WriteFileAtomic(paths.NativeAgySettingsPath(), origSettings, false); err != nil {
		t.Fatal(err)
	}

	alice := makeAccount("alice@example.com", 0.80, 0.80, "at-alice-secret", "rt-alice-secret", now.Add(time.Hour))
	bob := makeAccount("bob@example.com", 0.60, 0.60, "at-bob-secret", "rt-bob-secret", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	newCfg := func(in string) Config {
		return Config{
			BinaryCommand: "/usr/local/bin/multi-anti",
			AgyBinary:     fakeAgy,
			Store:         st,
			OAuth:         &stubOAuth{},
			Fetcher:       &stubFetcher{},
			Stdin:         strings.NewReader(in),
			Stdout:        &stdout,
			Stderr:        &stderr,
			Now:           func() time.Time { return now },
		}
	}

	if code := Run(ctx, []string{"plugin", "install", "--json"}, newCfg("")); code != 0 {
		t.Fatalf("plugin install failed code=%d stderr=%s", code, stderr.String())
	}
	var pStat hook.PluginStatus
	if err := json.Unmarshal(stdout.Bytes(), &pStat); err != nil {
		t.Fatalf("unmarshal plugin install status: %v", err)
	}
	if !pStat.Installed || !pStat.StatusLineEnabled {
		t.Fatalf("expected installed plugin and enabled statusLine: %+v", pStat)
	}

	stdout.Reset()
	if code := Run(ctx, []string{"plugin", "status"}, newCfg("")); code != 0 || !strings.Contains(stdout.String(), "installed:           true") {
		t.Fatalf("plugin status unexpected code=%d out=%s", code, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"hook", "session-start"}, newCfg(`{"conversationId":"conv-1"}`)); code != 0 {
		t.Fatalf("hook session-start failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "alice@example.com") {
		t.Fatalf("unexpected session-start output: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"hook", "stop"}, newCfg(`{"conversationId":"conv-1","error":"HTTP 429 RESOURCE_EXHAUSTED"}`)); code != 0 {
		t.Fatalf("hook stop failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bob@example.com") {
		t.Fatalf("expected stop hook switch to bob, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"statusline"}, newCfg(`{"email":"bob@example.com"}`)); code != 0 {
		t.Fatalf("statusline failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bob@example.com") {
		t.Fatalf("unexpected statusline output: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"doctor", "--json"}, newCfg("")); code != 0 {
		t.Fatalf("doctor --json failed code=%d out=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertNoSecrets(t, stdout.String(), "at-alice-secret", "rt-alice-secret", "at-bob-secret", "rt-bob-secret")
	var docRep DoctorReportView
	if err := json.Unmarshal(stdout.Bytes(), &docRep); err != nil {
		t.Fatalf("unmarshal doctor --json: %v", err)
	}
	if !docRep.Healthy || docRep.AgyVer != "1.5.11" || docRep.Accounts.Total != 2 {
		t.Fatalf("unexpected doctor report: %+v", docRep)
	}

	state, _ := st.Load(ctx)
	if err := os.WriteFile(state.NativeBackup.BackupPath, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := Run(ctx, []string{"doctor"}, newCfg("")); code == 0 || !strings.Contains(stdout.String(), "SHA256 mismatch") {
		t.Fatalf("expected doctor failure on corrupt backup, got code=%d out=%s", code, stdout.String())
	}

	if err := os.WriteFile(state.NativeBackup.BackupPath, origNative, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"restore-native"}, newCfg("")); code != 0 {
		t.Fatalf("restore-native failed code=%d stderr=%s", code, stderr.String())
	}
	restoredTok, _ := os.ReadFile(paths.NativeAgyTokenPath())
	if !bytes.Equal(restoredTok, origNative) {
		t.Fatalf("native token not restored: got %s", restoredTok)
	}
	settingsRaw, _ := os.ReadFile(paths.NativeAgySettingsPath())
	if !strings.Contains(string(settingsRaw), "custom-status") {
		t.Fatalf("original statusLine not restored: %s", settingsRaw)
	}

	stdout.Reset()
	if code := Run(ctx, []string{"plugin", "uninstall"}, newCfg("")); code != 0 {
		t.Fatalf("plugin uninstall failed code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(paths.NativePluginDir()); !os.IsNotExist(err) {
		t.Fatalf("expected plugin dir deleted, err=%v", err)
	}
}

func TestEdgeCasesNoneReadyStatusLineInstallAndDoctorValidateFail(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	exportPath := filepath.Join(t.TempDir(), "export.json")
	exportPayload := `{"accounts":[{"email":"only@example.com","refresh_token":"rt-only","access_token":"at-only"}]}`
	if err := os.WriteFile(exportPath, []byte(exportPayload), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		BinaryCommand: "/usr/local/bin/multi-anti",
		AgyBinary:     fakeAgy,
		Store:         st,
		OAuth:         &stubOAuth{},
		Fetcher:       &stubFetcher{},
		Stdin:         strings.NewReader(""),
		Stdout:        &stdout,
		Stderr:        &stderr,
		Now:           func() time.Time { return now },
	}

	if code := Run(ctx, []string{"import", exportPath, "--no-refresh"}, cfg); code != 0 {
		t.Fatalf("import accounts object failed code=%d stderr=%s", code, stderr.String())
	}

	until := now.Add(20 * time.Minute)
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		acc := s.Accounts["only@example.com"]
		acc.Health = domain.AccountHealth{
			Status:        domain.HealthCooldown,
			CooldownUntil: &until,
			UpdatedAt:     now,
		}
		s.Accounts[acc.Key] = acc
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"run", "--pool", "3p", "--no-refresh", "-p", "hi"}, cfg); code == 0 || !strings.Contains(stderr.String(), "no ready accounts") || !strings.Contains(stderr.String(), "2026-11-18T12:20:00Z") {
		t.Fatalf("expected none-ready with reset hint on run, got code=%d stderr=%s", code, stderr.String())
	}

	other := makeAccount("other@example.com", 0.50, 0.50, "at-other", "rt-other", now.Add(time.Hour))
	other.Health = domain.AccountHealth{
		Status:        domain.HealthCooldown,
		CooldownUntil: &until,
		UpdatedAt:     now,
	}
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[other.Key] = other
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"next", "--no-refresh"}, cfg); code == 0 || !strings.Contains(stderr.String(), "no ready accounts") || !strings.Contains(stderr.String(), "20m") {
		t.Fatalf("expected none-ready with reset hint on next, got code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"statusline", "install"}, cfg); code != 0 {
		t.Fatalf("statusline install failed code=%d stderr=%s", code, stderr.String())
	}
	stInspect, err := hook.InspectPlugin(paths)
	if err != nil || !stInspect.StatusLineEnabled {
		t.Fatalf("expected statusLine enabled, got %+v err=%v", stInspect, err)
	}
	if code := Run(ctx, []string{"statusline", "uninstall"}, cfg); code != 0 {
		t.Fatalf("statusline uninstall failed code=%d stderr=%s", code, stderr.String())
	}
	stInspect, _ = hook.InspectPlugin(paths)
	if stInspect.StatusLineEnabled {
		t.Fatalf("expected statusLine disabled after uninstall")
	}

	if code := Run(ctx, []string{"plugin", "install", "--no-statusline"}, cfg); code != 0 {
		t.Fatalf("plugin install failed code=%d stderr=%s", code, stderr.String())
	}
	t.Setenv("FAKE_AGY_VALIDATE_FAIL", "1")
	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"doctor"}, cfg); code == 0 || !strings.Contains(stdout.String(), "agy plugin validate --strict failed") {
		t.Fatalf("expected doctor failure when plugin validate fails, got code=%d out=%s", code, stdout.String())
	}
}

func TestConcurrentSwitchKeepsNativeTokenAndActiveKeyInSync(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	emails := []string{"a@example.com", "b@example.com", "c@example.com"}
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		for _, e := range emails {
			acc := makeAccount(e, 0.5, 0.5, "at-"+e, "rt-"+e, now.Add(time.Hour))
			s.Accounts[acc.Key] = acc
		}
		s.ActiveKey = domain.AccountKey(emails[0])
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 40; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var out, errOut bytes.Buffer
				Run(ctx, []string{"switch", "--no-refresh", emails[i%len(emails)]}, Config{
					Store:   st,
					Stdout:  &out,
					Stderr:  &errOut,
					Fetcher: &stubFetcher{},
					Now:     func() time.Time { return now },
				})
			}()
		}
		wg.Wait()

		state, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(paths.NativeAgyTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := oauth.DecodeAgyTokenFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		if id.Key != state.ActiveKey {
			t.Fatalf("round %d: native token holds %q but active_key is %q", round, id.Key, state.ActiveKey)
		}
	}
}

func TestLoginFallbackViaAgy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	prevClientID := oauth.DefaultClientID
	oauth.DefaultClientID = ""
	defer func() { oauth.DefaultClientID = prevClientID }()
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
	t.Setenv("MULTI_ANTI_MANAGED", "1")
	t.Setenv("MULTI_ANTI_ACCOUNT", "stale@example.com")
	t.Setenv("MULTI_ANTI_ISOLATED", "1")

	tmpRoot := t.TempDir()
	t.Setenv("TMPDIR", tmpRoot)
	t.Setenv("TMP", tmpRoot)
	t.Setenv("TEMP", tmpRoot)

	envLogPath := filepath.Join(t.TempDir(), "env.json")
	codeLogPath := filepath.Join(t.TempDir(), "code.txt")
	t.Setenv("FAKE_AGY_LOGIN_MODE", "prompt")
	t.Setenv("FAKE_AGY_LOGIN_ENV_LOG", envLogPath)
	t.Setenv("FAKE_AGY_LOGIN_CODE_LOG", codeLogPath)

	var helpOut, helpErr bytes.Buffer
	if code := Run(ctx, []string{"help", "login"}, Config{Stdout: &helpOut, Stderr: &helpErr}); code != 0 || !strings.Contains(helpOut.String(), "--agy-bin") {
		t.Fatalf("expected help login to mention --agy-bin, got code=%d out=%q", code, helpOut.String())
	}

	stdinR, stdinW := io.Pipe()
	var (
		browserMu    sync.Mutex
		browserCalls int
		capturedURL  string
	)
	urlSeen := make(chan struct{}, 1)

	go func() {
		select {
		case <-urlSeen:
			_, _ = io.WriteString(stdinW, "code-from-stdin\n")
			_ = stdinW.Close()
		case <-time.After(5 * time.Second):
			_ = stdinW.Close()
		}
	}()

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   oauth.NewGoogleOAuthClient(oauth.Config{}),
		Fetcher: &stubFetcher{},
		OpenBrowserFn: func(url string) error {
			browserMu.Lock()
			browserCalls++
			capturedURL = url
			browserMu.Unlock()
			select {
			case urlSeen <- struct{}{}:
			default:
			}
			return nil
		},
		Stdin:  stdinR,
		Stdout: &stdout,
		Stderr: &stderr,
		Now:    func() time.Time { return now },
	}

	start := time.Now()
	code := Run(ctx, []string{"login", "--agy-bin", fakeAgy, "--priority", "7", "--alias", "AgyFallback", "--json"}, cfg)
	elapsed := time.Since(start)
	if code != 0 {
		t.Fatalf("login fallback failed code=%d stderr=%s", code, stderr.String())
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("expected loginViaAgy to cancel agy after token capture, took %v", elapsed)
	}

	browserMu.Lock()
	gotBrowserCalls := browserCalls
	gotURL := capturedURL
	browserMu.Unlock()
	if gotBrowserCalls != 1 || gotURL != "https://accounts.google.com/o/oauth2/auth?state=s1" {
		t.Fatalf("unexpected OpenBrowserFn calls=%d url=%q", gotBrowserCalls, gotURL)
	}

	codeRaw, err := os.ReadFile(codeLogPath)
	if err != nil || string(codeRaw) != "code-from-stdin" {
		t.Fatalf("unexpected stdin handoff code=%q err=%v", string(codeRaw), err)
	}

	var childEnv struct {
		Args              []string `json:"args"`
		Home              string   `json:"home"`
		UserProfile       string   `json:"userprofile"`
		SSHTTY            string   `json:"ssh_tty"`
		XDGConfigHome     string   `json:"xdg_config_home"`
		XDGDataHome       string   `json:"xdg_data_home"`
		XDGCacheHome      string   `json:"xdg_cache_home"`
		MultiAntiManaged  string   `json:"multi_anti_managed"`
		MultiAntiAccount  string   `json:"multi_anti_account"`
		MultiAntiIsolated string   `json:"multi_anti_isolated"`
		MultiAntiHome     string   `json:"multi_anti_home"`
		MultiAntiAgyHome  string   `json:"multi_anti_agy_home"`
	}
	envRaw, err := os.ReadFile(envLogPath)
	if err != nil {
		t.Fatalf("read child env log: %v", err)
	}
	if err := json.Unmarshal(envRaw, &childEnv); err != nil {
		t.Fatalf("unmarshal child env log: %v", err)
	}
	if len(childEnv.Args) != 2 || childEnv.Args[0] != "-p" || childEnv.Args[1] != "OK" {
		t.Fatalf("unexpected agy args: %v", childEnv.Args)
	}
	if childEnv.SSHTTY != "multi-anti" || childEnv.Home == "" || childEnv.Home != childEnv.UserProfile {
		t.Fatalf("unexpected isolated child HOME/USERPROFILE/SSH_TTY: %+v", childEnv)
	}
	if childEnv.MultiAntiManaged != "" || childEnv.MultiAntiAccount != "" || childEnv.MultiAntiIsolated != "" || childEnv.MultiAntiHome != "" || childEnv.MultiAntiAgyHome != "" {
		t.Fatalf("expected MULTI_ANTI_* env vars stripped, got %+v", childEnv)
	}
	if runtime.GOOS != "windows" {
		if childEnv.XDGConfigHome != filepath.Join(childEnv.Home, ".config") ||
			childEnv.XDGDataHome != filepath.Join(childEnv.Home, ".local", "share") ||
			childEnv.XDGCacheHome != filepath.Join(childEnv.Home, ".cache") {
			t.Fatalf("unexpected XDG dirs in isolated child env: %+v", childEnv)
		}
	}

	assertNoSecrets(t, stdout.String(), "ya29.fake-agy-access-secret", "1//fake-agy-refresh-secret", "hdr.fake-agy-id-secret.sig")
	if !strings.Contains(stderr.String(), "Authentication required.") {
		t.Fatalf("expected agy prompt forwarded to stderr, got %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "authentication interrupted") || strings.Contains(stderr.String(), "authentication failed") {
		t.Fatalf("expected spurious interrupt error muted after token capture, got %q", stderr.String())
	}

	var res ImportResultView
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal login --json: %v\nstdout:\n%s", err, stdout.String())
	}
	if res.ActiveKey != "agy-login@example.com" || len(res.Imported) != 1 {
		t.Fatalf("unexpected login result: %+v", res)
	}
	if res.Imported[0].Priority != 7 || res.Imported[0].DisplayName != "AgyFallback" || !res.Imported[0].HasRefreshToken || !res.Imported[0].HasAccessToken {
		t.Fatalf("unexpected imported account: %+v", res.Imported[0])
	}

	if entries, err := os.ReadDir(tmpRoot); err != nil || len(entries) != 0 {
		t.Fatalf("expected isolated login temp dir cleaned up, entries=%d err=%v", len(entries), err)
	}

	stdout.Reset()
	stderr.Reset()
	noBrowserCalls := 0
	noBrowserCfg := Config{
		Store:   st,
		OAuth:   oauth.NewGoogleOAuthClient(oauth.Config{}),
		Fetcher: &stubFetcher{},
		OpenBrowserFn: func(url string) error {
			noBrowserCalls++
			return nil
		},
		Stdin:  strings.NewReader("code-no-browser\n"),
		Stdout: &stdout,
		Stderr: &stderr,
		Now:    func() time.Time { return now },
	}
	code = Run(ctx, []string{"login", "--no-browser", "--no-refresh", "--agy-bin", fakeAgy}, noBrowserCfg)
	if code != 0 {
		t.Fatalf("login --no-browser failed code=%d stderr=%s", code, stderr.String())
	}
	if noBrowserCalls != 0 {
		t.Fatalf("expected OpenBrowserFn not called with --no-browser, got %d calls", noBrowserCalls)
	}
	if entries, err := os.ReadDir(tmpRoot); err != nil || len(entries) != 0 {
		t.Fatalf("expected isolated login temp dir cleaned up after --no-browser, entries=%d err=%v", len(entries), err)
	}
}

func TestLoginViaAgyFailurePropagation(t *testing.T) {
	ctx := context.Background()
	_, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	prevClientID := oauth.DefaultClientID
	oauth.DefaultClientID = ""
	defer func() { oauth.DefaultClientID = prevClientID }()
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
	t.Setenv("FAKE_AGY_LOGIN_MODE", "fail")

	tmpRoot := t.TempDir()
	t.Setenv("TMPDIR", tmpRoot)
	t.Setenv("TMP", tmpRoot)
	t.Setenv("TEMP", tmpRoot)

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:  st,
		OAuth:  oauth.NewGoogleOAuthClient(oauth.Config{}),
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	code := Run(ctx, []string{"login", "--no-browser", "--no-refresh", "--agy-bin", fakeAgy}, cfg)
	if code != 1 {
		t.Fatalf("expected failure exit code 1, got %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "agy login failed:") || !strings.Contains(stderr.String(), "fake agy login error: unauthorized") {
		t.Fatalf("unexpected stderr on failed agy login:\n%s", stderr.String())
	}
	if entries, err := os.ReadDir(tmpRoot); err != nil || len(entries) != 0 {
		t.Fatalf("expected isolated temp dir cleaned up on failure, entries=%d err=%v", len(entries), err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(ctx, []string{"login", "--no-browser", "--no-refresh", "--agy-bin", filepath.Join(t.TempDir(), "missing-agy")}, cfg)
	if code != 1 || !strings.Contains(stderr.String(), "resolve agy binary") {
		t.Fatalf("expected missing binary error, got code=%d stderr=%s", code, stderr.String())
	}
}

func TestSwitchAndNextStageRefreshOnlyAccountOnMissingClientID(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	alice := makeAccount("alice@example.com", 0.20, 0.20, "", "rt-alice-only", time.Time{})
	bob := makeAccount("bob@example.com", 0.90, 0.90, "", "rt-bob-only", time.Time{})
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	refreshErr := oauth.ErrMissingClientID
	oauthMock := &stubOAuth{
		refreshFn: func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, n time.Time) (domain.AccountCredentials, bool, error) {
			return creds, false, refreshErr
		},
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   oauthMock,
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	if code := Run(ctx, []string{"next", "--no-refresh", "--json"}, cfg); code != 0 {
		t.Fatalf("next with ErrMissingClientID failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ := st.Load(ctx)
	if state.ActiveKey != bob.Key {
		t.Fatalf("expected ActiveKey=bob, got %q", state.ActiveKey)
	}
	stagedRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
	if err != nil {
		t.Fatal(err)
	}
	stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedRaw)
	if err != nil || stagedID.Email != "bob@example.com" || stagedCreds.RefreshToken != "rt-bob-only" {
		t.Fatalf("unexpected staged token after next: id=%+v creds=%+v err=%v", stagedID, stagedCreds, err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"switch", "alice@example.com", "--json"}, cfg); code != 0 {
		t.Fatalf("switch with ErrMissingClientID failed code=%d stderr=%s", code, stderr.String())
	}
	state, _ = st.Load(ctx)
	if state.ActiveKey != alice.Key {
		t.Fatalf("expected ActiveKey=alice, got %q", state.ActiveKey)
	}
	stagedRaw, _ = os.ReadFile(paths.NativeAgyTokenPath())
	stagedID, stagedCreds, err = oauth.DecodeAgyTokenFile(stagedRaw)
	if err != nil || stagedID.Email != "alice@example.com" || stagedCreds.RefreshToken != "rt-alice-only" {
		t.Fatalf("unexpected staged token after switch: id=%+v creds=%+v err=%v", stagedID, stagedCreds, err)
	}

	refreshErr = oauth.ErrRefreshRevoked
	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"switch", "bob@example.com"}, cfg); code == 0 || !strings.Contains(stderr.String(), "revoked") {
		t.Fatalf("expected ErrRefreshRevoked rejection on switch, got code=%d stderr=%s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"next", "--no-refresh"}, cfg); code == 0 {
		t.Fatalf("expected next to reject revoked remaining account, got code=%d stdout=%s", code, stdout.String())
	}
}

func TestQuotaStaleNoteAndDoctorOAuthClientCheck(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)

	alice := makeAccount("alice@example.com", 0.75, 0.80, "", "rt-alice", time.Time{})
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	oauthMock := &stubOAuth{
		refreshFn: func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, n time.Time) (domain.AccountCredentials, bool, error) {
			return creds, false, oauth.ErrMissingClientID
		},
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		AgyBinary: fakeAgy,
		Store:     st,
		OAuth:     oauthMock,
		Fetcher:   &stubFetcher{},
		Stdout:    &stdout,
		Stderr:    &stderr,
		Now:       func() time.Time { return now },
	}

	if code := Run(ctx, []string{"quota"}, cfg); code != 0 {
		t.Fatalf("quota failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stale (set OAuth client_id to refresh offline)") {
		t.Fatalf("expected stale note in quota output:\n%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--json"}, cfg); code != 0 {
		t.Fatalf("quota --json failed code=%d stderr=%s", code, stderr.String())
	}
	var qRep QuotaReportView
	if err := json.Unmarshal(stdout.Bytes(), &qRep); err != nil {
		t.Fatalf("unmarshal quota --json: %v", err)
	}
	if len(qRep.Accounts) != 1 || !strings.Contains(qRep.Accounts[0].Error, "missing OAuth client_id") {
		t.Fatalf("expected raw missing OAuth client_id error in JSON, got %+v", qRep.Accounts)
	}

	prevClientID := oauth.DefaultClientID
	oauth.DefaultClientID = ""
	defer func() { oauth.DefaultClientID = prevClientID }()
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"doctor"}, cfg); code != 0 {
		t.Fatalf("doctor failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[INFO]") || !strings.Contains(stdout.String(), "oauth_client") || !strings.Contains(stdout.String(), "not configured; login uses agy fallback (set MULTI_ANTI_OAUTH_CLIENT_ID for offline quota refresh)") {
		t.Fatalf("expected oauth_client [INFO] check in doctor output:\n%s", stdout.String())
	}

	stdout.Reset()
	if code := Run(ctx, []string{"doctor", "--json"}, cfg); code != 0 {
		t.Fatalf("doctor --json failed code=%d stderr=%s", code, stderr.String())
	}
	var docInfo DoctorReportView
	if err := json.Unmarshal(stdout.Bytes(), &docInfo); err != nil {
		t.Fatalf("unmarshal doctor --json: %v", err)
	}
	if !docInfo.Healthy || !hasDoctorCheck(docInfo.Checks, "oauth_client", DoctorInfo) {
		t.Fatalf("expected healthy doctor with oauth_client info check, got %+v", docInfo.Checks)
	}

	const configuredClientID = "test-client-id.apps.googleusercontent.com"
	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", configuredClientID)
	stdout.Reset()
	if code := Run(ctx, []string{"doctor", "--json"}, cfg); code != 0 {
		t.Fatalf("doctor --json with client_id failed code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), configuredClientID) {
		t.Fatalf("doctor output leaked client_id:\n%s", stdout.String())
	}
	var docOK DoctorReportView
	if err := json.Unmarshal(stdout.Bytes(), &docOK); err != nil {
		t.Fatalf("unmarshal doctor --json: %v", err)
	}
	if !hasDoctorCheck(docOK.Checks, "oauth_client", DoctorOK) {
		t.Fatalf("expected oauth_client OK check, got %+v", docOK.Checks)
	}

	t.Setenv("MULTI_ANTI_OAUTH_CLIENT_ID", "")
	oauth.DefaultClientID = "build-default-client-id"
	stdout.Reset()
	if code := Run(ctx, []string{"doctor", "--json"}, cfg); code != 0 {
		t.Fatalf("doctor --json with DefaultClientID failed code=%d stderr=%s", code, stderr.String())
	}
	var docDefaultOK DoctorReportView
	if err := json.Unmarshal(stdout.Bytes(), &docDefaultOK); err != nil {
		t.Fatalf("unmarshal doctor --json: %v", err)
	}
	if !hasDoctorCheck(docDefaultOK.Checks, "oauth_client", DoctorOK) {
		t.Fatalf("expected oauth_client OK check with DefaultClientID, got %+v", docDefaultOK.Checks)
	}
}

func TestUsageAliasAndFullModelsAndQuotaDisplay(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)

	gemWeeklyReset := now.Add(141*time.Hour + 59*time.Minute)
	gem5hReset := now.Add(4*time.Hour + 47*time.Minute)
	threePWeeklyReset := now.Add(158*time.Hour + 13*time.Minute)

	proAcc := domain.Account{
		Key:   "elobuddyvietnam@gmail.com",
		Email: "elobuddyvietnam@gmail.com",
		Health: domain.AccountHealth{
			Status: domain.HealthReady,
		},
		Creds: domain.AccountCredentials{
			AccessToken:  "at-pro",
			RefreshToken: "rt-pro",
			Expiry:       now.Add(time.Hour),
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now,
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", DisplayName: "Five Hour Limit Remaining", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.8733, ResetAt: &gem5hReset},
				{GroupID: "gemini-weekly", DisplayName: "Weekly Limit Remaining", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.8181, ResetAt: &gemWeeklyReset},
				{GroupID: "3p-5h", DisplayName: "Five Hour Limit Remaining", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.00},
				{GroupID: "3p-weekly", DisplayName: "Weekly Limit Remaining", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.3591, ResetAt: &threePWeeklyReset},
			},
		},
		AddedAt: now.Add(-24 * time.Hour),
	}

	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = proAcc.Key
		s.Accounts[proAcc.Key] = proAcc
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   &stubOAuth{},
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	if code := Run(ctx, []string{"usage", "--cached"}, cfg); code != 0 {
		t.Fatalf("usage --cached failed code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	wantCompact := []string{
		"elobuddyvietnam@gmail.com (pro) [*]",
		"gemini",
		"claude/gpt",
		"5h [#########.]  87.33%",
		"4h 47m (2026-11-20 04:47Z)",
		"wk [########..]  81.81%",
		"5d 21h 59m (2026-11-25 21:59Z)",
		"5h [##########] 100.00%  -",
		"wk [####......]  35.91%",
		"6d 14h 13m (2026-11-26 14:13Z)",
	}
	for _, want := range wantCompact {
		if !strings.Contains(out, want) {
			t.Fatalf("usage --cached output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{
		"Models within this group:",
		"For paid Pro plans",
		"│Within each group",
		"argon",
	} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(unwanted)) {
			t.Fatalf("usage --cached output unexpectedly included %q:\n%s", unwanted, out)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"usage", "--cached", "--pool", "gemini"}, cfg); code != 0 {
		t.Fatalf("usage --cached --pool gemini failed code=%d stderr=%s", code, stderr.String())
	}
	poolOut := stdout.String()
	if !strings.Contains(poolOut, "gemini") || !strings.Contains(poolOut, "87.33%") {
		t.Fatalf("expected gemini compact breakdown in filtered output:\n%s", poolOut)
	}
	if strings.Contains(poolOut, "claude/gpt") {
		t.Fatalf("unexpected other pool rows in --pool gemini output:\n%s", poolOut)
	}

	freeReset := now.Add(2*time.Hour + 15*time.Minute)
	freeAcc := domain.Account{
		Key:   "free@example.com",
		Email: "free@example.com",
		Health: domain.AccountHealth{
			Status: domain.HealthReady,
		},
		Creds: domain.AccountCredentials{
			AccessToken:  "at-free",
			RefreshToken: "rt-free",
			Expiry:       now.Add(time.Hour),
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt:        now,
			Source:           domain.QuotaSourceModels,
			Tier:             domain.TierFree,
			SummaryForbidden: true,
			Models: []domain.ModelQuota{
				{ModelID: "orchestrator-neon", DisplayName: "Orchestrator (Neon)", RemainingFraction: 0.625, ResetAt: &freeReset},
				{ModelID: "claude-opus-5-5", DisplayName: "Claude Opus 5.5", RemainingFraction: 1.0},
			},
		},
		AddedAt: now.Add(-12 * time.Hour),
	}
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		delete(s.Accounts, proAcc.Key)
		s.ActiveKey = freeAcc.Key
		s.Accounts[freeAcc.Key] = freeAcc
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--cached"}, cfg); code != 0 {
		t.Fatalf("quota --cached for free account failed code=%d stderr=%s", code, stderr.String())
	}
	freeOut := stdout.String()
	for _, want := range []string{
		"free@example.com (free) [*]",
		"Orchestrator (Neon)",
		"gemini",
		"62.50%",
		"2h 15m (2026-11-20 02:15Z)",
		"Claude Opus 5.5",
		"claude/gpt",
		"100.00%",
	} {
		if !strings.Contains(freeOut, want) {
			t.Fatalf("free-tier quota output missing %q:\n%s", want, freeOut)
		}
	}
}

func TestAccountsColumnsNativeSyncAndSwitchHints(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)
	t.Setenv("SSH_TTY", "")

	alice := domain.Account{
		Key:    "alice@example.com",
		Email:  "alice@example.com",
		Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
		Creds: domain.AccountCredentials{
			AccessToken:  "old-at-alice",
			RefreshToken: "rt-alice",
			Expiry:       now.Add(5 * time.Minute),
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now,
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.90},
				{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.98},
				{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.50},
			},
		},
		AddedAt: now.Add(-24 * time.Hour),
	}
	bob := makeAccount("bob@example.com", 0.40, 0.30, "at-bob", "rt-bob", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fresherAliceRaw, err := oauth.EncodeAgyTokenFile(alice.Email, domain.AccountCredentials{
		AccessToken:  "native-fresher-alice",
		RefreshToken: "rt-alice",
		Expiry:       now.Add(55 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), fresherAliceRaw, true); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   &stubOAuth{},
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	if code := Run(ctx, []string{"accounts"}, cfg); code != 0 {
		t.Fatalf("accounts failed code=%d stderr=%s", code, stderr.String())
	}
	accOut := stdout.String()
	for _, want := range []string{"GEMINI 5h/wk", "CLAUDE/GPT 5h/wk", "90%/98%", "-/50%"} {
		if !strings.Contains(accOut, want) {
			t.Fatalf("accounts output missing %q:\n%s", want, accOut)
		}
	}
	if strings.Contains(accOut, "ARGON") {
		t.Fatalf("accounts output unexpectedly contained ARGON:\n%s", accOut)
	}
	stateAfterSync, _ := st.Load(ctx)
	if stateAfterSync.Accounts[alice.Key].Creds.AccessToken != "native-fresher-alice" {
		t.Fatalf("accounts did not sync fresher native token: %+v", stateAfterSync.Accounts[alice.Key].Creds)
	}

	unmanagedRaw, err := oauth.EncodeAgyTokenFile("stranger@example.com", domain.AccountCredentials{
		AccessToken:  "at-stranger",
		RefreshToken: "rt-stranger",
		Expiry:       now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), unmanagedRaw, true); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := Run(ctx, []string{"accounts"}, cfg); code != 0 {
		t.Fatalf("accounts(unmanaged) failed code=%d", code)
	}
	if !strings.Contains(stdout.String(), "stranger@example.com (not managed") {
		t.Fatalf("expected unmanaged native token note, got:\n%s", stdout.String())
	}

	bobNativeRaw, _ := oauth.EncodeAgyTokenFile(bob.Email, domain.AccountCredentials{
		AccessToken:  "at-bob",
		RefreshToken: "rt-bob",
		Expiry:       now.Add(time.Hour),
	})
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), bobNativeRaw, true); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := Run(ctx, []string{"accounts"}, cfg); code != 0 {
		t.Fatalf("accounts(drift) failed code=%d", code)
	}
	if !strings.Contains(stdout.String(), "native agy token holds bob@example.com while active_key is alice@example.com") {
		t.Fatalf("expected drift note, got:\n%s", stdout.String())
	}

	fresherAliceRaw2, _ := oauth.EncodeAgyTokenFile(alice.Email, domain.AccountCredentials{
		AccessToken:  "native-fresher-alice-2",
		RefreshToken: "rt-alice",
		Expiry:       now.Add(58 * time.Minute),
	})
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), fresherAliceRaw2, true); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"next", "--no-refresh"}, cfg); code != 0 {
		t.Fatalf("next failed code=%d stderr=%s", code, stderr.String())
	}
	nextOut := stdout.String()
	if !strings.Contains(nextOut, "Switched active account to bob@example.com") ||
		!strings.Contains(nextOut, "policy mode is highest_remaining") ||
		!strings.Contains(nextOut, "SSH_TTY is unset") {
		t.Fatalf("expected highest_remaining and SSH_TTY hints in next output:\n%s", nextOut)
	}
	stateAfterNext, _ := st.Load(ctx)
	if stateAfterNext.Accounts[alice.Key].Creds.AccessToken != "native-fresher-alice-2" {
		t.Fatalf("next overwrote native token without saving fresher alice token: %+v", stateAfterNext.Accounts[alice.Key].Creds)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"switch", "alice@example.com", "--json"}, cfg); code != 0 {
		t.Fatalf("switch --json failed code=%d stderr=%s", code, stderr.String())
	}
	var swView SwitchResultView
	if err := json.Unmarshal(stdout.Bytes(), &swView); err != nil {
		t.Fatalf("switch --json produced invalid JSON: %v\nraw:\n%s", err, stdout.String())
	}
	if swView.ToKey != alice.Key {
		t.Fatalf("ToKey = %q, want %q", swView.ToKey, alice.Key)
	}
}

func TestStatusLineHidesOutputWhenSignedOut(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	_, populatedStore := setupCLIEnv(t)
	alice := makeAccount("alice@example.com", 0.80, 0.80, "at-alice", "rt-alice", now.Add(time.Hour))
	if _, err := populatedStore.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	runStatusLine := func(st store.Store, stdin string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Run(ctx, []string{"statusline"}, Config{
			Store:  st,
			Stdin:  strings.NewReader(stdin),
			Stdout: &stdout,
			Stderr: &stderr,
			Now:    func() time.Time { return now },
		})
		return code, stdout.String(), stderr.String()
	}

	for _, payload := range []string{`{}`, `{"email":"","agent_state":"idle"}`} {
		code, out, errOut := runStatusLine(populatedStore, payload)
		if code != 0 || errOut != "" {
			t.Fatalf("statusline(%s) code=%d stderr=%q", payload, code, errOut)
		}
		if out != "" {
			t.Fatalf("statusline(%s) stdout = %q, want 0 bytes", payload, out)
		}
	}

	_, emptyStore := setupCLIEnv(t)
	code, out, errOut := runStatusLine(emptyStore, `{}`)
	if code != 0 || errOut != "" {
		t.Fatalf("statusline(empty store, {}) code=%d stderr=%q", code, errOut)
	}
	if out != "" {
		t.Fatalf("statusline(empty store, {}) stdout = %q, want 0 bytes", out)
	}

	code, out, errOut = runStatusLine(populatedStore, `{"email":"alice@example.com"}`)
	if code != 0 || errOut != "" {
		t.Fatalf("statusline(signed-in) code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "alice@example.com") {
		t.Fatalf("expected alice@example.com in signed-in statusline output, got %q", out)
	}
}

func TestRemoveClearsMatchingStagedNativeToken(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	t.Run("removes native token only when staged account matches removed account", func(t *testing.T) {
		paths, st := setupCLIEnv(t)
		alice := makeAccount("alice@example.com", 0.80, 0.80, "at-alice", "rt-alice", now.Add(time.Hour))
		bob := makeAccount("bob@example.com", 0.70, 0.70, "at-bob", "rt-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = alice.Key
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		aliceRaw, err := oauth.EncodeAgyTokenFile(alice.Email, alice.Creds)
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), aliceRaw, true); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		cfg := Config{
			Store:  st,
			Stdout: &stdout,
			Stderr: &stderr,
			Now:    func() time.Time { return now },
		}

		if code := Run(ctx, []string{"remove", "bob@example.com"}, cfg); code != 0 {
			t.Fatalf("remove bob failed code=%d stderr=%s", code, stderr.String())
		}
		rawAfterBob, err := os.ReadFile(paths.NativeAgyTokenPath())
		if err != nil {
			t.Fatalf("expected staged alice token preserved after removing bob, read err=%v", err)
		}
		idAfterBob, _, err := oauth.DecodeAgyTokenFile(rawAfterBob)
		if err != nil || idAfterBob.Key != alice.Key {
			t.Fatalf("unexpected staged token after removing bob: id=%+v err=%v", idAfterBob, err)
		}

		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, []string{"remove", "alice@example.com"}, cfg); code != 0 {
			t.Fatalf("remove alice failed code=%d stderr=%s", code, stderr.String())
		}
		if _, err := os.Stat(paths.NativeAgyTokenPath()); !os.IsNotExist(err) {
			t.Fatalf("expected staged native token deleted after removing alice, stat err=%v", err)
		}
		state, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Accounts) != 0 || state.ActiveKey != "" {
			t.Fatalf("expected empty accounts and cleared ActiveKey, got %+v", state)
		}
	})

	t.Run("preserves unmanaged native token and succeeds when native token is absent", func(t *testing.T) {
		paths, st := setupCLIEnv(t)
		alice := makeAccount("alice@example.com", 0.80, 0.80, "at-alice", "rt-alice", now.Add(time.Hour))
		bob := makeAccount("bob@example.com", 0.70, 0.70, "at-bob", "rt-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = alice.Key
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		otherRaw, err := oauth.EncodeAgyTokenFile("other@example.com", domain.AccountCredentials{
			AccessToken:  "at-other",
			RefreshToken: "rt-other",
			Expiry:       now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), otherRaw, true); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		cfg := Config{
			Store:  st,
			Stdout: &stdout,
			Stderr: &stderr,
			Now:    func() time.Time { return now },
		}

		if code := Run(ctx, []string{"remove", "alice@example.com"}, cfg); code != 0 {
			t.Fatalf("remove alice with unmanaged native token failed code=%d stderr=%s", code, stderr.String())
		}
		rawAfterAlice, err := os.ReadFile(paths.NativeAgyTokenPath())
		if err != nil {
			t.Fatalf("expected unmanaged native token preserved, read err=%v", err)
		}
		idAfterAlice, _, err := oauth.DecodeAgyTokenFile(rawAfterAlice)
		if err != nil || idAfterAlice.Key != "other@example.com" {
			t.Fatalf("unexpected unmanaged native token content: id=%+v err=%v", idAfterAlice, err)
		}

		if err := os.Remove(paths.NativeAgyTokenPath()); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, []string{"remove", "bob@example.com"}, cfg); code != 0 {
			t.Fatalf("remove bob when native token absent failed code=%d stderr=%s", code, stderr.String())
		}
	})
}

func TestRunPositionalAccountGuardSwitchPoolHintsAndWindowsSSHTTY(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 16, 0, 0, 0, time.UTC)

	newReproAccounts := func() (domain.Account, domain.Account) {
		reset3P := now.Add(14*time.Hour + 9*time.Minute)
		dijen := domain.Account{
			Key:         "dijendergupta5@gmail.com",
			Email:       "dijendergupta5@gmail.com",
			DisplayName: "dijen",
			Health:      domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
			Creds: domain.AccountCredentials{
				AccessToken:  "at-dijen",
				RefreshToken: "rt-dijen",
				Expiry:       now.Add(time.Hour),
			},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 1.0},
					{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 1.0},
					{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.0, ResetAt: &reset3P},
				},
			},
			AddedAt: now.Add(-24 * time.Hour),
		}
		sanj := domain.Account{
			Key:    "sanjeesanya4@gmail.com",
			Email:  "sanjeesanya4@gmail.com",
			Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
			Creds: domain.AccountCredentials{
				AccessToken:  "at-sanj",
				RefreshToken: "rt-sanj",
				Expiry:       now.Add(time.Hour),
			},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 1.0},
					{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 1.0},
					{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.0},
					{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.49},
				},
			},
			AddedAt: now.Add(-24 * time.Hour),
		}
		return dijen, sanj
	}

	t.Run("run_rejects_bare_email_or_account_before_dashdash_without_side_effects", func(t *testing.T) {
		paths, st := setupCLIEnv(t)
		fakeAgy := buildFakeAgyBinary(t)
		dijen, sanj := newReproAccounts()
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[dijen.Key] = dijen
			s.Accounts[sanj.Key] = sanj
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "agy.log")
		t.Setenv("FAKE_AGY_LOG", logPath)

		var fetchCalls atomic.Int32
		var stdout, stderr bytes.Buffer
		cfg := Config{
			AgyBinary: fakeAgy,
			Store:     st,
			OAuth:     &stubOAuth{},
			Fetcher: &stubFetcher{
				fetchFn: func(ctx context.Context, accessToken string, opts quota.FetchOptions) (domain.QuotaSnapshot, error) {
					fetchCalls.Add(1)
					return domain.QuotaSnapshot{}, nil
				},
			},
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
			Now:    func() time.Time { return now },
		}

		rejectedCases := []struct {
			args     []string
			wantHint string
		}{
			{
				args:     []string{"run", "dijendergupta5@gmail.com"},
				wantHint: "use 'multi-anti run --account dijendergupta5@gmail.com'",
			},
			{
				args:     []string{"run", "dijen"},
				wantHint: "use 'multi-anti run --account dijen'",
			},
			{
				args:     []string{"run", "typo@gmail.com"},
				wantHint: "use 'multi-anti run --account typo@gmail.com'",
			},
			{
				args:     []string{"run", "-c", "dijendergupta5@gmail.com"},
				wantHint: "use 'multi-anti run --account dijendergupta5@gmail.com'",
			},
		}

		for _, tc := range rejectedCases {
			stdout.Reset()
			stderr.Reset()
			code := Run(ctx, tc.args, cfg)
			if code != 2 {
				t.Fatalf("Run(%v) exit code = %d, want 2 (stderr=%q)", tc.args, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantHint) {
				t.Fatalf("Run(%v) stderr = %q, want substring %q", tc.args, stderr.String(), tc.wantHint)
			}
		}

		if fetchCalls.Load() != 0 {
			t.Fatalf("rejected run args triggered %d quota fetches, want 0", fetchCalls.Load())
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatalf("rejected run args invoked agy (stat log err=%v)", err)
		}
		if _, err := os.Stat(paths.NativeAgyTokenPath()); !os.IsNotExist(err) {
			t.Fatalf("rejected run args staged native token (stat err=%v)", err)
		}
		stateAfterReject, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stateAfterReject.ActiveKey != "" {
			t.Fatalf("ActiveKey mutated to %q after rejected run", stateAfterReject.ActiveKey)
		}
		for _, k := range []domain.AccountKey{dijen.Key, sanj.Key} {
			if stateAfterReject.Accounts[k].LastUsedAt != nil {
				t.Fatalf("LastUsedAt mutated for %s after rejected run", k)
			}
		}

		validCases := []struct {
			args        []string
			wantLogPref string
			wantLogArg  string
		}{
			{
				args:        []string{"run", "--no-refresh", "-p", "dijendergupta5@gmail.com"},
				wantLogPref: "sanjeesanya4@gmail.com|",
				wantLogArg:  "-p dijendergupta5@gmail.com",
			},
			{
				args:        []string{"run", "--no-refresh", "--", "-p", "dijendergupta5@gmail.com"},
				wantLogPref: "sanjeesanya4@gmail.com|",
				wantLogArg:  "-p dijendergupta5@gmail.com",
			},
			{
				args:        []string{"run", "--no-refresh", "--account", "dijendergupta5@gmail.com", "-p", "hi"},
				wantLogPref: "dijendergupta5@gmail.com|",
				wantLogArg:  "-p hi",
			},
		}

		for _, tc := range validCases {
			_ = os.Remove(logPath)
			stdout.Reset()
			stderr.Reset()
			code := Run(ctx, tc.args, cfg)
			if code != 0 {
				t.Fatalf("Run(%v) code = %d, want 0 (stderr=%q)", tc.args, code, stderr.String())
			}
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("Run(%v) read agy log: %v", tc.args, err)
			}
			line := strings.TrimSpace(string(raw))
			if !strings.HasPrefix(line, tc.wantLogPref) || !strings.Contains(line, tc.wantLogArg) {
				t.Fatalf("Run(%v) log = %q, want prefix %q and arg %q", tc.args, line, tc.wantLogPref, tc.wantLogArg)
			}
		}
	})

	t.Run("switch_and_next_emit_truthful_pool_exhaustion_hints", func(t *testing.T) {
		_, st := setupCLIEnv(t)
		dijen, sanj := newReproAccounts()
		cooldownAcc := makeAccount("cool@example.com", 0.90, 0.90, "at-cool", "rt-cool", now.Add(time.Hour))
		until := now.Add(15 * time.Minute)
		cooldownAcc.Health = domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &until, Reason: "429", UpdatedAt: now}
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[dijen.Key] = dijen
			s.Accounts[sanj.Key] = sanj
			s.Accounts[cooldownAcc.Key] = cooldownAcc
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		cfg := Config{
			Store:   st,
			OAuth:   &stubOAuth{},
			Fetcher: &stubFetcher{},
			Stdout:  &stdout,
			Stderr:  &stderr,
			Now:     func() time.Time { return now },
		}

		if code := Run(ctx, []string{"switch", "dijendergupta5@gmail.com"}, cfg); code != 0 {
			t.Fatalf("switch dijen failed code=%d stderr=%s", code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{
			"dijendergupta5@gmail.com has exhausted quota in pool 3p (target_pool=all)",
			"plain 'multi-anti run' will switch to sanjeesanya4@gmail.com",
			"multi-anti run --account dijendergupta5@gmail.com",
			"--pool gemini",
			"multi-anti policy --pool gemini",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("switch dijen output missing %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "fill_first") {
			t.Fatalf("switch dijen output unexpectedly suggested fill_first:\n%s", out)
		}

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Policy.Mode = domain.SwitchFillFirst
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, []string{"switch", "dijendergupta5@gmail.com"}, cfg); code != 0 {
			t.Fatalf("switch dijen under fill_first failed code=%d stderr=%s", code, stderr.String())
		}
		fillOut := stdout.String()
		if !strings.Contains(fillOut, "dijendergupta5@gmail.com has exhausted quota in pool 3p (target_pool=all)") {
			t.Fatalf("switch dijen under fill_first missing pool exhaustion hint:\n%s", fillOut)
		}
		if strings.Contains(fillOut, "fill_first") {
			t.Fatalf("switch dijen under fill_first unexpectedly contained fill_first:\n%s", fillOut)
		}

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Policy.Mode = domain.SwitchHighestRemaining
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, []string{"switch", "cool@example.com", "--force"}, cfg); code != 0 {
			t.Fatalf("switch cooldown --force failed code=%d stderr=%s", code, stderr.String())
		}
		coolOut := stdout.String()
		if !strings.Contains(coolOut, "ineligible for automatic selection (health_cooldown)") ||
			!strings.Contains(coolOut, "multi-anti run --account cool@example.com") {
			t.Fatalf("switch cooldown --force missing expected hint:\n%s", coolOut)
		}
		if strings.Contains(coolOut, "fill_first") {
			t.Fatalf("switch cooldown --force unexpectedly suggested fill_first:\n%s", coolOut)
		}

		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, []string{"next", "--no-refresh"}, cfg); code != 0 {
			t.Fatalf("next failed code=%d stderr=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Switched active account to sanjeesanya4@gmail.com") {
			t.Fatalf("expected next to switch to sanjeesanya4@gmail.com, got:\n%s", stdout.String())
		}
	})

	t.Run("windows_and_linux_ssh_tty_hints_in_switch_next_and_doctor", func(t *testing.T) {
		_, st := setupCLIEnv(t)
		fakeAgy := buildFakeAgyBinary(t)
		alice := makeAccount("alice@example.com", 0.90, 0.90, "at-alice", "rt-alice", now.Add(time.Hour))
		bob := makeAccount("bob@example.com", 0.80, 0.80, "at-bob", "rt-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = alice.Key
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		cfg := Config{
			AgyBinary: fakeAgy,
			Store:     st,
			OAuth:     &stubOAuth{},
			Fetcher:   &stubFetcher{},
			Stdout:    &stdout,
			Stderr:    &stderr,
			Now:       func() time.Time { return now },
		}

		winApp := NewApp(cfg)
		winApp.goos = "windows"
		for _, args := range [][]string{
			{"switch", "bob@example.com"},
			{"next", "--no-refresh"},
			{"doctor"},
		} {
			stdout.Reset()
			stderr.Reset()
			if code := winApp.Run(ctx, args); code != 0 {
				t.Fatalf("winApp.Run(%v) failed code=%d stderr=%s", args, code, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, `set $env:SSH_TTY="multi-anti" in PowerShell`) {
				t.Fatalf("winApp.Run(%v) missing PowerShell SSH_TTY hint:\n%s", args, out)
			}
			if strings.Contains(out, "export SSH_TTY=multi-anti") {
				t.Fatalf("winApp.Run(%v) unexpectedly contained export SSH_TTY:\n%s", args, out)
			}
		}

		linApp := NewApp(cfg)
		linApp.goos = "linux"
		for _, args := range [][]string{
			{"switch", "bob@example.com"},
			{"next", "--no-refresh"},
			{"doctor"},
		} {
			stdout.Reset()
			stderr.Reset()
			if code := linApp.Run(ctx, args); code != 0 {
				t.Fatalf("linApp.Run(%v) failed code=%d stderr=%s", args, code, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, "export SSH_TTY=multi-anti") {
				t.Fatalf("linApp.Run(%v) missing export SSH_TTY hint:\n%s", args, out)
			}
			if strings.Contains(out, "$env:SSH_TTY") {
				t.Fatalf("linApp.Run(%v) unexpectedly contained PowerShell SSH_TTY hint:\n%s", args, out)
			}
		}
	})
}

func TestRunDefaultsAutoRelaunchAndSupportsNoAutoRelaunch(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 16, 40, 0, 0, time.UTC)

	defaultParsed, err := parseRunArgs([]string{"--no-refresh"})
	if err != nil {
		t.Fatalf("parseRunArgs(--no-refresh) error = %v", err)
	}
	if !defaultParsed.autoRelaunch {
		t.Fatalf("expected autoRelaunch to default to true")
	}

	disabledParsed, err := parseRunArgs([]string{"--no-auto-relaunch"})
	if err != nil {
		t.Fatalf("parseRunArgs(--no-auto-relaunch) error = %v", err)
	}
	if disabledParsed.autoRelaunch {
		t.Fatalf("expected --no-auto-relaunch to set autoRelaunch=false")
	}

	_, st := setupCLIEnv(t)
	fakeAgy := buildFakeAgyBinary(t)
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		for i, rem := range []float64{0.95, 0.85, 0.75, 0.65, 0.55} {
			email := string([]byte{'a', byte('1' + i)}) + "@example.com"
			acc := makeAccount(email, rem, rem, "at-"+email, "rt-"+email, now.Add(time.Hour))
			s.Accounts[acc.Key] = acc
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "scale.log")
	t.Setenv("FAKE_AGY_LOG", logPath)
	t.Setenv("FAKE_AGY_FAIL_ACCOUNT", "a1@example.com,a2@example.com,a3@example.com,a4@example.com")

	var stdout, stderr bytes.Buffer
	cfg := Config{
		AgyBinary: fakeAgy,
		Store:     st,
		OAuth:     &stubOAuth{},
		Fetcher:   &stubFetcher{},
		Stdin:     strings.NewReader(""),
		Stdout:    &stdout,
		Stderr:    &stderr,
		Now:       func() time.Time { return now },
	}

	if code := Run(ctx, []string{"run", "--no-refresh", "-p", "hi"}, cfg); code != 0 {
		t.Fatalf("run across 5 accounts failed code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[4], "a5@example.com|") {
		t.Fatalf("expected failover across all 5 accounts, got lines=%v", lines)
	}
}

func TestExpiredQuotaWindowResetsToFullAcrossStatusLineAccountsQuotaAndSelector(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 17, 0, 0, 0, time.UTC)
	_, st := setupCLIEnv(t)

	epochZero := time.Unix(0, 0).UTC()
	bkset5hReset := now.Add(4*time.Hour + 30*time.Minute)
	bksetWkReset := now.Add(7 * 24 * time.Hour)
	elo5hReset := now.Add(4*time.Hour + 42*time.Minute)
	eloWkReset := now.Add(6 * 24 * time.Hour)
	nttExpired5h := time.Date(2026, 11, 21, 18, 29, 29, 0, time.UTC)
	nttExpired3p5h := time.Date(2026, 11, 21, 22, 1, 56, 0, time.UTC)
	nttFutureWk := time.Date(2026, 11, 28, 13, 29, 29, 0, time.UTC)
	nttFuture3pWk := time.Date(2026, 11, 28, 17, 1, 56, 0, time.UTC)

	bkset := domain.Account{
		Key:    "tuannt.bkset@gmail.com",
		Email:  "tuannt.bkset@gmail.com",
		Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
		Creds:  domain.AccountCredentials{AccessToken: "at-bkset", RefreshToken: "rt-bkset", Expiry: now.Add(time.Hour)},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now.Add(-5 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.79, ResetAt: &bkset5hReset},
				{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.93, ResetAt: &bksetWkReset},
				{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.0, ResetAt: &epochZero},
				{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 1.0, ResetAt: &epochZero},
			},
		},
		AddedAt: now.Add(-48 * time.Hour),
	}

	elo := domain.Account{
		Key:    "elobuddyvietnam@gmail.com",
		Email:  "elobuddyvietnam@gmail.com",
		Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
		Creds:  domain.AccountCredentials{AccessToken: "at-elo", RefreshToken: "rt-elo", Expiry: now.Add(time.Hour)},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now.Add(-2 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.71, ResetAt: &elo5hReset},
				{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.89, ResetAt: &eloWkReset},
				{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.0, ResetAt: &epochZero},
				{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 1.0, ResetAt: &epochZero},
			},
		},
		AddedAt: now.Add(-48 * time.Hour),
	}

	ntt := domain.Account{
		Key:    "ntt.cn2.01@gmail.com",
		Email:  "ntt.cn2.01@gmail.com",
		Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now.Add(-96 * time.Hour)},
		Creds:  domain.AccountCredentials{AccessToken: "at-ntt", RefreshToken: "rt-ntt", Expiry: now.Add(-95 * time.Hour)},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: time.Date(2026, 11, 21, 17, 1, 55, 0, time.UTC),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.5065, ResetAt: &nttExpired5h},
				{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.8590, ResetAt: &nttFutureWk},
				{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.0, ResetAt: &nttExpired3p5h},
				{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 1.0, ResetAt: &nttFuture3pWk},
			},
		},
		AddedAt: now.Add(-96 * time.Hour),
	}

	epochZeroAcc := domain.Account{
		Key:    "epoch-zero@example.com",
		Email:  "epoch-zero@example.com",
		Health: domain.AccountHealth{Status: domain.HealthReady, UpdatedAt: now},
		Creds:  domain.AccountCredentials{AccessToken: "at-ez", RefreshToken: "rt-ez", Expiry: now.Add(time.Hour)},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now.Add(-5 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.0, ResetAt: &epochZero},
			},
		},
		AddedAt: now.Add(-48 * time.Hour),
	}

	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = bkset.Key
		s.Accounts[bkset.Key] = bkset
		s.Accounts[elo.Key] = elo
		s.Accounts[ntt.Key] = ntt
		s.Accounts[epochZeroAcc.Key] = epochZeroAcc
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	newCfg := func(stdin string) Config {
		return Config{
			Store:   st,
			OAuth:   &stubOAuth{},
			Fetcher: &stubFetcher{},
			Stdin:   strings.NewReader(stdin),
			Stdout:  &stdout,
			Stderr:  &stderr,
			Now:     func() time.Time { return now },
		}
	}

	if code := Run(ctx, []string{"statusline"}, newCfg(`{"email":"tuannt.bkset@gmail.com"}`)); code != 0 {
		t.Fatalf("statusline failed code=%d stderr=%s", code, stderr.String())
	}
	slOut := stdout.String()
	var nttStatusLine string
	for _, line := range strings.Split(slOut, "\n") {
		if strings.Contains(line, "ntt.cn2.01@gmail.com") {
			nttStatusLine = line
			break
		}
	}
	if !strings.HasPrefix(nttStatusLine, "> ntt.cn2.01@gmail.com") || !strings.Contains(nttStatusLine, "100%/86%") || strings.Contains(nttStatusLine, "51%") {
		t.Fatalf("statusline ntt.cn2.01 row = %q, want > prefix and 100%%/86%%:\n%s", nttStatusLine, slOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"ls"}, newCfg("")); code != 0 {
		t.Fatalf("ls failed code=%d stderr=%s", code, stderr.String())
	}
	lsOut := stdout.String()
	var nttLsLine string
	for _, line := range strings.Split(lsOut, "\n") {
		if strings.Contains(line, "ntt.cn2.01@gmail.com") {
			nttLsLine = line
			break
		}
	}
	if !strings.Contains(nttLsLine, "100%/86%") || strings.Contains(nttLsLine, "51%") {
		t.Fatalf("ls ntt.cn2.01 row = %q, want 100%%/86%%:\n%s", nttLsLine, lsOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--cached"}, newCfg("")); code != 0 {
		t.Fatalf("quota --cached failed code=%d stderr=%s", code, stderr.String())
	}
	quotaOut := stdout.String()
	var rank1Line, epochLine string
	for _, line := range strings.Split(quotaOut, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "1 ") && strings.Contains(trimmed, "ntt.cn2.01@gmail.com") {
			rank1Line = line
		}
		if strings.Contains(line, "epoch-zero@example.com") && strings.Contains(line, "quota_exhausted") {
			epochLine = line
		}
	}
	if rank1Line == "" || !strings.Contains(rank1Line, "86%") {
		t.Fatalf("expected ntt.cn2.01@gmail.com ranked #1 at 86%% in quota --cached:\n%s", quotaOut)
	}
	if !strings.Contains(quotaOut, "5h [##########] 100.00%  -") || !strings.Contains(quotaOut, "wk [#########.]  85.90%") {
		t.Fatalf("expected expired 5h reset to 100.00%% and wk at 85.90%% in quota --cached:\n%s", quotaOut)
	}
	if epochLine == "" {
		t.Fatalf("expected epoch-zero@example.com to remain quota_exhausted in quota --cached:\n%s", quotaOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"next", "--no-refresh"}, newCfg("")); code != 0 {
		t.Fatalf("next --no-refresh failed code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Switched active account to ntt.cn2.01@gmail.com") {
		t.Fatalf("expected next to select ntt.cn2.01@gmail.com, got:\n%s", stdout.String())
	}
}

func TestLegacyArgonStateOmittedFromTablesAndArgonModelSelectsGemini(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 18, 0, 0, 0, time.UTC)
	paths, st := setupCLIEnv(t)

	legacyJSON := `{
  "schema_version": 1,
  "generation": 2,
  "active_key": "old@example.com",
  "policy": {
    "mode": "highest_remaining",
    "target_pool": "gemini-argon",
    "min_remaining_threshold": 0.05,
    "cooldown_default": 300000000000,
    "refresh_skew": 300000000000
  },
  "accounts": {
    "old@example.com": {
      "key": "old@example.com",
      "email": "old@example.com",
      "health": {"status": "ready", "updated_at": "2026-11-25T17:00:00Z"},
      "creds": {"access_token": "at-old", "refresh_token": "rt-old", "expiry": "2026-11-25T19:00:00Z"},
      "quota": {
        "fetched_at": "2026-11-21T17:00:00Z",
        "source": "retrieveUserQuotaSummary",
        "tier": "pro",
        "buckets": [
          {"group_id": "gemini-5h", "pool": "gemini", "window": "5h", "remaining_fraction": 0.25},
          {"group_id": "gemini-weekly", "pool": "gemini", "window": "weekly", "remaining_fraction": 0.90},
          {"group_id": "3p-5h", "pool": "3p", "window": "5h", "remaining_fraction": 1.0},
          {"group_id": "3p-weekly", "pool": "3p", "window": "weekly", "remaining_fraction": 1.0},
          {"group_id": "gemini-argon-wtu-weekly", "pool": "gemini-argon", "window": "weekly", "remaining_fraction": 1.0}
        ]
      },
      "added_at": "2026-11-21T17:00:00Z"
    },
    "fresh@example.com": {
      "key": "fresh@example.com",
      "email": "fresh@example.com",
      "health": {"status": "ready", "updated_at": "2026-11-25T17:00:00Z"},
      "creds": {"access_token": "at-fresh", "refresh_token": "rt-fresh", "expiry": "2026-11-25T19:00:00Z"},
      "quota": {
        "fetched_at": "2026-11-25T17:30:00Z",
        "source": "retrieveUserQuotaSummary",
        "tier": "pro",
        "buckets": [
          {"group_id": "gemini-5h", "pool": "gemini", "window": "5h", "remaining_fraction": 0.95},
          {"group_id": "gemini-weekly", "pool": "gemini", "window": "weekly", "remaining_fraction": 0.95},
          {"group_id": "3p-5h", "pool": "3p", "window": "5h", "remaining_fraction": 1.0},
          {"group_id": "3p-weekly", "pool": "3p", "window": "weekly", "remaining_fraction": 1.0}
        ]
      },
      "added_at": "2026-11-25T17:00:00Z"
    }
  }
}`
	if err := platform.WriteFileAtomic(paths.StateFile(), []byte(legacyJSON), true); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	newCfg := func(stdin string) Config {
		return Config{
			Store:   st,
			OAuth:   &stubOAuth{},
			Fetcher: &stubFetcher{},
			Stdin:   strings.NewReader(stdin),
			Stdout:  &stdout,
			Stderr:  &stderr,
			Now:     func() time.Time { return now },
		}
	}

	if code := Run(ctx, []string{"accounts"}, newCfg("")); code != 0 {
		t.Fatalf("accounts failed code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(strings.ToUpper(stdout.String()), "ARGON") {
		t.Fatalf("accounts output unexpectedly contained ARGON:\n%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"statusline"}, newCfg(`{"email":"old@example.com"}`)); code != 0 {
		t.Fatalf("statusline failed code=%d stderr=%s", code, stderr.String())
	}
	slOut := stdout.String()
	if strings.Contains(strings.ToUpper(slOut), "ARGON") || strings.Contains(slOut, "OTHER") {
		t.Fatalf("statusline unexpectedly contained ARGON or OTHER:\n%s", slOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--cached"}, newCfg("")); code != 0 {
		t.Fatalf("quota --cached failed code=%d stderr=%s", code, stderr.String())
	}
	qOut := stdout.String()
	if strings.Contains(strings.ToLower(qOut), "argon") || strings.Contains(strings.ToLower(qOut), "other") {
		t.Fatalf("quota --cached unexpectedly contained argon or other:\n%s", qOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"switch", "--model", "gemini-4-argon-high", "--no-refresh", "--json"}, newCfg("")); code != 0 {
		t.Fatalf("switch --model gemini-4-argon-high failed code=%d stderr=%s", code, stderr.String())
	}
	var sw SwitchResultView
	if err := json.Unmarshal(stdout.Bytes(), &sw); err != nil {
		t.Fatalf("unmarshal switch output: %v\n%s", err, stdout.String())
	}
	if sw.Outcome != domain.OutcomeSwitched || sw.ToKey != "fresh@example.com" || sw.Pool != domain.PoolGemini {
		t.Fatalf("switch result = %+v, want switched to fresh@example.com on PoolGemini", sw)
	}
}

func hasDoctorCheck(checks []DoctorCheckView, name string, status DoctorStatus) bool {
	for _, c := range checks {
		if c.Name == name && c.Status == status {
			return true
		}
	}
	return false
}

func TestResetTimeFullDisplayLocalTimezoneAndJSON(t *testing.T) {
	ctx := context.Background()
	ict := time.FixedZone("ICT", 7*3600)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC).In(ict)
	_, st := setupCLIEnv(t)

	gem5hReset := now.UTC().Add(5*time.Hour + 54*time.Minute)
	gemWkReset := now.UTC().Add(6*24*time.Hour + 14*time.Hour + 13*time.Minute)
	threeP5hReset := now.UTC().Add(1*time.Hour + 52*time.Minute)
	cooldownUntil := now.UTC().Add(25 * time.Minute)
	fetchedAt := now.UTC().Add(-10 * time.Minute)

	alice := domain.Account{
		Key:   "alice@example.com",
		Email: "alice@example.com",
		Health: domain.AccountHealth{
			Status:        domain.HealthCooldown,
			CooldownUntil: &cooldownUntil,
			Reason:        "rate limited",
			UpdatedAt:     now.UTC(),
		},
		Creds: domain.AccountCredentials{
			AccessToken:  "at-alice-secret",
			RefreshToken: "rt-alice-secret",
			IDToken:      "id-alice-secret",
			Expiry:       now.UTC().Add(time.Hour),
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: fetchedAt,
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.72, ResetAt: &gem5hReset},
				{GroupID: "gemini-wk", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.85, ResetAt: &gemWkReset},
				{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 0.83, ResetAt: &threeP5hReset},
				{GroupID: "3p-wk", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 1.0},
			},
			Models: []domain.ModelQuota{
				{ModelID: "gemini-2.5-pro", DisplayName: "Gemini 2.5 Pro", RemainingFraction: 0.72, ResetAt: &gem5hReset},
			},
		},
		AddedAt: now.UTC().Add(-24 * time.Hour),
	}

	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg := Config{
		Store:   st,
		OAuth:   &stubOAuth{},
		Fetcher: &stubFetcher{},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Now:     func() time.Time { return now },
	}

	for _, cmd := range [][]string{{"quota", "--cached"}, {"usage", "--cached"}} {
		stdout.Reset()
		stderr.Reset()
		if code := Run(ctx, cmd, cfg); code != 0 {
			t.Fatalf("%v failed code=%d stderr=%s", cmd, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{
			"Quota (cached, pool=all, 2026-11-26 19:00:00 +07:00)",
			"alice@example.com (pro) [*] [cooldown: 25m (2026-11-26 19:25 +07:00)] (fetched 10m ago, 2026-11-26 18:50 +07:00)",
			"5h [#######...]  72.00%",
			"5h 54m (2026-11-27 00:54 +07:00)",
			"wk [#########.]  85.00%",
			"6d 14h 13m (2026-12-03 09:13 +07:00)",
			"5h [########..]  83.00%",
			"1h 52m (2026-11-26 20:52 +07:00)",
			"wk [##########] 100.00%  -",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("%v output missing %q:\n%s", cmd, want, out)
			}
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--cached", "--models"}, cfg); code != 0 {
		t.Fatalf("quota --cached --models failed code=%d stderr=%s", code, stderr.String())
	}
	modelsOut := stdout.String()
	if !strings.Contains(modelsOut, "gemini-2.5-pro (Gemini 2.5 Pro)") ||
		!strings.Contains(modelsOut, "72.00%") ||
		!strings.Contains(modelsOut, "5h 54m (2026-11-27 00:54 +07:00)") {
		t.Fatalf("quota --cached --models missing local reset detail:\n%s", modelsOut)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"accounts"}, cfg); code != 0 {
		t.Fatalf("accounts failed code=%d stderr=%s", code, stderr.String())
	}
	accOut := stdout.String()
	for _, want := range []string{"cooldown (25m)", "72%(5h54m)/85%(6d14h)", "83%(1h52m)/100%"} {
		if !strings.Contains(accOut, want) {
			t.Fatalf("accounts output missing %q:\n%s", want, accOut)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"switch", "alice@example.com"}, cfg); code == 0 {
		t.Fatalf("expected cooldown switch refusal, got code=0")
	} else if !strings.Contains(stderr.String(), "resets in 25m at 2026-11-26 19:25 +07:00") {
		t.Fatalf("switch cooldown refusal missing local timestamp: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"quota", "--cached", "--models", "--json"}, cfg); code != 0 {
		t.Fatalf("quota --json failed code=%d stderr=%s", code, stderr.String())
	}
	quotaJSONRaw := stdout.String()
	assertNoSecrets(t, quotaJSONRaw, "at-alice-secret", "rt-alice-secret", "id-alice-secret")

	var qReport struct {
		GeneratedAtLocal string `json:"generated_at_local"`
		Accounts         []struct {
			ResetAtLocal string `json:"reset_at_local"`
			ResetIn      string `json:"reset_in"`
			ResetInSecs  *int64 `json:"reset_in_seconds"`
			Health       struct {
				CooldownUntilLocal       string `json:"cooldown_until_local"`
				CooldownRemaining        string `json:"cooldown_remaining"`
				CooldownRemainingSeconds *int64 `json:"cooldown_remaining_seconds"`
			} `json:"health"`
			Quota struct {
				FetchedAtLocal string `json:"fetched_at_local"`
				Buckets        []struct {
					GroupID      string `json:"group_id"`
					ResetAtLocal string `json:"reset_at_local"`
					ResetIn      string `json:"reset_in"`
					ResetInSecs  *int64 `json:"reset_in_seconds"`
				} `json:"buckets"`
				Models []struct {
					ModelID      string `json:"model_id"`
					ResetAtLocal string `json:"reset_at_local"`
					ResetIn      string `json:"reset_in"`
					ResetInSecs  *int64 `json:"reset_in_seconds"`
				} `json:"models"`
			} `json:"quota"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &qReport); err != nil {
		t.Fatalf("unmarshal quota --json: %v\n%s", err, quotaJSONRaw)
	}
	if qReport.GeneratedAtLocal != "2026-11-26 19:00:00 +07:00" {
		t.Fatalf("generated_at_local = %q", qReport.GeneratedAtLocal)
	}
	qa := qReport.Accounts[0]
	if qa.ResetAtLocal != "2026-11-26 19:25 +07:00" || qa.ResetIn != "25m" || qa.ResetInSecs == nil || *qa.ResetInSecs != 1500 {
		t.Fatalf("QuotaAccountView reset fields = %+v", qa)
	}
	if qa.Health.CooldownUntilLocal != "2026-11-26 19:25 +07:00" || qa.Health.CooldownRemaining != "25m" || qa.Health.CooldownRemainingSeconds == nil || *qa.Health.CooldownRemainingSeconds != 1500 {
		t.Fatalf("QuotaAccountView health fields = %+v", qa.Health)
	}
	if qa.Quota.FetchedAtLocal != "2026-11-26 18:50:00 +07:00" {
		t.Fatalf("fetched_at_local = %q", qa.Quota.FetchedAtLocal)
	}
	if len(qa.Quota.Buckets) != 4 ||
		qa.Quota.Buckets[0].ResetAtLocal != "2026-11-27 00:54 +07:00" ||
		qa.Quota.Buckets[0].ResetIn != "5h 54m" ||
		qa.Quota.Buckets[0].ResetInSecs == nil || *qa.Quota.Buckets[0].ResetInSecs != 5*3600+54*60 {
		t.Fatalf("unexpected quota.buckets[0]: %+v", qa.Quota.Buckets)
	}
	if len(qa.Quota.Models) != 1 ||
		qa.Quota.Models[0].ResetAtLocal != "2026-11-27 00:54 +07:00" ||
		qa.Quota.Models[0].ResetIn != "5h 54m" ||
		qa.Quota.Models[0].ResetInSecs == nil || *qa.Quota.Models[0].ResetInSecs != 5*3600+54*60 {
		t.Fatalf("unexpected quota.models[0]: %+v", qa.Quota.Models)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(ctx, []string{"accounts", "--json"}, cfg); code != 0 {
		t.Fatalf("accounts --json failed code=%d stderr=%s", code, stderr.String())
	}
	accJSONRaw := stdout.String()
	assertNoSecrets(t, accJSONRaw, "at-alice-secret", "rt-alice-secret", "id-alice-secret")

	var accList struct {
		Accounts []struct {
			PrimaryResetAtLocal   string `json:"primary_reset_at_local"`
			PrimaryResetIn        string `json:"primary_reset_in"`
			PrimaryResetInSeconds *int64 `json:"primary_reset_in_seconds"`
			Health                struct {
				CooldownUntilLocal       string `json:"cooldown_until_local"`
				CooldownRemainingSeconds *int64 `json:"cooldown_remaining_seconds"`
			} `json:"health"`
			Quota *struct {
				FetchedAtLocal string `json:"fetched_at_local"`
				Buckets        []struct {
					GroupID      string `json:"group_id"`
					ResetAtLocal string `json:"reset_at_local"`
					ResetIn      string `json:"reset_in"`
				} `json:"buckets"`
			} `json:"quota"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &accList); err != nil {
		t.Fatalf("unmarshal accounts --json: %v\n%s", err, accJSONRaw)
	}
	if len(accList.Accounts) != 1 {
		t.Fatalf("accounts len = %d, want 1", len(accList.Accounts))
	}
	av := accList.Accounts[0]
	if av.PrimaryResetAtLocal != "2026-11-27 00:54 +07:00" || av.PrimaryResetIn != "5h 54m" || av.PrimaryResetInSeconds == nil || *av.PrimaryResetInSeconds != 5*3600+54*60 {
		t.Fatalf("AccountView primary reset fields = %+v", av)
	}
	if av.Health.CooldownUntilLocal != "2026-11-26 19:25 +07:00" || av.Health.CooldownRemainingSeconds == nil || *av.Health.CooldownRemainingSeconds != 1500 {
		t.Fatalf("AccountView health fields = %+v", av.Health)
	}
	if av.Quota == nil || av.Quota.FetchedAtLocal != "2026-11-26 18:50:00 +07:00" || len(av.Quota.Buckets) != 4 {
		t.Fatalf("accounts --json missing full quota.buckets: %+v", av.Quota)
	}
}
