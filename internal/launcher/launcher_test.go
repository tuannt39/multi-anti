package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

type stubOAuth struct {
	refreshFn func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error)
}

func (s *stubOAuth) Login(context.Context, oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("unexpected Login")
}

func (s *stubOAuth) Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error) {
	if s.refreshFn != nil {
		return s.refreshFn(ctx, creds, skew, now)
	}
	return creds, false, nil
}

func (s *stubOAuth) ImportNativeToken(context.Context, string) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("unexpected ImportNativeToken")
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
			{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.8},
		},
	}, nil
}

func setupLauncherEnv(t *testing.T) (realHome string, paths platform.Paths, st *store.FileStore) {
	t.Helper()
	tmp := t.TempDir()
	realHome = filepath.Join(tmp, "real-home")
	if err := os.MkdirAll(realHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", realHome)
	t.Setenv("USERPROFILE", realHome)
	t.Setenv("MULTI_ANTI_HOME", filepath.Join(tmp, "data"))
	t.Setenv("MULTI_ANTI_AGY_HOME", filepath.Join(tmp, "agy-home"))
	t.Setenv("MULTI_ANTI_RUN_ID", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("GIT_CONFIG_GLOBAL", "")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/test-ssh-agent.sock")

	p, err := platform.ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths() error = %v", err)
	}
	return realHome, p, store.NewFileStore(p)
}

func makeLauncherAccount(email string, rem float64, accessTok, refreshTok string, expiry time.Time) domain.Account {
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
			ClientID:     "client-123",
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: expiry.Add(-5 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{
					GroupID:           "gemini-5h",
					DisplayName:       "Gemini 5-Hour",
					Pool:              domain.PoolGemini,
					Window:            domain.Window5h,
					RemainingFraction: rem,
				},
			},
		},
		AddedAt: expiry.Add(-24 * time.Hour),
	}
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

func buildFakeAgyBinary(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	binName := "fake-agy"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(dir, binName)
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fake agy binary: %v\n%s", err, out)
	}
	return binPath
}

func TestPrepareLaunchDefaultMode(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	realHome, paths, st := setupLauncherEnv(t)

	origRaw, err := oauth.EncodeAgyTokenFile("native-orig@example.com", domain.AccountCredentials{
		AccessToken:  "orig-access",
		RefreshToken: "orig-refresh",
		Expiry:       now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), origRaw, true); err != nil {
		t.Fatal(err)
	}

	alice := makeLauncherAccount("alice@example.com", 0.40, "stale-alice", "ref-alice", now.Add(-time.Minute))
	bob := makeLauncherAccount("bob@example.com", 0.30, "tok-bob", "ref-bob", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	oa := &stubOAuth{
		refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, ts time.Time) (domain.AccountCredentials, bool, error) {
			if creds.RefreshToken == "ref-alice" {
				creds.AccessToken = "fresh-alice"
				creds.Expiry = ts.Add(time.Hour)
				return creds, true, nil
			}
			return creds, false, nil
		},
	}
	fetcher := &stubFetcher{
		fetchFn: func(fetchCtx context.Context, token string, opts quota.FetchOptions) (domain.QuotaSnapshot, error) {
			lockCtx, cancel := context.WithTimeout(fetchCtx, 100*time.Millisecond)
			defer cancel()
			if err := platform.WithFileLock(lockCtx, paths.StateLockFile(), false, func() error { return nil }); err != nil {
				t.Errorf("StateLockFile unexpectedly held during Fetch: %v", err)
			}

			rem := 0.25
			if token == "fresh-alice" {
				rem = 0.85
			}
			return domain.QuotaSnapshot{
				FetchedAt: opts.Now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: rem},
				},
			}, nil
		},
	}

	prepared, err := PrepareLaunch(ctx, st, oa, fetcher, selector.NewDefaultSelector(), PrepareOptions{Now: now})
	if err != nil {
		t.Fatalf("PrepareLaunch() error = %v", err)
	}
	if prepared.Isolated {
		t.Fatalf("expected default non-isolated launch")
	}
	if prepared.Account.Key != alice.Key {
		t.Fatalf("selected account = %q, want %q", prepared.Account.Key, alice.Key)
	}
	if prepared.StagedTokenPath != paths.NativeAgyTokenPath() {
		t.Fatalf("StagedTokenPath = %q, want %q", prepared.StagedTokenPath, paths.NativeAgyTokenPath())
	}

	envMap := envSliceToMap(prepared.Env)
	if envMap["HOME"] != realHome {
		t.Fatalf("HOME = %q, want realHome %q", envMap["HOME"], realHome)
	}
	if envMap["SSH_TTY"] != "multi-anti" || envMap["MULTI_ANTI_MANAGED"] != "1" || envMap["MULTI_ANTI_ACCOUNT"] != string(alice.Key) || envMap["MULTI_ANTI_HOME"] != paths.DataDir() {
		t.Fatalf("unexpected injected env: %+v", envMap)
	}

	stagedRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
	if err != nil {
		t.Fatal(err)
	}
	stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if stagedID.Key != alice.Key || stagedCreds.AccessToken != "fresh-alice" {
		t.Fatalf("staged token mismatch: id=%+v creds=%+v", stagedID, stagedCreds)
	}

	if _, err := st.RestoreNativeBackup(ctx); err != nil {
		t.Fatalf("RestoreNativeBackup() error = %v", err)
	}
	restoredRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredRaw, origRaw) {
		t.Fatalf("restored native token does not match original backup")
	}
}

func TestPrepareLaunchIsolatedMode(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	realHome, paths, st := setupLauncherEnv(t)

	if err := platform.WriteFileAtomic(paths.NativeAgySettingsPath(), []byte(`{"theme":"dark"}`+"\n"), false); err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(filepath.Join(paths.NativeGeminiConfigDir(), "marker.txt"), []byte("shared-config\n"), false); err != nil {
		t.Fatal(err)
	}

	alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[alice.Key] = alice
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	prepared, err := PrepareLaunch(ctx, st, nil, nil, nil, PrepareOptions{
		Isolate:   true,
		NoRefresh: true,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("PrepareLaunch(Isolate) error = %v", err)
	}
	profDir := paths.ProfileDir(alice.Key)
	if !prepared.Isolated || prepared.HomeOverride != profDir {
		t.Fatalf("unexpected isolated launch metadata: %+v", prepared)
	}

	if _, err := os.Stat(paths.NativeAgyTokenPath()); !os.IsNotExist(err) {
		t.Fatalf("NativeAgyTokenPath should not be written in isolated mode")
	}

	stagedID, _, err := oauth.DecodeAgyTokenFile(mustReadFile(t, prepared.StagedTokenPath))
	if err != nil || stagedID.Key != alice.Key {
		t.Fatalf("isolated staged token invalid: id=%+v err=%v", stagedID, err)
	}
	projectedSettings := mustReadFile(t, filepath.Join(profDir, ".gemini", "antigravity-cli", "settings.json"))
	if !strings.Contains(string(projectedSettings), `"theme":"dark"`) {
		t.Fatalf("projected settings missing: %s", projectedSettings)
	}
	projectedCfg := mustReadFile(t, filepath.Join(profDir, ".gemini", "config", "marker.txt"))
	if string(projectedCfg) != "shared-config\n" {
		t.Fatalf("projected config dir missing marker: %q", projectedCfg)
	}

	envMap := envSliceToMap(prepared.Env)
	if envMap["HOME"] != profDir || envMap["USERPROFILE"] != profDir {
		t.Fatalf("HOME/USERPROFILE not overridden to %q: HOME=%q USERPROFILE=%q", profDir, envMap["HOME"], envMap["USERPROFILE"])
	}
	if envMap["MULTI_ANTI_ISOLATED"] != "1" || envMap["SSH_TTY"] != "multi-anti" {
		t.Fatalf("missing isolated markers in env: %+v", envMap)
	}
	if runtime.GOOS != "windows" {
		if envMap["XDG_CONFIG_HOME"] != filepath.Join(realHome, ".config") ||
			envMap["XDG_DATA_HOME"] != filepath.Join(realHome, ".local", "share") ||
			envMap["XDG_CACHE_HOME"] != filepath.Join(realHome, ".cache") ||
			envMap["GIT_CONFIG_GLOBAL"] != filepath.Join(realHome, ".gitconfig") ||
			envMap["SSH_AUTH_SOCK"] != "/tmp/test-ssh-agent.sock" {
			t.Fatalf("dotfile preservation env mismatch: %+v", envMap)
		}
	}
}

func TestPrepareLaunchMissingClientIDFallback(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		accessTok string
		expiry    time.Time
		explicit  bool
	}{
		{
			name:      "only refresh_token with empty access_token",
			accessTok: "",
			expiry:    time.Time{},
		},
		{
			name:      "expired access_token with refresh_token",
			accessTok: "expired-alice",
			expiry:    now.Add(-time.Hour),
			explicit:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths, st := setupLauncherEnv(t)

			alice := makeLauncherAccount("alice@example.com", 0.80, tc.accessTok, "ref-alice", tc.expiry)
			alice.Creds.ClientID = ""
			if _, err := st.Update(ctx, func(s *domain.StoreState) error {
				s.Accounts[alice.Key] = alice
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			oa := &stubOAuth{
				refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, _ time.Time) (domain.AccountCredentials, bool, error) {
					return creds, false, oauth.ErrMissingClientID
				},
			}
			fetcher := &stubFetcher{
				fetchFn: func(_ context.Context, _ string, _ quota.FetchOptions) (domain.QuotaSnapshot, error) {
					return domain.QuotaSnapshot{}, errors.New("unexpected fetch when refresh failed")
				},
			}

			opts := PrepareOptions{Now: now}
			if tc.explicit {
				opts.Account = alice.Key
			}
			prepared, err := PrepareLaunch(ctx, st, oa, fetcher, selector.NewDefaultSelector(), opts)
			if err != nil {
				t.Fatalf("PrepareLaunch() error = %v", err)
			}
			if prepared.Account.Key != alice.Key {
				t.Fatalf("selected account = %q, want %q", prepared.Account.Key, alice.Key)
			}
			if prepared.Account.Health.Status != domain.HealthReady {
				t.Fatalf("account health = %+v, want HealthReady", prepared.Account.Health)
			}
			if prepared.StagedTokenPath != paths.NativeAgyTokenPath() {
				t.Fatalf("StagedTokenPath = %q, want %q", prepared.StagedTokenPath, paths.NativeAgyTokenPath())
			}

			stagedRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
			if err != nil {
				t.Fatalf("ReadFile(NativeAgyTokenPath) error = %v", err)
			}
			stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedRaw)
			if err != nil {
				t.Fatalf("DecodeAgyTokenFile() error = %v", err)
			}
			if stagedID.Key != alice.Key {
				t.Fatalf("staged account = %q, want %q", stagedID.Key, alice.Key)
			}
			if stagedCreds.AccessToken != tc.accessTok || stagedCreds.RefreshToken != "ref-alice" {
				t.Fatalf("staged creds = %+v, want access=%q refresh=%q", stagedCreds, tc.accessTok, "ref-alice")
			}
		})
	}
}

func TestSyncBackStagedToken(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, paths, st := setupLauncherEnv(t)

	alice := makeLauncherAccount("alice@example.com", 0.80, "old-access", "old-refresh", now.Add(10*time.Minute))
	bob := makeLauncherAccount("bob@example.com", 0.70, "bob-access", "bob-refresh", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	staged := paths.NativeAgyTokenPath()

	bobRaw, err := oauth.EncodeAgyTokenFile(bob.Email, domain.AccountCredentials{
		AccessToken:  "mutated-bob-access",
		RefreshToken: "mutated-bob-refresh",
		Expiry:       now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(staged, bobRaw, true); err != nil {
		t.Fatal(err)
	}
	if err := SyncBackStagedToken(ctx, st, staged, alice.Email); err != nil {
		t.Fatalf("SyncBackStagedToken(mismatch) error = %v", err)
	}
	afterMismatch, _ := st.Load(ctx)
	if afterMismatch.Accounts[alice.Key].Creds.AccessToken != "old-access" ||
		afterMismatch.Accounts[bob.Key].Creds.AccessToken != "bob-access" {
		t.Fatalf("mismatched SyncBack mutated store: %+v", afterMismatch.Accounts)
	}

	aliceUpdatedRaw, err := oauth.EncodeAgyTokenFile(alice.Email, domain.AccountCredentials{
		AccessToken:  "new-alice-access",
		RefreshToken: "new-alice-refresh",
		Expiry:       now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(staged, aliceUpdatedRaw, true); err != nil {
		t.Fatal(err)
	}
	if err := SyncBackStagedToken(ctx, st, staged, alice.Email); err != nil {
		t.Fatalf("SyncBackStagedToken(match) error = %v", err)
	}
	afterSync, _ := st.Load(ctx)
	if afterSync.Accounts[alice.Key].Creds.AccessToken != "new-alice-access" ||
		afterSync.Accounts[alice.Key].Creds.RefreshToken != "new-alice-refresh" ||
		afterSync.Accounts[alice.Key].Creds.ClientID != "client-123" {
		t.Fatalf("synced alice creds unexpected: %+v", afterSync.Accounts[alice.Key].Creds)
	}
	genAfterSync := afterSync.Generation

	if err := SyncBackStagedToken(ctx, st, staged, alice.Email); err != nil {
		t.Fatal(err)
	}
	afterNoop, _ := st.Load(ctx)
	if afterNoop.Generation != genAfterSync {
		t.Fatalf("Generation bumped on unchanged syncback: %d -> %d", genAfterSync, afterNoop.Generation)
	}

	// Verify SyncBackStagedToken preserves RefreshToken/IDToken and clears HealthNeedsReauth + stale FetchError.
	realFuture := time.Now().UTC().Add(time.Hour)
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		cur := s.Accounts[alice.Key]
		cur.Creds.IDToken = "keep-id-token"
		cur.Health = domain.AccountHealth{Status: domain.HealthNeedsReauth, Reason: "expired", UpdatedAt: now}
		cur.Quota.FetchError = "stale fetch err"
		s.Accounts[alice.Key] = cur
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	freshNoRefreshRaw, err := oauth.EncodeAgyTokenFile(alice.Email, domain.AccountCredentials{
		AccessToken: "reauthed-alice-access",
		Expiry:      realFuture,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(staged, freshNoRefreshRaw, true); err != nil {
		t.Fatal(err)
	}
	if err := SyncBackStagedToken(ctx, st, staged, alice.Email); err != nil {
		t.Fatalf("SyncBackStagedToken(reauth clear) error = %v", err)
	}
	afterReauth, _ := st.Load(ctx)
	if afterReauth.Accounts[alice.Key].Health.Status != domain.HealthReady {
		t.Fatalf("Health = %+v, want HealthReady", afterReauth.Accounts[alice.Key].Health)
	}
	if afterReauth.Accounts[alice.Key].Creds.RefreshToken != "new-alice-refresh" || afterReauth.Accounts[alice.Key].Creds.IDToken != "keep-id-token" {
		t.Fatalf("SyncBackStagedToken dropped preserved creds: %+v", afterReauth.Accounts[alice.Key].Creds)
	}
	if afterReauth.Accounts[alice.Key].Quota.FetchError != "" {
		t.Fatalf("FetchError = %q, want cleared", afterReauth.Accounts[alice.Key].Quota.FetchError)
	}
}

func TestPrepareLaunchPreservesFresherNativeTokenWithNoRefresh(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	_, paths, st := setupLauncherEnv(t)

	alice := makeLauncherAccount("alice@example.com", 0.30, "old-alice-at", "ref-alice", now.Add(10*time.Minute))
	bob := makeLauncherAccount("bob@example.com", 0.90, "bob-at", "ref-bob", now.Add(time.Hour))
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.ActiveKey = alice.Key
		s.Accounts[alice.Key] = alice
		s.Accounts[bob.Key] = bob
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fresherAliceRaw, err := oauth.EncodeAgyTokenFile(alice.Email, domain.AccountCredentials{
		AccessToken:  "fresher-alice-at",
		RefreshToken: "ref-alice",
		Expiry:       now.Add(55 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), fresherAliceRaw, true); err != nil {
		t.Fatal(err)
	}

	prepared, err := PrepareLaunch(ctx, st, &stubOAuth{}, &stubFetcher{}, selector.NewDefaultSelector(), PrepareOptions{
		Account:   bob.Key,
		NoRefresh: true,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("PrepareLaunch() error = %v", err)
	}
	if prepared.Account.Key != bob.Key {
		t.Fatalf("selected account = %q, want %q", prepared.Account.Key, bob.Key)
	}
	after, _ := st.Load(ctx)
	if after.Accounts[alice.Key].Creds.AccessToken != "fresher-alice-at" {
		t.Fatalf("PrepareLaunch --no-refresh overwrote native token without saving fresher alice token: %+v", after.Accounts[alice.Key].Creds)
	}
}

func TestRunFakeAgyScenarios(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	fakeBin := buildFakeAgyBinary(t, `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writeSignal(cid, fromKey, toKey string) {
	sigDir := filepath.Join(os.Getenv("MULTI_ANTI_HOME"), "signals")
	_ = os.MkdirAll(sigDir, 0o700)
	sig, _ := json.Marshal(map[string]any{
		"conversation_id": cid,
		"from_key":        fromKey,
		"to_key":          toKey,
		"reason":          "quota exhausted",
		"at":              time.Now().UTC().Format(time.RFC3339),
	})
	_ = os.WriteFile(filepath.Join(sigDir, "latest.json"), sig, 0o600)
}

func main() {
	acct := os.Getenv("MULTI_ANTI_ACCOUNT")
	if logFile := os.Getenv("FAKE_AGY_LOG"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(9)
		}
		_, _ = f.WriteString(acct + "|" + strings.Join(os.Args[1:], " ") + "\n")
		_ = f.Close()
	}

	switch os.Getenv("FAKE_AGY_MODE") {
	case "interactive_signal":
		if acct == "alice@example.com" {
			writeSignal("conv-interactive-77", "alice@example.com", "bob@example.com")
			fmt.Fprintln(os.Stderr, "switching via stop hook")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "resumed ok")
	case "interactive_clean_exit_signal":
		if acct == "alice@example.com" {
			writeSignal("conv-clean-88", "alice@example.com", "bob@example.com")
			os.Exit(0)
		}
		fmt.Fprintln(os.Stdout, "clean relaunch ok on "+acct)
	case "headless_quota_tail":
		if acct == "acct1@example.com" {
			fmt.Fprint(os.Stdout, strings.Repeat("x", 72*1024))
			fmt.Fprintln(os.Stderr, "\nHTTP 429 RESOURCE_EXHAUSTED: retryDelay: \"60s\"")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "headless success on "+acct)
	case "headless_signal_chain":
		switch acct {
		case "acct1@example.com":
			writeSignal("conv-h-1", "acct1@example.com", "acct2@example.com")
			os.Exit(1)
		case "acct2@example.com":
			writeSignal("conv-h-2", "acct2@example.com", "acct3@example.com")
			os.Exit(1)
		default:
			fmt.Fprintln(os.Stdout, "chained success on "+acct)
		}
	case "non_quota_error":
		fmt.Fprintln(os.Stderr, "invalid CLI flag")
		os.Exit(2)
	case "login_new_account":
		tokPath := filepath.Join(os.Getenv("MULTI_ANTI_AGY_HOME"), ".gemini", "antigravity-cli", "antigravity-oauth-token")
		if err := os.MkdirAll(filepath.Dir(tokPath), 0o700); err != nil {
			os.Exit(9)
		}
		payload := "{\"token\":{\"access_token\":\"tok-carol\",\"token_type\":\"Bearer\",\"refresh_token\":\"ref-carol\",\"expiry\":\"2099-01-01T00:00:00Z\"},\"auth_method\":\"consumer\",\"id_token_email\":\"carol@example.com\"}\n"
		if err := os.WriteFile(tokPath, []byte(payload), 0o600); err != nil {
			os.Exit(9)
		}
	case "logout_delete_token":
		tokPath := filepath.Join(os.Getenv("MULTI_ANTI_AGY_HOME"), ".gemini", "antigravity-cli", "antigravity-oauth-token")
		if err := os.Remove(tokPath); err != nil {
			os.Exit(9)
		}
	default:
		os.Exit(3)
	}
}
`)

	t.Run("interactive AutoRelaunch consumes signal and passes --conversation", func(t *testing.T) {
		_, paths, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		bob := makeLauncherAccount("bob@example.com", 0.70, "tok-bob", "ref-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "invocations.log")
		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:       fakeBin,
			Args:         []string{"--model", "gemini-2.5-pro"},
			NoRefresh:    true,
			AutoRelaunch: true,
			MaxSwitches:  2,
			Stdin:        strings.NewReader(""),
			Stdout:       &stdout,
			Stderr:       &stderr,
			ExtraEnv:     []string{"FAKE_AGY_MODE=interactive_signal", "FAKE_AGY_LOG=" + logPath},
			Now:          func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 || res.LastAccount != bob.Key || len(res.Switches) != 1 {
			t.Fatalf("unexpected RunResult: %+v", res)
		}

		lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, logPath))), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 invocations, got %d: %v", len(lines), lines)
		}
		if lines[0] != "alice@example.com|--model gemini-2.5-pro" {
			t.Fatalf("attempt 1 = %q", lines[0])
		}
		if lines[1] != "bob@example.com|--conversation conv-interactive-77 -i continue --model gemini-2.5-pro" {
			t.Fatalf("attempt 2 = %q", lines[1])
		}
		if _, ok, _ := hook.ReadLatestSwitchSignal(paths); ok {
			t.Fatalf("expected signals to be cleared after Run")
		}
	})

	t.Run("interactive AutoRelaunch=false does not relaunch and clears signal", func(t *testing.T) {
		_, paths, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		bob := makeLauncherAccount("bob@example.com", 0.70, "tok-bob", "ref-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:       fakeBin,
			NoRefresh:    true,
			AutoRelaunch: false,
			MaxSwitches:  2,
			Stdin:        strings.NewReader(""),
			Stdout:       &stdout,
			Stderr:       &stderr,
			ExtraEnv:     []string{"FAKE_AGY_MODE=interactive_signal"},
			Now:          func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 1 || len(res.Switches) != 0 || res.LastAccount != alice.Key {
			t.Fatalf("unexpected RunResult: %+v", res)
		}
		if _, ok, _ := hook.ReadLatestSwitchSignal(paths); ok {
			t.Fatalf("expected unconsumed signal to be cleared on exit")
		}
	})

	t.Run("headless -p retries on 429 tail error and marks cooldown", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		acct1 := makeLauncherAccount("acct1@example.com", 0.90, "tok-1", "ref-1", now.Add(time.Hour))
		acct2 := makeLauncherAccount("acct2@example.com", 0.70, "tok-2", "ref-2", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[acct1.Key] = acct1
			s.Accounts[acct2.Key] = acct2
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:      fakeBin,
			Args:        []string{"-p", "explain this diff"},
			NoRefresh:   true,
			MaxSwitches: 2,
			Stdout:      &stdout,
			Stderr:      &stderr,
			ExtraEnv:    []string{"FAKE_AGY_MODE=headless_quota_tail"},
			Now:         func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 || res.LastAccount != acct2.Key || len(res.Switches) != 1 {
			t.Fatalf("unexpected RunResult: %+v", res)
		}
		if !strings.Contains(stdout.String(), "headless success on acct2@example.com") {
			t.Fatalf("stdout missing success output: %q", stdout.String())
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		a1 := stAfter.Accounts[acct1.Key]
		if a1.Health.Status != domain.HealthCooldown || a1.Health.CooldownUntil == nil || !a1.Health.CooldownUntil.Equal(now.Add(60*time.Second)) {
			t.Fatalf("acct1 health = %+v, want cooldown +60s", a1.Health)
		}
	})

	t.Run("headless updates --conversation across multi-hop signal switches", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		a1 := makeLauncherAccount("acct1@example.com", 0.90, "tok-1", "ref-1", now.Add(time.Hour))
		a2 := makeLauncherAccount("acct2@example.com", 0.80, "tok-2", "ref-2", now.Add(time.Hour))
		a3 := makeLauncherAccount("acct3@example.com", 0.70, "tok-3", "ref-3", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[a1.Key] = a1
			s.Accounts[a2.Key] = a2
			s.Accounts[a3.Key] = a3
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "chain.log")
		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:      fakeBin,
			Args:        []string{"-p", "continue"},
			NoRefresh:   true,
			MaxSwitches: 3,
			Stdout:      &stdout,
			Stderr:      &stderr,
			ExtraEnv:    []string{"FAKE_AGY_MODE=headless_signal_chain", "FAKE_AGY_LOG=" + logPath},
			Now:         func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 || res.LastAccount != a3.Key || len(res.Switches) != 2 {
			t.Fatalf("unexpected RunResult: %+v", res)
		}
		lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, logPath))), "\n")
		if len(lines) != 3 {
			t.Fatalf("expected 3 attempts, got %v", lines)
		}
		if lines[1] != "acct2@example.com|--conversation conv-h-1 -p continue" ||
			lines[2] != "acct3@example.com|--conversation conv-h-2 -p continue" {
			t.Fatalf("unexpected conversation arg chain: %v", lines)
		}
	})

	t.Run("non-quota error does not retry or cool down", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		acct1 := makeLauncherAccount("acct1@example.com", 0.90, "tok-1", "ref-1", now.Add(time.Hour))
		acct2 := makeLauncherAccount("acct2@example.com", 0.70, "tok-2", "ref-2", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[acct1.Key] = acct1
			s.Accounts[acct2.Key] = acct2
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:      fakeBin,
			Args:        []string{"--prompt=hello"},
			NoRefresh:   true,
			MaxSwitches: 3,
			Stdout:      &stdout,
			Stderr:      &stderr,
			ExtraEnv:    []string{"FAKE_AGY_MODE=non_quota_error"},
			Now:         func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 2 || len(res.Switches) != 0 || res.LastAccount != acct1.Key {
			t.Fatalf("unexpected RunResult on non-quota error: %+v", res)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.Accounts[acct1.Key].Health.Status != domain.HealthReady {
			t.Fatalf("acct1 should remain ready on non-quota error, got %+v", stAfter.Accounts[acct1.Key].Health)
		}
	})

	t.Run("interactive AutoRelaunch relaunches after clean exit 0 when Stop hook wrote signal", func(t *testing.T) {
		_, paths, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		bob := makeLauncherAccount("bob@example.com", 0.70, "tok-bob", "ref-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "invocations.log")
		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:       fakeBin,
			Args:         []string{"--model", "gemini-2.5-pro"},
			NoRefresh:    true,
			AutoRelaunch: true,
			MaxSwitches:  2,
			Stdin:        strings.NewReader(""),
			Stdout:       &stdout,
			Stderr:       &stderr,
			ExtraEnv:     []string{"FAKE_AGY_MODE=interactive_clean_exit_signal", "FAKE_AGY_LOG=" + logPath},
			Now:          func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 || res.LastAccount != bob.Key || len(res.Switches) != 1 {
			t.Fatalf("unexpected RunResult: %+v", res)
		}
		if !strings.Contains(stdout.String(), "clean relaunch ok on bob@example.com") {
			t.Fatalf("stdout = %q", stdout.String())
		}
		lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, logPath))), "\n")
		if len(lines) != 2 || !strings.Contains(lines[1], "--conversation conv-clean-88") {
			t.Fatalf("unexpected invocation log: %q", lines)
		}
		if _, ok, _ := hook.ReadLatestSwitchSignal(paths); ok {
			t.Fatalf("expected switch signal cleared after relaunch")
		}
	})

	t.Run("auto-enrolls new account written by /login during agy session", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:    fakeBin,
			NoRefresh: true,
			Stdin:     strings.NewReader(""),
			Stdout:    &stdout,
			Stderr:    &stderr,
			ExtraEnv:  []string{"FAKE_AGY_MODE=login_new_account"},
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
		}

		after, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after.ActiveKey != "carol@example.com" {
			t.Fatalf("ActiveKey = %q, want carol@example.com", after.ActiveKey)
		}
		carol, ok := after.Accounts["carol@example.com"]
		if !ok || carol.Health.Status != domain.HealthReady || carol.Creds.AccessToken != "tok-carol" || carol.Creds.RefreshToken != "ref-carol" {
			t.Fatalf("carol not auto-enrolled after /login: ok=%v acc=%+v", ok, carol)
		}
		if orig, ok := after.Accounts[alice.Key]; !ok || orig.Creds.AccessToken != "tok-alice" {
			t.Fatalf("alice unexpectedly modified: ok=%v acc=%+v", ok, orig)
		}
	})

	t.Run("clears active_key when /logout deletes staged token during agy session", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:    fakeBin,
			NoRefresh: true,
			Stdin:     strings.NewReader(""),
			Stdout:    &stdout,
			Stderr:    &stderr,
			ExtraEnv:  []string{"FAKE_AGY_MODE=logout_delete_token"},
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("ExitCode = %d, want 0", res.ExitCode)
		}

		after, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after.ActiveKey != "" {
			t.Fatalf("ActiveKey = %q, want empty after /logout", after.ActiveKey)
		}
		if _, ok := after.Accounts[alice.Key]; !ok {
			t.Fatalf("alice removed unexpectedly during soft-sync /logout")
		}
	})
}

func TestRunNoneReadyReturnsResetHint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, _, st := setupLauncherEnv(t)

	resetAt := now.Add(15 * time.Minute)
	acct1 := makeLauncherAccount("acct1@example.com", 0.90, "tok-1", "ref-1", now.Add(time.Hour))
	acct1.Health = domain.AccountHealth{
		Status:        domain.HealthCooldown,
		Reason:        "quota exhausted",
		CooldownUntil: &resetAt,
		UpdatedAt:     now,
	}
	if _, err := st.Update(ctx, func(s *domain.StoreState) error {
		s.Accounts[acct1.Key] = acct1
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	res, err := Run(ctx, st, nil, nil, nil, RunOptions{
		Binary:    "agy",
		Args:      []string{"-p", "hi"},
		NoRefresh: true,
		Now:       func() time.Time { return now },
	})
	if !errors.Is(err, ErrNoReadyAccounts) {
		t.Fatalf("expected ErrNoReadyAccounts, got err=%v", err)
	}
	if res.Decision.Outcome != domain.OutcomeNoneReady {
		t.Fatalf("Decision = %+v, want OutcomeNoneReady", res.Decision)
	}
	if !strings.Contains(err.Error(), "2026-11-18T12:15:00Z") {
		t.Fatalf("error missing reset hint: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	return b
}

func TestRunInteractiveLiveQuotaSwitchTerminatesStuckTUIAndContinues(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 16, 40, 0, 0, time.UTC)

	liveBin := buildFakeAgyBinary(t, `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	acct := os.Getenv("MULTI_ANTI_ACCOUNT")
	if logFile := os.Getenv("FAKE_AGY_LOG"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(9)
		}
		_, _ = f.WriteString(acct + "|" + strings.Join(os.Args[1:], " ") + "\n")
		_ = f.Close()
	}

	switch os.Getenv("FAKE_AGY_LIVE_MODE") {
	case "stuck_on_alice":
		if acct == "alice@example.com" {
			runID := os.Getenv("MULTI_ANTI_RUN_ID")
			sigDir := filepath.Join(os.Getenv("MULTI_ANTI_HOME"), "signals")
			_ = os.MkdirAll(sigDir, 0o700)
			sig, _ := json.Marshal(map[string]any{
				"conversation_id": "ceb19e39-6c65-41c8-8dfb-61ad2951a142",
				"from_key":        "alice@example.com",
				"to_key":          "bob@example.com",
				"reason":          "switched from alice@example.com (health_cooldown) by highest_remaining",
				"at":              time.Now().UTC().Format(time.RFC3339),
			})
			if runID != "" {
				_ = os.WriteFile(filepath.Join(sigDir, "run-"+runID+".json"), sig, 0o600)
			}
			_ = os.WriteFile(filepath.Join(sigDir, "latest.json"), sig, 0o600)
			fmt.Fprintln(os.Stderr, "Individual quota reached. Resets in 3h58m27s.")
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			select {
			case <-sigCh:
				os.Exit(0)
			case <-time.After(30 * time.Second):
				os.Exit(42)
			}
		}
		fmt.Fprintln(os.Stdout, "continued on "+acct)
	case "ignore_foreign_latest":
		sigDir := filepath.Join(os.Getenv("MULTI_ANTI_HOME"), "signals")
		_ = os.MkdirAll(sigDir, 0o700)
		foreignSig, _ := json.Marshal(map[string]any{
			"conversation_id": "other-conv",
			"from_key":        "other@example.com",
			"to_key":          "bob@example.com",
			"reason":          "foreign terminal switch",
			"at":              time.Now().UTC().Format(time.RFC3339),
		})
		_ = os.WriteFile(filepath.Join(sigDir, "latest.json"), foreignSig, 0o600)
		time.Sleep(100 * time.Millisecond)
		fmt.Fprintln(os.Stdout, "finished cleanly on "+acct)
	}
}
`)

	t.Run("terminates stuck interactive agy on run signal and resumes with -i continue", func(t *testing.T) {
		_, paths, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		bob := makeLauncherAccount("bob@example.com", 0.70, "tok-bob", "ref-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "live.log")
		var stdout, stderr bytes.Buffer
		start := time.Now()
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:             liveBin,
			Args:               []string{"--conversation=ceb19e39-6c65-41c8-8dfb-61ad2951a142", "-i", "initial prompt", "--effort", "high"},
			NoRefresh:          true,
			AutoRelaunch:       true,
			MaxSwitches:        2,
			SignalPollInterval: 15 * time.Millisecond,
			SignalGraceDelay:   25 * time.Millisecond,
			Stdin:              strings.NewReader(""),
			Stdout:             &stdout,
			Stderr:             &stderr,
			ExtraEnv:           []string{"FAKE_AGY_LIVE_MODE=stuck_on_alice", "FAKE_AGY_LOG=" + logPath},
			Now:                func() time.Time { return now },
		})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if elapsed >= 3*time.Second {
			t.Fatalf("expected live signal watcher to restart stuck agy within <3s, took %v", elapsed)
		}
		if res.ExitCode != 0 || res.LastAccount != bob.Key || len(res.Switches) != 1 {
			t.Fatalf("unexpected RunResult: %+v (stderr=%s)", res, stderr.String())
		}
		if !strings.Contains(stdout.String(), "continued on bob@example.com") {
			t.Fatalf("stdout = %q", stdout.String())
		}

		lines := strings.Split(strings.TrimSpace(string(mustReadFile(t, logPath))), "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 invocations, got %d: %v", len(lines), lines)
		}
		if lines[1] != "bob@example.com|--conversation ceb19e39-6c65-41c8-8dfb-61ad2951a142 -i continue --effort high" {
			t.Fatalf("attempt 2 = %q", lines[1])
		}
		entries, err := os.ReadDir(paths.SignalsDir())
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "run-") {
					t.Fatalf("expected run signal cleared, found %s", e.Name())
				}
			}
		}
	})

	t.Run("ignores foreign terminal latest.json signal while interactive agy runs", func(t *testing.T) {
		_, _, st := setupLauncherEnv(t)
		alice := makeLauncherAccount("alice@example.com", 0.90, "tok-alice", "ref-alice", now.Add(time.Hour))
		bob := makeLauncherAccount("bob@example.com", 0.70, "tok-bob", "ref-bob", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.Accounts[alice.Key] = alice
			s.Accounts[bob.Key] = bob
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		logPath := filepath.Join(t.TempDir(), "isolated.log")
		var stdout, stderr bytes.Buffer
		res, err := Run(ctx, st, nil, nil, nil, RunOptions{
			Binary:             liveBin,
			Args:               []string{"--effort", "high"},
			NoRefresh:          true,
			AutoRelaunch:       true,
			MaxSwitches:        2,
			SignalPollInterval: 10 * time.Millisecond,
			SignalGraceDelay:   10 * time.Millisecond,
			Stdin:              strings.NewReader(""),
			Stdout:             &stdout,
			Stderr:             &stderr,
			ExtraEnv:           []string{"FAKE_AGY_LIVE_MODE=ignore_foreign_latest", "FAKE_AGY_LOG=" + logPath},
			Now:                func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if res.ExitCode != 0 || res.LastAccount != alice.Key || len(res.Switches) != 0 {
			t.Fatalf("unexpected RunResult on foreign signal: %+v", res)
		}
	})
}
