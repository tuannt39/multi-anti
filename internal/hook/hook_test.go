package hook

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/store"
)

type stubOAuthClient struct {
	refreshFn func(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error)
}

func (s *stubOAuthClient) Login(context.Context, oauth.LoginOptions) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("unexpected Login call")
}

func (s *stubOAuthClient) Refresh(ctx context.Context, creds domain.AccountCredentials, skew time.Duration, now time.Time) (domain.AccountCredentials, bool, error) {
	if s.refreshFn != nil {
		return s.refreshFn(ctx, creds, skew, now)
	}
	return creds, false, nil
}

func (s *stubOAuthClient) ImportNativeToken(context.Context, string) (domain.AccountIdentity, domain.AccountCredentials, error) {
	return domain.AccountIdentity{}, domain.AccountCredentials{}, errors.New("unexpected ImportNativeToken call")
}

func setupIsolatedHookEnv(t *testing.T) (platform.Paths, *store.FileStore) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("MULTI_ANTI_HOME", filepath.Join(tmp, "data"))
	t.Setenv("MULTI_ANTI_AGY_HOME", filepath.Join(tmp, "agy-home"))
	t.Setenv("MULTI_ANTI_ACCOUNT", "")
	t.Setenv("MULTI_ANTI_ISOLATED", "")

	paths, err := platform.ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths() error = %v", err)
	}
	return paths, store.NewFileStore(paths)
}

func makeHookAccount(email string, rem float64, accessTok, refreshTok string, expiry time.Time) domain.Account {
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
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt:    expiry.Add(-10 * time.Minute),
			Source:       domain.QuotaSourceSummary,
			EndpointHost: "cloudcode-pa.googleapis.com",
			Tier:         domain.TierPro,
			ProjectID:    "proj-" + email,
			Credits: []domain.CreditInfo{
				{Provider: "GOOGLE_ONE_AI", Remaining: 100},
			},
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

func writeNativeToken(t *testing.T, paths platform.Paths, acc domain.Account) {
	t.Helper()
	raw, err := oauth.EncodeAgyTokenFile(acc.Email, acc.Creds)
	if err != nil {
		t.Fatalf("EncodeAgyTokenFile() error = %v", err)
	}
	if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), raw, true); err != nil {
		t.Fatalf("WriteFileAtomic(NativeAgyTokenPath) error = %v", err)
	}
}

func TestHandleSessionStart(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	t.Run("unconfigured store returns empty JSON object", func(t *testing.T) {
		_, st := setupIsolatedHookEnv(t)
		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})

		out, err := h.HandleSessionStart(ctx, []byte(`{"conversationId":"c1"}`))
		if err != nil {
			t.Fatalf("HandleSessionStart() error = %v", err)
		}
		if strings.TrimSpace(string(out)) != `{}` {
			t.Fatalf("output = %s, want {}", out)
		}
	})

	t.Run("configured store emits user_markdown with empty systemMessage and no secrets", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.72, "secret-alice-access", "secret-alice-refresh", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "secret-bob-access", "secret-bob-refresh", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err := h.HandleSessionStart(ctx, []byte(`{"conversationId":"c1","modelName":"gemini-2.5-pro"}`))
		if err != nil {
			t.Fatalf("HandleSessionStart() error = %v", err)
		}

		var parsed SessionStartOutput
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("json.Unmarshal() error = %v; raw=%s", err, out)
		}
		if len(parsed.InjectSteps) != 1 || parsed.InjectSteps[0].SystemMessage == nil {
			t.Fatalf("unexpected injectSteps: %+v", parsed.InjectSteps)
		}
		sm := parsed.InjectSteps[0].SystemMessage
		if sm.SystemMessage != "" {
			t.Fatalf("systemMessage = %q, want empty string", sm.SystemMessage)
		}
		md, _ := sm.Metadata["user_markdown"].(string)
		if !strings.Contains(md, "alice@example.com") || !strings.Contains(md, "72%") || !strings.Contains(md, "2/2") {
			t.Fatalf("unexpected user_markdown: %q", md)
		}
		if strings.Contains(string(out), "secret-") {
			t.Fatalf("output leaked token secret: %s", out)
		}
	})

	t.Run("malformed stdin degrades gracefully", func(t *testing.T) {
		_, st := setupIsolatedHookEnv(t)
		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err := h.HandleSessionStart(ctx, []byte(`{not-json`))
		if err != nil {
			t.Fatalf("HandleSessionStart() error = %v", err)
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON output: %s", out)
		}
	})

	t.Run("syncs fresher native token and records LastUsedAt and ActiveKey", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.60, "old-a", "ref-a", now.Add(5*time.Minute))
		b := makeHookAccount("bob@example.com", 0.90, "old-b", "ref-b", now.Add(5*time.Minute))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		fresherB := makeHookAccount("bob@example.com", 0.90, "native-fresher-b", "ref-b", now.Add(55*time.Minute))
		writeNativeToken(t, paths, fresherB)

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err := h.HandleSessionStart(ctx, []byte(`{"conversationId":"c-sync"}`))
		if err != nil {
			t.Fatalf("HandleSessionStart() error = %v", err)
		}
		if !strings.Contains(string(out), "bob@example.com") {
			t.Fatalf("expected active bob in session-start output: %s", out)
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stAfter.ActiveKey != b.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, b.Key)
		}
		bobAfter := stAfter.Accounts[b.Key]
		if bobAfter.Creds.AccessToken != "native-fresher-b" {
			t.Fatalf("bob AccessToken = %q, want native-fresher-b", bobAfter.Creds.AccessToken)
		}
		if bobAfter.LastUsedAt == nil || !bobAfter.LastUsedAt.Equal(now) {
			t.Fatalf("bob LastUsedAt = %v, want %v", bobAfter.LastUsedAt, now)
		}
	})
}

func TestHandleStop(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	t.Run("quota exhausted in error cools down active account, refreshes and stages next, writes signal", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.50, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "stale-b", "ref-b", now.Add(-time.Minute))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		oa := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, ts time.Time) (domain.AccountCredentials, bool, error) {
				if creds.RefreshToken != "ref-b" {
					return creds, false, errors.New("unexpected refresh token")
				}
				creds.AccessToken = "fresh-tok-b"
				creds.Expiry = ts.Add(time.Hour)
				return creds, true, nil
			},
		}

		h := NewHandler(HandlerConfig{Store: st, OAuth: oa, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-123",
			ModelName:         "gemini-2.5-pro",
			TerminationReason: "ERROR",
			Error:             `429 RESOURCE_EXHAUSTED: retryDelay: "90s"`,
		})

		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		if err := json.Unmarshal(out, &stopOut); err != nil {
			t.Fatalf("Unmarshal StopOutput error = %v", err)
		}
		if stopOut.Decision != "allow" || !strings.Contains(stopOut.Reason, "bob@example.com") {
			t.Fatalf("unexpected StopOutput: %+v", stopOut)
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stAfter.NativeBackup == nil || !stAfter.NativeBackup.HadFile {
			t.Fatalf("NativeBackup not captured: %+v", stAfter.NativeBackup)
		}
		if stAfter.ActiveKey != b.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, b.Key)
		}
		aliceAfter := stAfter.Accounts[a.Key]
		if aliceAfter.Health.Status != domain.HealthCooldown || aliceAfter.Health.CooldownUntil == nil || !aliceAfter.Health.CooldownUntil.Equal(now.Add(90*time.Second)) {
			t.Fatalf("alice health = %+v, want cooldown until +90s", aliceAfter.Health)
		}
		if aliceAfter.LastUsedAt == nil || !aliceAfter.LastUsedAt.Equal(now) {
			t.Fatalf("alice LastUsedAt = %v, want %v", aliceAfter.LastUsedAt, now)
		}
		if bobAfter := stAfter.Accounts[b.Key]; bobAfter.LastUsedAt == nil || !bobAfter.LastUsedAt.Equal(now) {
			t.Fatalf("bob LastUsedAt = %v, want %v", bobAfter.LastUsedAt, now)
		}
		if stAfter.LastSwitch == nil || stAfter.LastSwitch.Trigger != "hook_stop" || stAfter.LastSwitch.ToKey != b.Key {
			t.Fatalf("LastSwitch = %+v", stAfter.LastSwitch)
		}

		stagedRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
		if err != nil {
			t.Fatalf("ReadFile(NativeAgyTokenPath) error = %v", err)
		}
		stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedRaw)
		if err != nil {
			t.Fatalf("DecodeAgyTokenFile() error = %v", err)
		}
		if stagedID.Key != b.Key || stagedCreds.AccessToken != "fresh-tok-b" {
			t.Fatalf("staged token mismatch: id=%+v creds=%+v", stagedID, stagedCreds)
		}

		sig, ok, err := ReadLatestSwitchSignal(paths)
		if err != nil || !ok {
			t.Fatalf("ReadLatestSwitchSignal() = (%+v, %v, %v)", sig, ok, err)
		}
		if sig.ConversationID != "conv-123" || sig.FromKey != a.Key || sig.ToKey != b.Key {
			t.Fatalf("latest signal = %+v", sig)
		}
		scopedSig, ok, err := ReadSwitchSignal(paths, "conv-123")
		if err != nil || !ok || scopedSig.ToKey != b.Key {
			t.Fatalf("ReadSwitchSignal() = (%+v, %v, %v)", scopedSig, ok, err)
		}
	})

	t.Run("preserves fresher native token from failing account before overwriting", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.50, "old-a", "ref-a", now.Add(5*time.Minute))
		b := makeHookAccount("bob@example.com", 0.90, "tok-b", "ref-b", now.Add(time.Hour))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		fresherA := makeHookAccount("alice@example.com", 0.50, "refreshed-by-agy-a", "ref-a", now.Add(55*time.Minute))
		writeNativeToken(t, paths, fresherA)

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-sync",
			ModelName:         "gemini-2.5-pro",
			TerminationReason: "ERROR",
			Error:             "429 RESOURCE_EXHAUSTED",
		})
		if _, err := h.HandleStop(ctx, stdin); err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stAfter.Accounts[a.Key].Creds.AccessToken != "refreshed-by-agy-a" {
			t.Fatalf("alice fresher token was lost before switch: %+v", stAfter.Accounts[a.Key].Creds)
		}
		if stAfter.ActiveKey != b.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, b.Key)
		}
	})

	t.Run("detects quota exhaustion in last 16KB of transcriptPath", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.40, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.85, "tok-b", "ref-b", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		transcriptPath := filepath.Join(t.TempDir(), "transcript.jsonl")
		padding := strings.Repeat(`{"type":"STEP","content":"normal log line"}`+"\n", 600)
		tailLine := `{"type":"ERROR","content":"Usage limit reached, resets in 10 minutes"}` + "\n"
		if err := os.WriteFile(transcriptPath, []byte(padding+tailLine), 0o600); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-tail",
			TranscriptPath:    transcriptPath,
			TerminationReason: "ERROR",
		})
		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		_ = json.Unmarshal(out, &stopOut)
		if stopOut.Decision != "allow" || !strings.Contains(stopOut.Reason, "bob@example.com") {
			t.Fatalf("unexpected StopOutput: %+v", stopOut)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.ActiveKey != b.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, b.Key)
		}
		if until := stAfter.Accounts[a.Key].Health.CooldownUntil; until == nil || !until.Equal(now.Add(10*time.Minute)) {
			t.Fatalf("CooldownUntil = %v, want +10m", until)
		}
		if !strings.Contains(stAfter.Accounts[a.Key].Health.Reason, "Usage limit reached") {
			t.Fatalf("cooldown reason should capture tail error, got %q", stAfter.Accounts[a.Key].Health.Reason)
		}
	})

	t.Run("ignores older non-error transcript lines containing quota keywords", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.50, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "tok-b", "ref-b", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		transcriptPath := filepath.Join(t.TempDir(), "transcript.jsonl")
		lines := strings.Join([]string{
			`{"type":"GENERIC","status":"DONE","content":"read_file selector.go: RESOURCE_EXHAUSTED 429"}`,
			`{"type":"GENERIC","status":"DONE","content":"normal step"}`,
			`{"type":"GENERIC","status":"ERROR","error":"exit status 1: compile failed"}`,
		}, "\n") + "\n"
		if err := os.WriteFile(transcriptPath, []byte(lines), 0o600); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-false-pos",
			TranscriptPath:    transcriptPath,
			TerminationReason: "ERROR",
			Error:             "exit status 1: compile failed",
		})
		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		_ = json.Unmarshal(out, &stopOut)
		if stopOut.Decision != "allow" || stopOut.Reason != "" {
			t.Fatalf("unexpected StopOutput on non-quota error: %+v", stopOut)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.ActiveKey != a.Key || stAfter.Accounts[a.Key].Health.Status != domain.HealthReady {
			t.Fatalf("account should remain active and ready, got active=%q health=%+v", stAfter.ActiveKey, stAfter.Accounts[a.Key].Health)
		}
	})

	t.Run("non-quota error does not switch or cool down", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.50, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "tok-b", "ref-b", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-err",
			TerminationReason: "ERROR",
			Error:             "exit status 1: build failed",
		})
		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		_ = json.Unmarshal(out, &stopOut)
		if stopOut.Decision != "allow" || stopOut.Reason != "" {
			t.Fatalf("unexpected StopOutput: %+v", stopOut)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.ActiveKey != a.Key || stAfter.Accounts[a.Key].Health.Status != domain.HealthReady {
			t.Fatalf("unexpected state change on non-quota error: %+v", stAfter)
		}
	})

	t.Run("already switched idempotency prevents cooling down newly staged account", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.50, "tok-a", "ref-a", now.Add(time.Hour))
		a.Health = domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: ptrTime(now.Add(5 * time.Minute))}
		b := makeHookAccount("bob@example.com", 0.90, "tok-b", "ref-b", now.Add(time.Hour))
		writeNativeToken(t, paths, b)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-dup",
			TerminationReason: "ERROR",
			Error:             "429 RESOURCE_EXHAUSTED",
		})
		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		_ = json.Unmarshal(out, &stopOut)
		if stopOut.Decision != "allow" || !strings.Contains(stopOut.Reason, "already switched") {
			t.Fatalf("unexpected StopOutput: %+v", stopOut)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.Accounts[b.Key].Health.Status != domain.HealthReady {
			t.Fatalf("bob should remain HealthReady, got %+v", stAfter.Accounts[b.Key].Health)
		}

		t.Setenv("MULTI_ANTI_ACCOUNT", string(a.Key))
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = b.Key
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := h.HandleStop(ctx, stdin); err != nil {
			t.Fatalf("second HandleStop() error = %v", err)
		}
		stAfter2, _ := st.Load(ctx)
		if stAfter2.Accounts[b.Key].Health.Status != domain.HealthReady {
			t.Fatalf("bob wrongly cooled down on second Stop hook: %+v", stAfter2.Accounts[b.Key].Health)
		}
	})

	t.Run("revoked next candidate transitions to needs_reauth and falls back to third account", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.30, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.95, "stale-b", "revoked-b", now.Add(-time.Minute))
		c := makeHookAccount("carol@example.com", 0.75, "tok-c", "ref-c", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			s.Accounts[c.Key] = c
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		oa := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, _ time.Time) (domain.AccountCredentials, bool, error) {
				if creds.RefreshToken == "revoked-b" {
					return creds, false, oauth.ErrRefreshRevoked
				}
				return creds, false, nil
			},
		}
		h := NewHandler(HandlerConfig{Store: st, OAuth: oa, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-revoked",
			TerminationReason: "ERROR",
			Error:             "429 RESOURCE_EXHAUSTED",
		})
		if _, err := h.HandleStop(ctx, stdin); err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}

		stAfter, _ := st.Load(ctx)
		if stAfter.Accounts[b.Key].Health.Status != domain.HealthNeedsReauth {
			t.Fatalf("bob health = %+v, want needs_reauth", stAfter.Accounts[b.Key].Health)
		}
		if stAfter.ActiveKey != c.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, c.Key)
		}
	})

	t.Run("stages target with RefreshToken and empty AccessToken when Refresh returns ErrMissingClientID", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.30, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "", "ref-b-only", time.Time{})
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		oa := &stubOAuthClient{
			refreshFn: func(_ context.Context, creds domain.AccountCredentials, _ time.Duration, _ time.Time) (domain.AccountCredentials, bool, error) {
				return creds, false, oauth.ErrMissingClientID
			},
		}
		h := NewHandler(HandlerConfig{Store: st, OAuth: oa, Now: func() time.Time { return now }})
		stdin, _ := json.Marshal(HookInput{
			ConversationID:    "conv-missing-cid",
			ModelName:         "gemini-2.5-pro",
			TerminationReason: "ERROR",
			Error:             `429 RESOURCE_EXHAUSTED: retryDelay: "60s"`,
		})

		out, err := h.HandleStop(ctx, stdin)
		if err != nil {
			t.Fatalf("HandleStop() error = %v", err)
		}
		var stopOut StopOutput
		if err := json.Unmarshal(out, &stopOut); err != nil {
			t.Fatalf("Unmarshal StopOutput error = %v", err)
		}
		if stopOut.Decision != "allow" || !strings.Contains(stopOut.Reason, "bob@example.com") {
			t.Fatalf("unexpected StopOutput: %+v", stopOut)
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stAfter.ActiveKey != b.Key {
			t.Fatalf("ActiveKey = %q, want %q", stAfter.ActiveKey, b.Key)
		}
		if stAfter.Accounts[b.Key].Health.Status != domain.HealthReady {
			t.Fatalf("bob health = %+v, want HealthReady", stAfter.Accounts[b.Key].Health)
		}

		stagedRaw, err := os.ReadFile(paths.NativeAgyTokenPath())
		if err != nil {
			t.Fatalf("ReadFile(NativeAgyTokenPath) error = %v", err)
		}
		stagedID, stagedCreds, err := oauth.DecodeAgyTokenFile(stagedRaw)
		if err != nil {
			t.Fatalf("DecodeAgyTokenFile() error = %v", err)
		}
		if stagedID.Key != b.Key || stagedCreds.AccessToken != "" || stagedCreds.RefreshToken != "ref-b-only" {
			t.Fatalf("staged token mismatch: id=%+v creds=%+v", stagedID, stagedCreds)
		}
	})
}

func TestHandleStatusLine(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	t.Run("renders active + next and updates cached fractions without clobbering metadata", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		a := makeHookAccount("alice@example.com", 0.80, "tok-a", "ref-a", now.Add(time.Hour))
		b := makeHookAccount("bob@example.com", 0.90, "tok-b", "ref-b", now.Add(time.Hour))
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		stdin := `{
			"email": "alice@example.com",
			"plan_tier": "g1-pro-tier",
			"quota": {
				"gemini-5h": {"remaining_fraction": 0.42, "reset_in_seconds": 3600}
			},
			"model": {"id": "gemini-2.5-pro"}
		}`

		line, err := h.HandleStatusLine(ctx, []byte(stdin))
		if err != nil {
			t.Fatalf("HandleStatusLine() error = %v", err)
		}
		if strings.Contains(line, "\r") {
			t.Fatalf("status line must not contain carriage returns, got %q", line)
		}
		lines := strings.Split(line, "\n")
		if len(lines) != 3 {
			t.Fatalf("expected 3 status lines (header + 2 accounts), got %d:\n%s", len(lines), line)
		}
		for _, wantCol := range []string{"multi-anti", "GEMINI 5h/wk", "CLAUDE/GPT 5h/wk", "ARGON wk", "STATUS"} {
			if !strings.Contains(lines[0], wantCol) {
				t.Fatalf("header missing %q in %q", wantCol, lines[0])
			}
		}
		if !strings.HasPrefix(lines[1], "* alice@example.com") || !strings.Contains(lines[1], "42%/-") || !strings.HasSuffix(lines[1], "active") {
			t.Fatalf("unexpected row 1: %q", lines[1])
		}
		if !strings.HasPrefix(lines[2], "> bob@example.com") || !strings.Contains(lines[2], "90%/-") || !strings.HasSuffix(lines[2], "next") {
			t.Fatalf("unexpected row 2: %q", lines[2])
		}

		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		aliceQ := stAfter.Accounts[a.Key].Quota
		if aliceQ.Tier != domain.TierPro || aliceQ.EndpointHost != "cloudcode-pa.googleapis.com" || len(aliceQ.Credits) != 1 || aliceQ.ProjectID != "proj-alice@example.com" {
			t.Fatalf("metadata clobbered: %+v", aliceQ)
		}
		if aliceQ.Buckets[0].RemainingFraction != 0.42 {
			t.Fatalf("bucket remaining = %v, want 0.42", aliceQ.Buckets[0].RemainingFraction)
		}
		if aliceQ.Buckets[0].ResetAt == nil || !aliceQ.Buckets[0].ResetAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("bucket ResetAt = %v, want %v", aliceQ.Buckets[0].ResetAt, now.Add(time.Hour))
		}
	})

	t.Run("degrades gracefully on malformed JSON and empty store", func(t *testing.T) {
		_, st := setupIsolatedHookEnv(t)
		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})

		line, err := h.HandleStatusLine(ctx, []byte(`{bad json`))
		if err != nil {
			t.Fatalf("HandleStatusLine() error = %v", err)
		}
		if line != "[multi-anti: unconfigured]" {
			t.Fatalf("line = %q, want [multi-anti: unconfigured]", line)
		}
	})

	t.Run("handles account with nil quota without panicking", func(t *testing.T) {
		_, st := setupIsolatedHookEnv(t)
		a := domain.Account{
			Key:    "alice@example.com",
			Email:  "alice@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady},
		}
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		line, err := h.HandleStatusLine(ctx, []byte(`{"email":"alice@example.com"}`))
		if err != nil {
			t.Fatalf("HandleStatusLine() error = %v", err)
		}
		if line != "[multi-anti: alice@example.com]" {
			t.Fatalf("line = %q", line)
		}
	})

	t.Run("renders compact multi-line table with all accounts and full pool quotas", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		reset3P := now.Add(158*time.Hour + 13*time.Minute)
		resetCarol5h := now.Add(3*time.Hour + 36*time.Minute)
		resetCarol3P := now.Add(157*time.Hour + 2*time.Minute)

		a := domain.Account{
			Key:    "alice@example.com",
			Email:  "alice@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady},
			Creds:  domain.AccountCredentials{RefreshToken: "ref-a", Expiry: now.Add(time.Hour)},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.199},
					{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.6155},
					{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0, ResetAt: &reset3P},
					{GroupID: "gemini-argon-wtu-weekly", Pool: domain.PoolGeminiArgon, Window: domain.WindowWeekly, RemainingFraction: 1},
				},
			},
		}
		b := domain.Account{
			Key:    "bob@example.com",
			Email:  "bob@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady},
			Creds:  domain.AccountCredentials{RefreshToken: "ref-b", Expiry: now.Add(time.Hour)},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 1},
					{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.4181},
					{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1},
					{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.4922},
					{GroupID: "gemini-argon-wtu-weekly", Pool: domain.PoolGeminiArgon, Window: domain.WindowWeekly, RemainingFraction: 0.2578},
				},
			},
		}
		c := domain.Account{
			Key:   "carol@example.com",
			Email: "carol@example.com",
			Health: domain.AccountHealth{
				Status:        domain.HealthCooldown,
				CooldownUntil: &resetCarol5h,
			},
			Creds: domain.AccountCredentials{RefreshToken: "ref-c", Expiry: now.Add(time.Hour)},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0, ResetAt: &resetCarol5h},
					{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.5557},
					{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0, ResetAt: &resetCarol3P},
					{GroupID: "gemini-argon-wtu-weekly", Pool: domain.PoolGeminiArgon, Window: domain.WindowWeekly, RemainingFraction: 1},
				},
			},
		}
		d := domain.Account{
			Key:    "dave@example.com",
			Email:  "dave@example.com",
			Health: domain.AccountHealth{Status: domain.HealthDisabled},
			Creds:  domain.AccountCredentials{RefreshToken: "ref-d", Expiry: now.Add(time.Hour)},
		}
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			s.Accounts[b.Key] = b
			s.Accounts[c.Key] = c
			s.Accounts[d.Key] = d
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err := h.HandleStatusLine(ctx, []byte(`{"email":"alice@example.com"}`))
		if err != nil {
			t.Fatalf("HandleStatusLine() error = %v", err)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 5 {
			t.Fatalf("expected 5 lines (header + 4 accounts), got %d:\n%s", len(lines), out)
		}
		for i, ln := range lines {
			if len(ln) >= 100 {
				t.Fatalf("line %d too wide (%d chars >= 100): %q", i, len(ln), ln)
			}
		}
		for _, wantCol := range []string{"multi-anti", "GEMINI 5h/wk", "CLAUDE/GPT 5h/wk", "ARGON wk", "STATUS"} {
			if !strings.Contains(lines[0], wantCol) {
				t.Fatalf("header missing %q in %q", wantCol, lines[0])
			}
		}
		if !strings.HasPrefix(lines[1], "* alice@example.com") || !strings.Contains(lines[1], "20%/62%") || !strings.Contains(lines[1], "-/0%(158h)") || !strings.Contains(lines[1], "100%") || !strings.HasSuffix(lines[1], "active") {
			t.Fatalf("unexpected active row: %q", lines[1])
		}
		if !strings.HasPrefix(lines[2], "> bob@example.com") || !strings.Contains(lines[2], "100%/42%") || !strings.Contains(lines[2], "100%/49%") || !strings.Contains(lines[2], "26%") || !strings.HasSuffix(lines[2], "next") {
			t.Fatalf("unexpected next row: %q", lines[2])
		}
		if !strings.HasPrefix(lines[3], "  carol@example.com") || !strings.Contains(lines[3], "0%(3h36m)/56%") || !strings.Contains(lines[3], "-/0%(157h)") || !strings.Contains(lines[3], "100%") || !strings.HasSuffix(lines[3], "cooldown 3h36m") {
			t.Fatalf("unexpected cooldown row: %q", lines[3])
		}
		if !strings.HasPrefix(lines[4], "  dave@example.com") || !strings.Contains(lines[4], "  -  ") || !strings.HasSuffix(lines[4], "disabled") {
			t.Fatalf("unexpected disabled row: %q", lines[4])
		}
	})

	t.Run("windowless statusline key preserves distinct 5h and weekly buckets", func(t *testing.T) {
		paths, st := setupIsolatedHookEnv(t)
		reset5h := now.Add(4 * time.Hour)
		resetWk := now.Add(140 * time.Hour)

		a := domain.Account{
			Key:    "alice@example.com",
			Email:  "alice@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady},
			Creds:  domain.AccountCredentials{RefreshToken: "ref-a", Expiry: now.Add(time.Hour)},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceSummary,
				Tier:      domain.TierPro,
				Buckets: []domain.QuotaBucket{
					{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.20, ResetAt: &reset5h},
					{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.80, ResetAt: &resetWk},
				},
			},
		}
		writeNativeToken(t, paths, a)

		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err := h.HandleStatusLine(ctx, []byte(`{"email":"alice@example.com","quota":{"gemini":{"remaining_fraction":0.65,"reset_in_seconds":504000}}}`))
		if err != nil {
			t.Fatalf("HandleStatusLine(matching reset) error = %v", err)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[1], "* alice@example.com") || !strings.Contains(lines[1], "20%/65%") {
			t.Fatalf("unexpected status table after matching reset:\n%s", out)
		}
		stAfter, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		buckets := stAfter.Accounts[a.Key].Quota.Buckets
		if buckets[0].RemainingFraction != 0.20 || buckets[1].RemainingFraction != 0.65 {
			t.Fatalf("unexpected buckets after matching reset: %+v", buckets)
		}

		out, err = h.HandleStatusLine(ctx, []byte(`{"email":"alice@example.com","quota":{"gemini":{"remaining_fraction":0.10}}}`))
		if err != nil {
			t.Fatalf("HandleStatusLine(no reset) error = %v", err)
		}
		lines = strings.Split(out, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[1], "* alice@example.com") || !strings.Contains(lines[1], "20%/65%") {
			t.Fatalf("unexpected status table after windowless key without reset:\n%s", out)
		}
		stAfter2, err := st.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		buckets2 := stAfter2.Accounts[a.Key].Quota.Buckets
		if buckets2[0].RemainingFraction != 0.20 || buckets2[1].RemainingFraction != 0.65 {
			t.Fatalf("windowless key clobbered buckets: %+v", buckets2)
		}
	})

	t.Run("renders models-only fallback and store-less multi-bucket input", func(t *testing.T) {
		nilStoreHandler := NewHandler(HandlerConfig{Now: func() time.Time { return now }})
		out, err := nilStoreHandler.HandleStatusLine(ctx, []byte(`{"email":"guest@example.com","quota":{"gemini-5h":{"remaining_fraction":0.42},"gemini-weekly":{"remaining_fraction":0.80},"3p-weekly":{"remaining_fraction":0.50}}}`))
		if err != nil {
			t.Fatalf("HandleStatusLine(nil store) error = %v", err)
		}
		lines := strings.Split(out, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[1], "* guest@example.com") || !strings.Contains(lines[1], "42%/80%") || !strings.Contains(lines[1], "-/50%") || !strings.Contains(lines[1], "  -  ") || !strings.HasSuffix(lines[1], "active") {
			t.Fatalf("unexpected nil-store status table:\n%s", out)
		}

		_, st := setupIsolatedHookEnv(t)
		a := domain.Account{
			Key:    "alice@example.com",
			Email:  "alice@example.com",
			Health: domain.AccountHealth{Status: domain.HealthReady},
			Quota: &domain.QuotaSnapshot{
				FetchedAt: now,
				Source:    domain.QuotaSourceModels,
				Tier:      domain.TierPro,
				Models: []domain.ModelQuota{
					{ModelID: "gemini-2.5-pro", RemainingFraction: 0.75},
					{ModelID: "claude-sonnet-4-5", RemainingFraction: 0.40},
				},
			},
		}
		if _, err := st.Update(ctx, func(s *domain.StoreState) error {
			s.ActiveKey = a.Key
			s.Accounts[a.Key] = a
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		h := NewHandler(HandlerConfig{Store: st, Now: func() time.Time { return now }})
		out, err = h.HandleStatusLine(ctx, []byte(`{"email":"alice@example.com"}`))
		if err != nil {
			t.Fatalf("HandleStatusLine(models-only) error = %v", err)
		}
		lines = strings.Split(out, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[1], "* alice@example.com") || !strings.Contains(lines[1], "75%") || !strings.Contains(lines[1], "40%") || !strings.Contains(lines[1], "  -  ") || !strings.HasSuffix(lines[1], "active") {
			t.Fatalf("unexpected models-only status table:\n%s", out)
		}
	})
}

func TestInstallerPluginAndStatusLine(t *testing.T) {
	ctx := context.Background()

	t.Run("installs plugin, quotes binary command, enables disabled config entry, and uninstalls cleanly", func(t *testing.T) {
		paths, _ := setupIsolatedHookEnv(t)
		cfgPath := filepath.Join(paths.NativeGeminiConfigDir(), "config.json")
		initialCfg := `{
  "theme": "solarized",
  "plugins": {
    "other-plugin": {"enabled": false},
    "multi-anti": {"enabled": false, "pinned": true}
  }
}`
		if err := platform.WriteFileAtomic(cfgPath, []byte(initialCfg), false); err != nil {
			t.Fatal(err)
		}

		binWithSpace := filepath.Join(t.TempDir(), "my bin", "multi-anti")
		if err := InstallPlugin(ctx, paths, InstallOptions{BinaryCommand: binWithSpace}); err != nil {
			t.Fatalf("InstallPlugin() error = %v", err)
		}

		st, err := InspectPlugin(paths)
		if err != nil {
			t.Fatalf("InspectPlugin() error = %v", err)
		}
		if !st.Installed || st.DisabledInConfig {
			t.Fatalf("unexpected PluginStatus: %+v", st)
		}

		hooksRaw, err := os.ReadFile(filepath.Join(paths.NativePluginDir(), "hooks.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(hooksRaw), "hook session-start") || !strings.Contains(string(hooksRaw), binWithSpace) {
			t.Fatalf("unexpected hooks.json: %s", hooksRaw)
		}

		cfgRaw, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg["theme"] != "solarized" {
			t.Fatalf("unrelated theme key lost: %v", cfg)
		}
		plugins := cfg["plugins"].(map[string]any)
		if plugins["other-plugin"].(map[string]any)["enabled"] != false {
			t.Fatalf("other-plugin modified: %v", plugins)
		}
		ma := plugins["multi-anti"].(map[string]any)
		if ma["enabled"] != true || ma["pinned"] != true {
			t.Fatalf("multi-anti entry unexpected: %v", ma)
		}

		if agyBin, lookErr := exec.LookPath("agy"); lookErr == nil {
			cmd := exec.Command(agyBin, "plugin", "validate", "--strict", "--json", paths.NativePluginDir())
			out, valErr := cmd.CombinedOutput()
			if valErr != nil {
				t.Fatalf("agy plugin validate --strict --json failed: %v\noutput: %s", valErr, out)
			}
			var report struct {
				Findings []any `json:"findings"`
			}
			if err := json.Unmarshal(out, &report); err != nil {
				t.Fatalf("parse agy validate output error = %v\nraw=%s", err, out)
			}
			if len(report.Findings) != 0 {
				t.Fatalf("expected 0 findings from agy validate, got %s", out)
			}
		}

		if err := UninstallPlugin(paths); err != nil {
			t.Fatalf("UninstallPlugin() error = %v", err)
		}
		if _, err := os.Stat(paths.NativePluginDir()); !os.IsNotExist(err) {
			t.Fatalf("plugin dir still exists after uninstall")
		}
	})

	t.Run("installs and restores prior statusLine while preserving unrelated settings", func(t *testing.T) {
		paths, _ := setupIsolatedHookEnv(t)
		initialSettings := `{
  "model": "gemini-2.5-pro",
  "statusLine": {
    "type": "command",
    "command": "custom-statusline --json",
    "stack_with_default": false
  }
}`
		if err := platform.WriteFileAtomic(paths.NativeAgySettingsPath(), []byte(initialSettings), false); err != nil {
			t.Fatal(err)
		}

		if err := InstallStatusLine(paths, "/opt/bin/multi-anti"); err != nil {
			t.Fatalf("InstallStatusLine() error = %v", err)
		}
		if err := InstallStatusLine(paths, "/opt/bin/multi-anti"); err != nil {
			t.Fatalf("second InstallStatusLine() error = %v", err)
		}

		st, err := InspectPlugin(paths)
		if err != nil {
			t.Fatal(err)
		}
		if !st.StatusLineEnabled || st.StatusLineCommand != "/opt/bin/multi-anti statusline" {
			t.Fatalf("unexpected statusLine status: %+v", st)
		}

		if err := UninstallStatusLine(paths); err != nil {
			t.Fatalf("UninstallStatusLine() error = %v", err)
		}

		restoredRaw, err := os.ReadFile(paths.NativeAgySettingsPath())
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(restoredRaw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["model"] != "gemini-2.5-pro" {
			t.Fatalf("unrelated setting lost: %v", doc)
		}
		sl := doc["statusLine"].(map[string]any)
		if sl["command"] != "custom-statusline --json" || sl["stack_with_default"] != false {
			t.Fatalf("original statusLine not restored: %v", sl)
		}
	})

	t.Run("quotes commands safely for both Unix and Windows", func(t *testing.T) {
		if got := quoteCommandForOS("linux", "/tmp/my dir/multi-anti", "hook stop"); got != "'/tmp/my dir/multi-anti' hook stop" {
			t.Fatalf("linux quote = %q", got)
		}
		if got := quoteCommandForOS("windows", `C:\Program Files\multi-anti.exe`, "statusline"); got != `"C:\Program Files\multi-anti.exe" statusline` {
			t.Fatalf("windows quote = %q", got)
		}
	})
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
