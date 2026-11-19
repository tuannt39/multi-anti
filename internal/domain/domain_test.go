package domain

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeAccountKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		email     string
		accountID string
		want      AccountKey
		wantErr   error
	}{
		{
			name:      "normalizes email lowercase and trims whitespace",
			email:     "  Alice.Smith@Example.COM \t",
			accountID: "12345",
			want:      AccountKey("alice.smith@example.com"),
		},
		{
			name:      "falls back to id prefix when email empty",
			email:     "   ",
			accountID: "  sub-98765  ",
			want:      AccountKey("id:sub-98765"),
		},
		{
			name:      "returns ErrMissingIdentity when both missing",
			email:     " \n ",
			accountID: "",
			wantErr:   ErrMissingIdentity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeAccountKey(tc.email, tc.accountID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NormalizeAccountKey(%q, %q) err = %v, want %v", tc.email, tc.accountID, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("NormalizeAccountKey(%q, %q) = %q, want %q", tc.email, tc.accountID, got, tc.want)
			}
		})
	}
}

func TestAccountHealthEffectiveStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	future := now.Add(5 * time.Minute)
	past := now.Add(-1 * time.Second)
	exact := now

	tests := []struct {
		name       string
		health     AccountHealth
		wantStatus HealthStatus
		wantSelect bool
	}{
		{
			name:       "ready is selectable",
			health:     AccountHealth{Status: HealthReady},
			wantStatus: HealthReady,
			wantSelect: true,
		},
		{
			name:       "active cooldown stays cooldown",
			health:     AccountHealth{Status: HealthCooldown, CooldownUntil: &future},
			wantStatus: HealthCooldown,
			wantSelect: false,
		},
		{
			name:       "expired cooldown promotes to ready",
			health:     AccountHealth{Status: HealthCooldown, CooldownUntil: &past},
			wantStatus: HealthReady,
			wantSelect: true,
		},
		{
			name:       "cooldown ending exactly at now promotes to ready",
			health:     AccountHealth{Status: HealthCooldown, CooldownUntil: &exact},
			wantStatus: HealthReady,
			wantSelect: true,
		},
		{
			name:       "cooldown without deadline remains cooldown",
			health:     AccountHealth{Status: HealthCooldown},
			wantStatus: HealthCooldown,
			wantSelect: false,
		},
		{
			name:       "needs_reauth is not selectable",
			health:     AccountHealth{Status: HealthNeedsReauth},
			wantStatus: HealthNeedsReauth,
			wantSelect: false,
		},
		{
			name:       "disabled is not selectable",
			health:     AccountHealth{Status: HealthDisabled},
			wantStatus: HealthDisabled,
			wantSelect: false,
		},
		{
			name:       "empty uninitialized status is not selectable",
			health:     AccountHealth{},
			wantStatus: "",
			wantSelect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.health.EffectiveStatus(now); got != tc.wantStatus {
				t.Fatalf("EffectiveStatus() = %q, want %q", got, tc.wantStatus)
			}
			if got := tc.health.CanSelect(now); got != tc.wantSelect {
				t.Fatalf("CanSelect() = %v, want %v", got, tc.wantSelect)
			}
		})
	}
}

func TestQuotaSnapshotPoolRemaining(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 11, 18, 17, 0, 0, 0, time.UTC)

	t.Run("picks minimum window within pool", func(t *testing.T) {
		t.Parallel()
		snap := QuotaSnapshot{
			Source: QuotaSourceSummary,
			Buckets: []QuotaBucket{
				{Pool: PoolGemini, Window: Window5h, RemainingFraction: 0.25, ResetAt: &t1},
				{Pool: PoolGemini, Window: WindowWeekly, RemainingFraction: 0.80, ResetAt: &t2},
				{Pool: Pool3P, Window: Window5h, RemainingFraction: 0.60, ResetAt: &t3},
			},
		}

		rem, resetAt, ok := snap.PoolRemaining(PoolGemini)
		if !ok || rem != 0.25 || resetAt == nil || !resetAt.Equal(t1) {
			t.Fatalf("PoolRemaining(gemini) = (%v, %v, %v), want (0.25, %v, true)", rem, resetAt, ok, t1)
		}

		rem, resetAt, ok = snap.PoolRemaining("")
		if !ok || rem != 0.25 || resetAt == nil || !resetAt.Equal(t1) {
			t.Fatalf("PoolRemaining(\"\") = (%v, %v, %v), want (0.25, %v, true)", rem, resetAt, ok, t1)
		}

		if _, _, ok := snap.PoolRemaining(PoolGeminiArgon); ok {
			t.Fatalf("PoolRemaining(gemini-argon) unexpectedly found data")
		}
	})

	t.Run("empty pool aggregates known pools and ignores other", func(t *testing.T) {
		t.Parallel()
		snap := QuotaSnapshot{
			Buckets: []QuotaBucket{
				{Pool: PoolGemini, Window: Window5h, RemainingFraction: 0.70, ResetAt: &t1},
				{Pool: PoolOther, Window: Window5h, RemainingFraction: 0.01, ResetAt: &t3},
			},
		}

		rem, _, ok := snap.PoolRemaining("")
		if !ok || rem != 0.70 {
			t.Fatalf("PoolRemaining(\"\") = (%v, %v), want (0.70, true)", rem, ok)
		}
		remOther, _, okOther := snap.PoolRemaining(PoolOther)
		if !okOther || remOther != 0.01 {
			t.Fatalf("PoolRemaining(other) = (%v, %v), want (0.01, true)", remOther, okOther)
		}
	})

	t.Run("exhausted tie chooses latest reset deadline", func(t *testing.T) {
		t.Parallel()
		snap := QuotaSnapshot{
			Buckets: []QuotaBucket{
				{Pool: PoolGemini, Window: Window5h, RemainingFraction: 0, ResetAt: &t1},
				{Pool: PoolGemini, Window: WindowWeekly, RemainingFraction: 0, ResetAt: &t2},
			},
		}

		rem, resetAt, ok := snap.PoolRemaining(PoolGemini)
		if !ok || rem != 0 || resetAt == nil || !resetAt.Equal(t2) {
			t.Fatalf("PoolRemaining(gemini) = (%v, %v, %v), want (0, %v, true)", rem, resetAt, ok, t2)
		}
	})

	t.Run("falls back to Models when Buckets absent", func(t *testing.T) {
		t.Parallel()
		snap := QuotaSnapshot{
			Source: QuotaSourceModels,
			Models: []ModelQuota{
				{ModelID: "gemini-2.5-pro", RemainingFraction: 0.90, ResetAt: &t1},
				{ModelID: "claude-sonnet-4-6", RemainingFraction: 0.35, ResetAt: &t3},
				{ModelID: "gemini-argon", RemainingFraction: 0.50, ResetAt: &t2},
			},
		}

		rem, resetAt, ok := snap.PoolRemaining(Pool3P)
		if !ok || rem != 0.35 || resetAt == nil || !resetAt.Equal(t3) {
			t.Fatalf("PoolRemaining(3p) = (%v, %v, %v), want (0.35, %v, true)", rem, resetAt, ok, t3)
		}
		remAll, _, okAll := snap.PoolRemaining("")
		if !okAll || remAll != 0.35 {
			t.Fatalf("PoolRemaining(\"\") = (%v, %v), want (0.35, true)", remAll, okAll)
		}
	})

	t.Run("empty snapshot returns not ok", func(t *testing.T) {
		t.Parallel()
		if _, _, ok := (QuotaSnapshot{}).PoolRemaining(""); ok {
			t.Fatalf("expected empty snapshot PoolRemaining to return ok=false")
		}
	})
}

func TestInferPoolForModel(t *testing.T) {
	t.Parallel()

	snap := QuotaSnapshot{
		Models: []ModelQuota{
			{ModelID: "MODEL_PLACEHOLDER_M37", DisplayName: "Claude Sonnet 4.6 (Thinking)"},
			{ModelID: "MODEL_PLACEHOLDER_G1", DisplayName: "Gemini 3.1 Pro"},
		},
	}

	tests := []struct {
		model string
		want  QuotaPool
	}{
		{model: "gemini-2.5-pro", want: PoolGemini},
		{model: "gemini-3-flash", want: PoolGemini},
		{model: "Hydrogen (XHigh)", want: PoolGemini},
		{model: "Neon (XHigh)", want: PoolGemini},
		{model: "gemini-argon", want: PoolGeminiArgon},
		{model: "gemini-3.5-argon-preview", want: PoolGeminiArgon},
		{model: "claude-sonnet-4-6", want: Pool3P},
		{model: "Claude Sonnet 5.5 (High)", want: Pool3P},
		{model: "gemini-claude-sonnet-4-6", want: Pool3P},
		{model: "claude-opus-4-5-thinking", want: Pool3P},
		{model: "gpt-oss-120b", want: Pool3P},
		{model: "o3-mini", want: Pool3P},
		{model: "MODEL_PLACEHOLDER_M37", want: Pool3P},
		{model: "MODEL_PLACEHOLDER_G1", want: PoolGemini},
		{model: "proto1-custom", want: PoolOther},
		{model: "cross-encoder-v1", want: PoolOther},
		{model: "", want: PoolOther},
	}

	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			t.Parallel()
			if got := snap.InferPoolForModel(tc.model); got != tc.want {
				t.Fatalf("InferPoolForModel(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

func TestStoreStateJSONRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC)
	cooldownUntil := now.Add(10 * time.Minute)
	resetAt := now.Add(4 * time.Hour)
	lastUsed := now.Add(-2 * time.Minute)

	want := StoreState{
		SchemaVersion: CurrentSchemaVersion,
		Generation:    7,
		ActiveKey:     "alice@example.com",
		Policy: SelectionPolicy{
			Mode:                  SwitchPriority,
			TargetPool:            Pool3P,
			MinRemainingThreshold: 0.10,
			CooldownDefault:       3 * time.Minute,
			RefreshSkew:           90 * time.Second,
		},
		Accounts: map[AccountKey]Account{
			"alice@example.com": {
				Key:         "alice@example.com",
				Email:       "alice@example.com",
				AccountID:   "acct-1",
				DisplayName: "Alice",
				Priority:    1,
				Health: AccountHealth{
					Status:        HealthCooldown,
					Reason:        "rate_limited",
					CooldownUntil: &cooldownUntil,
					UpdatedAt:     now,
				},
				Creds: AccountCredentials{
					AccessToken:  "ya29.access",
					RefreshToken: "1//refresh",
					TokenType:    "Bearer",
					Expiry:       now.Add(time.Hour),
					IDToken:      "id.jwt",
					ClientID:     "client-123",
				},
				Quota: &QuotaSnapshot{
					FetchedAt:      now,
					Source:         QuotaSourceSummary,
					EndpointHost:   "cloudcode-pa.googleapis.com",
					Tier:           TierPro,
					RawCurrentTier: "g1-pro-tier",
					RawPaidTier:    "g1-pro-tier",
					ProjectID:      "proj-1",
					Credits: []CreditInfo{
						{Provider: "google", Remaining: 42.5, Unit: "USD"},
					},
					Buckets: []QuotaBucket{
						{
							GroupID:           "3p-5h",
							DisplayName:       "Claude / GPT 5h",
							Pool:              Pool3P,
							Window:            Window5h,
							RemainingFraction: 0.65,
							ResetAt:           &resetAt,
						},
					},
					Models: []ModelQuota{
						{
							ModelID:           "claude-sonnet-4-6",
							DisplayName:       "Claude Sonnet 4.6",
							RemainingFraction: 0.65,
							ResetAt:           &resetAt,
							SupportsThinking:  true,
						},
					},
				},
				AddedAt:    now.Add(-24 * time.Hour),
				LastUsedAt: &lastUsed,
			},
		},
		NativeBackup: &NativeBackupRecord{
			CapturedAt: now.Add(-24 * time.Hour),
			SourcePath: "/home/alice/.gemini/antigravity-cli/antigravity-oauth-token",
			BackupPath: "/home/alice/.local/share/multi-anti/backups/native-antigravity-oauth-token.bak",
			SHA256:     "deadbeef",
			HadFile:    true,
		},
		LastSwitch: &SwitchAuditEntry{
			At:      now,
			Outcome: OutcomeSwitched,
			FromKey: "bob@example.com",
			ToKey:   "alice@example.com",
			Reason:  "quota_low",
			Pool:    Pool3P,
			Trigger: "hook",
		},
	}

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal(StoreState) failed: %v", err)
	}

	var got StoreState
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("json.Unmarshal(StoreState) failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON round-trip mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestClassifyPoolAndWindow(t *testing.T) {
	t.Parallel()

	poolCases := []struct {
		input string
		want  QuotaPool
	}{
		{input: "Gemini 4 Neon", want: PoolGemini},
		{input: "Gemini 4 Hydrogen", want: PoolGemini},
		{input: "Orchestrator (Neon)", want: PoolGemini},
		{input: "Orchestrator", want: PoolGemini},
		{input: "Gemini 3.8 Flash", want: PoolGemini},
		{input: "Claude Opus 5.5", want: Pool3P},
		{input: "Claude Sonnet 5.5", want: Pool3P},
		{input: "GPT-OSS 120B", want: Pool3P},
		{input: "Gemini 4 Argon", want: PoolGeminiArgon},
		{input: "custom-model", want: PoolOther},
	}
	for _, tc := range poolCases {
		if got := ClassifyPool(tc.input); got != tc.want {
			t.Fatalf("ClassifyPool(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	windowCases := []struct {
		input string
		want  QuotaWindow
	}{
		{input: "Five Hour Limit Remaining", want: Window5h},
		{input: "gemini-5h", want: Window5h},
		{input: "3p_5_hour", want: Window5h},
		{input: "5-hour window", want: Window5h},
		{input: "five-hour-limit", want: Window5h},
		{input: "Weekly Limit Remaining", want: WindowWeekly},
		{input: "Gemini 4 Argon Weekly Limit", want: WindowWeekly},
		{input: "7d-quota", want: WindowWeekly},
		{input: "other-limit", want: WindowUnknown},
		{input: "", want: WindowUnknown},
	}
	for _, tc := range windowCases {
		if got := ClassifyWindow(tc.input); got != tc.want {
			t.Fatalf("ClassifyWindow(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
