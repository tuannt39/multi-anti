package selector

import (
	"testing"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
)

func makeSelectorAccount(
	key string,
	priority int,
	health domain.AccountHealth,
	lastUsed *time.Time,
	buckets ...domain.QuotaBucket,
) domain.Account {
	var q *domain.QuotaSnapshot
	if len(buckets) > 0 {
		q = &domain.QuotaSnapshot{
			Source:  domain.QuotaSourceSummary,
			Tier:    domain.TierPro,
			Buckets: buckets,
		}
	}
	return domain.Account{
		Key:        domain.AccountKey(key),
		Email:      key,
		Priority:   priority,
		Health:     health,
		Quota:      q,
		LastUsedAt: lastUsed,
	}
}

func TestDefaultSelectorModesAndTieBreaking(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	usedOld := now.Add(-30 * time.Minute)
	usedMid := now.Add(-15 * time.Minute)
	usedNew := now.Add(-2 * time.Minute)

	tests := []struct {
		name        string
		mode        domain.SwitchMode
		currentKey  domain.AccountKey
		forceSwitch bool
		exclude     map[domain.AccountKey]bool
		accounts    []domain.Account
		wantOutcome domain.SwitchOutcome
		wantToKey   domain.AccountKey
		wantRem     float64
	}{
		{
			name:       "highest_remaining picks highest pool fraction",
			mode:       domain.SwitchHighestRemaining,
			currentKey: "a@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 5, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.40}),
				makeSelectorAccount("b@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.90}),
				makeSelectorAccount("c@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.75}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "b@example.com",
			wantRem:     0.90,
		},
		{
			name:       "highest_remaining deterministic tie-break: Priority desc -> LastUsedAt oldest -> Key asc",
			mode:       domain.SwitchHighestRemaining,
			currentKey: "d@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("d@example.com", 5, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.80}),
				makeSelectorAccount("c@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedMid,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.80}),
				makeSelectorAccount("b@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.80}),
				makeSelectorAccount("a@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.80}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "a@example.com",
			wantRem:     0.80,
		},
		{
			name:       "fill_first keeps eligible current account above threshold",
			mode:       domain.SwitchFillFirst,
			currentKey: "a@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.70}),
				makeSelectorAccount("b@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.25}),
			},
			wantOutcome: domain.OutcomeKeepCurrent,
			wantToKey:   "a@example.com",
			wantRem:     0.70,
		},
		{
			name:       "fill_first drains lowest eligible account when current is below threshold",
			mode:       domain.SwitchFillFirst,
			currentKey: "a@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.03}),
				makeSelectorAccount("b@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.20}),
				makeSelectorAccount("c@example.com", 5, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.95}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "b@example.com",
			wantRem:     0.20,
		},
		{
			name:       "round_robin picks oldest LastUsedAt (never-used nil beats timestamps)",
			mode:       domain.SwitchRoundRobin,
			currentKey: "a@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.90}),
				makeSelectorAccount("b@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.50}),
				makeSelectorAccount("c@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.40}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "c@example.com",
			wantRem:     0.40,
		},
		{
			name:       "priority picks highest priority, breaking ties by oldest LastUsedAt then Key",
			mode:       domain.SwitchPriority,
			currentKey: "a@example.com",
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 5, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.95}),
				makeSelectorAccount("b@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.40}),
				makeSelectorAccount("c@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedMid,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.30}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "c@example.com",
			wantRem:     0.30,
		},
		{
			name:        "ForceSwitch prevents keeping current account even if it is best",
			mode:        domain.SwitchHighestRemaining,
			currentKey:  "a@example.com",
			forceSwitch: true,
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.99}),
				makeSelectorAccount("b@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.30}),
			},
			wantOutcome: domain.OutcomeSwitched,
			wantToKey:   "b@example.com",
			wantRem:     0.30,
		},
		{
			name:       "ExcludeKeys skips specified accounts",
			mode:       domain.SwitchHighestRemaining,
			currentKey: "a@example.com",
			exclude:    map[domain.AccountKey]bool{"b@example.com": true},
			accounts: []domain.Account{
				makeSelectorAccount("a@example.com", 1, domain.AccountHealth{Status: domain.HealthReady}, &usedNew,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.50}),
				makeSelectorAccount("b@example.com", 10, domain.AccountHealth{Status: domain.HealthReady}, &usedOld,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.99}),
			},
			wantOutcome: domain.OutcomeKeepCurrent,
			wantToKey:   "a@example.com",
			wantRem:     0.50,
		},
	}

	sel := NewDefaultSelector()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policy := domain.DefaultSelectionPolicy()
			policy.Mode = tc.mode

			state := domain.StoreState{
				SchemaVersion: domain.CurrentSchemaVersion,
				Policy:        policy,
				Accounts:      make(map[domain.AccountKey]domain.Account, len(tc.accounts)),
			}
			for _, acc := range tc.accounts {
				state.Accounts[acc.Key] = acc
			}

			dec := sel.Evaluate(state, EvalRequest{
				CurrentKey:  tc.currentKey,
				ForceSwitch: tc.forceSwitch,
				ExcludeKeys: tc.exclude,
				Now:         now,
			})
			if dec.Outcome != tc.wantOutcome {
				t.Fatalf("Outcome = %q, want %q (dec=%+v)", dec.Outcome, tc.wantOutcome, dec)
			}
			if dec.ToKey != tc.wantToKey {
				t.Fatalf("ToKey = %q, want %q", dec.ToKey, tc.wantToKey)
			}
			if dec.CandidateRemaining != tc.wantRem {
				t.Fatalf("CandidateRemaining = %v, want %v", dec.CandidateRemaining, tc.wantRem)
			}
		})
	}
}

func TestDefaultSelectorPoolIsolationAndCooldownPromotion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-10 * time.Second)
	active1 := now.Add(5 * time.Minute)
	active2 := now.Add(15 * time.Minute)

	sel := NewDefaultSelector()

	t.Run("isolates Pool3P and PoolGemini across TargetPool and TargetModel", func(t *testing.T) {
		t.Parallel()

		state := domain.StoreState{
			SchemaVersion: domain.CurrentSchemaVersion,
			Policy:        domain.DefaultSelectionPolicy(),
			Accounts: map[domain.AccountKey]domain.Account{
				"gem@example.com": makeSelectorAccount("gem@example.com", 0, domain.AccountHealth{Status: domain.HealthReady}, nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.95},
					domain.QuotaBucket{Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 0.00},
				),
				"threep@example.com": makeSelectorAccount("threep@example.com", 0, domain.AccountHealth{Status: domain.HealthReady}, nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.10},
					domain.QuotaBucket{Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 0.85},
				),
			},
		}

		decGemini := sel.Evaluate(state, EvalRequest{TargetPool: domain.PoolGemini, Now: now})
		if decGemini.ToKey != "gem@example.com" || decGemini.Pool != domain.PoolGemini {
			t.Fatalf("PoolGemini decision = %+v", decGemini)
		}

		dec3P := sel.Evaluate(state, EvalRequest{TargetModel: "claude-sonnet-4-6", Now: now})
		if dec3P.ToKey != "threep@example.com" || dec3P.Pool != domain.Pool3P {
			t.Fatalf("Pool3P decision = %+v", dec3P)
		}

		decArgon := sel.Evaluate(state, EvalRequest{TargetModel: "gemini-4-argon-high", Now: now})
		if decArgon.ToKey != "gem@example.com" || decArgon.Pool != domain.PoolGemini {
			t.Fatalf("Argon model PoolGemini decision = %+v", decArgon)
		}

		ranked3P := sel.Rank(state, EvalRequest{TargetPool: domain.Pool3P, Now: now})
		if len(ranked3P) != 2 || !ranked3P[0].Eligible || ranked3P[0].Key != "threep@example.com" {
			t.Fatalf("ranked3P = %+v", ranked3P)
		}
		if ranked3P[1].Eligible {
			t.Fatalf("expected non-eligible account for Pool3P: %+v", ranked3P)
		}
	})

	t.Run("promotes expired cooldown to selectable ready", func(t *testing.T) {
		t.Parallel()

		state := domain.StoreState{
			SchemaVersion: domain.CurrentSchemaVersion,
			Policy:        domain.DefaultSelectionPolicy(),
			Accounts: map[domain.AccountKey]domain.Account{
				"expired-cd@example.com": makeSelectorAccount(
					"expired-cd@example.com", 0,
					domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &expired},
					nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.80},
				),
				"active-cd@example.com": makeSelectorAccount(
					"active-cd@example.com", 10,
					domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &active1},
					nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.99},
				),
			},
		}

		dec := sel.Evaluate(state, EvalRequest{Now: now})
		if dec.Outcome != domain.OutcomeSwitched || dec.ToKey != "expired-cd@example.com" {
			t.Fatalf("decision = %+v, want switched to expired-cd@example.com", dec)
		}
	})

	t.Run("returns OutcomeNoneReady with EarliestReset ignoring disabled and needs_reauth", func(t *testing.T) {
		t.Parallel()

		earlierNeedsReauth := now.Add(1 * time.Minute)
		exhaustedReset := now.Add(3 * time.Minute)

		state := domain.StoreState{
			SchemaVersion: domain.CurrentSchemaVersion,
			ActiveKey:     "cd2@example.com",
			Policy:        domain.DefaultSelectionPolicy(),
			Accounts: map[domain.AccountKey]domain.Account{
				"reauth@example.com": makeSelectorAccount(
					"reauth@example.com", 0,
					domain.AccountHealth{Status: domain.HealthNeedsReauth, CooldownUntil: &earlierNeedsReauth},
					nil,
				),
				"cd1@example.com": makeSelectorAccount(
					"cd1@example.com", 0,
					domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &active2},
					nil,
				),
				"cd2@example.com": makeSelectorAccount(
					"cd2@example.com", 0,
					domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &active1},
					nil,
				),
				"exhausted@example.com": makeSelectorAccount(
					"exhausted@example.com", 0,
					domain.AccountHealth{Status: domain.HealthReady},
					nil,
					domain.QuotaBucket{Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.0, ResetAt: &exhaustedReset},
				),
			},
		}

		dec := sel.Evaluate(state, EvalRequest{Now: now})
		if dec.Outcome != domain.OutcomeNoneReady {
			t.Fatalf("Outcome = %q, want OutcomeNoneReady", dec.Outcome)
		}
		if dec.EarliestReset == nil || !dec.EarliestReset.Equal(exhaustedReset) {
			t.Fatalf("EarliestReset = %v, want %v", dec.EarliestReset, exhaustedReset)
		}
	})
}

func TestIsQuotaExhaustedErrorAndMarkCooldown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		text    string
		wantHit bool
		wantDur time.Duration
		hasDur  bool
	}{
		{
			name:    "RESOURCE_EXHAUSTED with retryDelay",
			text:    `{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"retryDelay":"45s"}]}}`,
			wantHit: true,
			hasDur:  true,
			wantDur: 45 * time.Second,
		},
		{
			name:    "Usage Limit Reached with Go duration",
			text:    "Usage Limit Reached: your quota resets in 2h15m30s",
			wantHit: true,
			hasDur:  true,
			wantDur: 2*time.Hour + 15*time.Minute + 30*time.Second,
		},
		{
			name:    "Individual quota reached",
			text:    "Individual quota reached for this account",
			wantHit: true,
		},
		{
			name:    "weekly limit with human duration",
			text:    "You have hit your weekly limit. Try again in 3 days",
			wantHit: true,
			hasDur:  true,
			wantDur: 72 * time.Hour,
		},
		{
			name:    "weekly quota",
			text:    "Weekly quota exceeded for Claude",
			wantHit: true,
		},
		{
			name:    "5-hour quota",
			text:    "Your 5-hour quota has been depleted",
			wantHit: true,
		},
		{
			name:    "spend-cap",
			text:    "Workspace spend-cap reached",
			wantHit: true,
		},
		{
			name:    "prepaid-balance",
			text:    "Insufficient prepaid-balance remaining",
			wantHit: true,
		},
		{
			name:    "INSUFFICIENT_G1_CREDITS",
			text:    "Error INSUFFICIENT_G1_CREDITS on project",
			wantHit: true,
		},
		{
			name:    "HTTP 429 with Retry-After seconds",
			text:    "HTTP 429 Too Many Requests; Retry-After: 120",
			wantHit: true,
			hasDur:  true,
			wantDur: 120 * time.Second,
		},
		{
			name:    "unrelated 429 inside port or ID does not match",
			text:    "dial tcp 127.0.0.1:4291: connection refused req-429-abc",
			wantHit: false,
		},
		{
			name:    "ordinary error does not match",
			text:    "context deadline exceeded",
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hit, dur := IsQuotaExhaustedError(tc.text)
			if hit != tc.wantHit {
				t.Fatalf("IsQuotaExhaustedError(%q) hit = %v, want %v", tc.text, hit, tc.wantHit)
			}
			if tc.hasDur {
				if dur == nil || *dur != tc.wantDur {
					t.Fatalf("duration = %v, want %v", dur, tc.wantDur)
				}
			} else if dur != nil {
				t.Fatalf("duration = %v, want nil", dur)
			}
		})
	}

	t.Run("MarkAccountCooldown uses future resetAt or falls back to fallback duration", func(t *testing.T) {
		t.Parallel()
		now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
		future := now.Add(20 * time.Minute)
		past := now.Add(-1 * time.Minute)

		acc := domain.Account{Key: "a@example.com"}
		MarkAccountCooldown(&acc, &future, "429", 5*time.Minute, now)
		if acc.Health.Status != domain.HealthCooldown || acc.Health.CooldownUntil == nil || !acc.Health.CooldownUntil.Equal(future) {
			t.Fatalf("Health with future resetAt = %+v", acc.Health)
		}

		MarkAccountCooldown(&acc, &past, "fallback", 7*time.Minute, now)
		if acc.Health.CooldownUntil == nil || !acc.Health.CooldownUntil.Equal(now.Add(7*time.Minute)) {
			t.Fatalf("Health with past resetAt = %+v, want fallback +7m", acc.Health)
		}
	})
}

func TestExcludedCooldownAccountContributesEarliestReset(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	until := now.Add(time.Minute)
	state := domain.StoreState{
		SchemaVersion: domain.CurrentSchemaVersion,
		Policy:        domain.DefaultSelectionPolicy(),
		Accounts: map[domain.AccountKey]domain.Account{
			"a@example.com": makeSelectorAccount("a@example.com", 0,
				domain.AccountHealth{Status: domain.HealthCooldown, CooldownUntil: &until}, nil),
		},
	}

	dec := NewDefaultSelector().Evaluate(state, EvalRequest{
		Now:         now,
		ExcludeKeys: map[domain.AccountKey]bool{"a@example.com": true},
	})
	if dec.Outcome != domain.OutcomeNoneReady {
		t.Fatalf("Outcome = %q, want OutcomeNoneReady", dec.Outcome)
	}
	if dec.EarliestReset == nil || !dec.EarliestReset.Equal(until) {
		t.Fatalf("EarliestReset = %v, want %v", dec.EarliestReset, until)
	}
}

func TestIsQuotaExhaustedExpandedPatternsAndCompoundDurations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		text    string
		wantHit bool
		wantDur time.Duration
	}{
		{
			name:    "spaced Go duration",
			text:    "RESOURCE_EXHAUSTED: Individual quota reached. Resets in 3h 8m 39s.",
			wantHit: true,
			wantDur: 3*time.Hour + 8*time.Minute + 39*time.Second,
		},
		{
			name:    "compound human duration",
			text:    "Quota exceeded. Try again in 2 hours 15 minutes",
			wantHit: true,
			wantDur: 2*time.Hour + 15*time.Minute,
		},
		{
			name:    "model capacity exhausted",
			text:    "MODEL_CAPACITY_EXHAUSTED: exhausted your capacity for this model",
			wantHit: true,
		},
		{
			name:    "too many requests with retry after",
			text:    "Too Many Requests; Retry-After: 90",
			wantHit: true,
			wantDur: 90 * time.Second,
		},
		{
			name:    "daily limit hit",
			text:    "Daily limit reached on free tier",
			wantHit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hit, dur := IsQuotaExhaustedError(tc.text)
			if hit != tc.wantHit {
				t.Fatalf("IsQuotaExhaustedError(%q) hit = %v, want %v", tc.text, hit, tc.wantHit)
			}
			if tc.wantDur > 0 {
				if dur == nil || *dur != tc.wantDur {
					t.Fatalf("duration = %v, want %v", dur, tc.wantDur)
				}
			}
		})
	}
}

func TestMarkPoolExhaustedZeroesOnlyTargetPool(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	resetAt := now.Add(2 * time.Hour)
	acc := makeSelectorAccount("a@example.com", 0, domain.AccountHealth{Status: domain.HealthReady}, nil,
		domain.QuotaBucket{GroupID: "g-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.75},
		domain.QuotaBucket{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 0.80},
	)
	acc.Quota.Models = []domain.ModelQuota{
		{ModelID: "gemini-4-neon-xhigh", RemainingFraction: 0.75},
		{ModelID: "claude-sonnet-5-5", RemainingFraction: 0.80},
	}

	MarkPoolExhausted(&acc, domain.PoolGemini, &resetAt)

	gemRem, gemReset, ok := acc.Quota.PoolRemaining(domain.PoolGemini)
	if !ok || gemRem != 0 || gemReset == nil || !gemReset.Equal(resetAt) {
		t.Fatalf("PoolGemini = (%v, %v, %v), want (0, %v, true)", gemRem, gemReset, ok, resetAt)
	}
	p3Rem, _, ok := acc.Quota.PoolRemaining(domain.Pool3P)
	if !ok || p3Rem != 0.80 {
		t.Fatalf("Pool3P = (%v, %v), want (0.80, true)", p3Rem, ok)
	}
	if acc.Quota.Models[0].RemainingFraction != 0 || acc.Quota.Models[1].RemainingFraction != 0.80 {
		t.Fatalf("unexpected model fractions after MarkPoolExhausted: %+v", acc.Quota.Models)
	}
}

func TestMarkPoolExhausted5hPreservesWeeklyWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	reset5h := now.Add(3*time.Hour + 36*time.Minute)
	resetWk := now.Add(140 * time.Hour)

	acc := domain.Account{
		Key:   "a@example.com",
		Email: "a@example.com",
		Health: domain.AccountHealth{
			Status:        domain.HealthCooldown,
			CooldownUntil: &reset5h,
			UpdatedAt:     now,
		},
		Quota: &domain.QuotaSnapshot{
			FetchedAt: now.Add(-5 * time.Minute),
			Source:    domain.QuotaSourceSummary,
			Tier:      domain.TierPro,
			Buckets: []domain.QuotaBucket{
				{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.25},
				{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.56, ResetAt: &resetWk},
			},
		},
	}

	MarkPoolExhausted(&acc, domain.PoolGemini, &reset5h)

	if acc.Quota.Buckets[0].RemainingFraction != 0 || acc.Quota.Buckets[0].ResetAt == nil || !acc.Quota.Buckets[0].ResetAt.Equal(reset5h) {
		t.Fatalf("5h bucket = %+v, want remaining 0 with reset %v", acc.Quota.Buckets[0], reset5h)
	}
	if acc.Quota.Buckets[1].RemainingFraction != 0.56 || acc.Quota.Buckets[1].ResetAt == nil || !acc.Quota.Buckets[1].ResetAt.Equal(resetWk) {
		t.Fatalf("weekly bucket unexpectedly clobbered: %+v", acc.Quota.Buckets[1])
	}
	rem, poolReset, ok := acc.Quota.PoolRemaining(domain.PoolGemini)
	if !ok || rem != 0 || poolReset == nil || !poolReset.Equal(reset5h) {
		t.Fatalf("PoolRemaining(PoolGemini) = (%v, %v, %v), want (0, %v, true)", rem, poolReset, ok, reset5h)
	}
}

func TestArgonAndCarbonModelsSelectPoolGemini(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 25, 18, 0, 0, 0, time.UTC)
	sel := NewDefaultSelector()
	state := domain.StoreState{
		SchemaVersion: domain.CurrentSchemaVersion,
		Policy:        domain.DefaultSelectionPolicy(),
		Accounts: map[domain.AccountKey]domain.Account{
			"gem@example.com": makeSelectorAccount("gem@example.com", 0, domain.AccountHealth{Status: domain.HealthReady}, nil,
				domain.QuotaBucket{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.90},
				domain.QuotaBucket{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.95},
				domain.QuotaBucket{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 0.10},
				domain.QuotaBucket{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 0.10},
			),
			"threep@example.com": makeSelectorAccount("threep@example.com", 0, domain.AccountHealth{Status: domain.HealthReady}, nil,
				domain.QuotaBucket{GroupID: "gemini-5h", Pool: domain.PoolGemini, Window: domain.Window5h, RemainingFraction: 0.20},
				domain.QuotaBucket{GroupID: "gemini-weekly", Pool: domain.PoolGemini, Window: domain.WindowWeekly, RemainingFraction: 0.80},
				domain.QuotaBucket{GroupID: "3p-5h", Pool: domain.Pool3P, Window: domain.Window5h, RemainingFraction: 1.00},
				domain.QuotaBucket{GroupID: "3p-weekly", Pool: domain.Pool3P, Window: domain.WindowWeekly, RemainingFraction: 1.00},
			),
		},
	}

	for _, model := range []string{"gemini-4-argon-high", "Argon (High)", "gemini-4-carbon-high", "Carbon (High)"} {
		dec := sel.Evaluate(state, EvalRequest{TargetModel: model, Now: now})
		if dec.Outcome != domain.OutcomeSwitched || dec.ToKey != "gem@example.com" || dec.Pool != domain.PoolGemini {
			t.Fatalf("Evaluate(model=%q) = %+v, want switched to gem@example.com on PoolGemini", model, dec)
		}
	}
}
