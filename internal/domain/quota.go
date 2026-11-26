package domain

import (
	"strings"
	"time"
	"unicode"
)

// SubscriptionTier identifies the account's Antigravity plan tier.
type SubscriptionTier string

const (
	TierUnknown    SubscriptionTier = "unknown"
	TierFree       SubscriptionTier = "free"
	TierPro        SubscriptionTier = "pro"
	TierUltra      SubscriptionTier = "ultra"
	TierEnterprise SubscriptionTier = "enterprise"
)

// QuotaSource identifies which backend endpoint produced a QuotaSnapshot.
type QuotaSource string

const (
	QuotaSourceSummary QuotaSource = "retrieveUserQuotaSummary"
	QuotaSourceModels  QuotaSource = "fetchAvailableModels"
)

// QuotaWindow identifies the reset cadence of a quota bucket.
type QuotaWindow string

const (
	Window5h      QuotaWindow = "5h"
	WindowWeekly  QuotaWindow = "weekly"
	WindowUnknown QuotaWindow = "unknown"
)

// QuotaPool groups models that share a rate-limit quota pool.
type QuotaPool string

const (
	PoolGemini QuotaPool = "gemini"
	Pool3P     QuotaPool = "3p"
	PoolOther  QuotaPool = "other"
)

// IsValid reports whether p is a recognized QuotaPool value.
func (p QuotaPool) IsValid() bool {
	switch p {
	case PoolGemini, Pool3P, PoolOther:
		return true
	default:
		return false
	}
}

func (p QuotaPool) isKnownForAggregate() bool {
	return p == PoolGemini || p == Pool3P
}

// CreditInfo records supplemental credit balance reported for an account.
type CreditInfo struct {
	Provider  string  `json:"provider,omitempty"`
	Remaining float64 `json:"remaining"`
	Unit      string  `json:"unit,omitempty"`
}

// QuotaBucket records remaining quota for one pool and window pair.
type QuotaBucket struct {
	GroupID           string      `json:"group_id,omitempty"`
	DisplayName       string      `json:"display_name,omitempty"`
	Pool              QuotaPool   `json:"pool"`
	Window            QuotaWindow `json:"window"`
	RemainingFraction float64     `json:"remaining_fraction"`
	ResetAt           *time.Time  `json:"reset_at,omitempty"`
}

// ModelQuota records per-model quota availability returned by fetchAvailableModels.
type ModelQuota struct {
	ModelID           string     `json:"model_id"`
	DisplayName       string     `json:"display_name,omitempty"`
	RemainingFraction float64    `json:"remaining_fraction"`
	ResetAt           *time.Time `json:"reset_at,omitempty"`
	SupportsThinking  bool       `json:"supports_thinking,omitempty"`
}

// QuotaSnapshot captures a normalized point-in-time quota reading for an account.
type QuotaSnapshot struct {
	FetchedAt        time.Time        `json:"fetched_at"`
	Source           QuotaSource      `json:"source"`
	EndpointHost     string           `json:"endpoint_host,omitempty"`
	Tier             SubscriptionTier `json:"tier"`
	RawCurrentTier   string           `json:"raw_current_tier,omitempty"`
	RawPaidTier      string           `json:"raw_paid_tier,omitempty"`
	ProjectID        string           `json:"project_id,omitempty"`
	Credits          []CreditInfo     `json:"credits,omitempty"`
	Buckets          []QuotaBucket    `json:"buckets,omitempty"`
	Models           []ModelQuota     `json:"models,omitempty"`
	SummaryForbidden bool             `json:"summary_forbidden,omitempty"`
	FetchError       string           `json:"fetch_error,omitempty"`
}

// HasScheduledReset reports whether resetAt represents an active scheduled reset deadline.
func HasScheduledReset(resetAt *time.Time) bool {
	return resetAt != nil && !resetAt.IsZero() && resetAt.Unix() > 0
}

// EffectiveAt returns the effective remaining fraction and active reset deadline at now,
// restoring remaining quota to 1.0 once a scheduled reset deadline has passed.
func (b QuotaBucket) EffectiveAt(now time.Time) (float64, *time.Time) {
	return effectiveWindowAt(b.RemainingFraction, b.ResetAt, now)
}

// EffectiveAt returns the effective remaining fraction and active reset deadline at now,
// restoring remaining quota to 1.0 once a scheduled reset deadline has passed.
func (m ModelQuota) EffectiveAt(now time.Time) (float64, *time.Time) {
	return effectiveWindowAt(m.RemainingFraction, m.ResetAt, now)
}

func effectiveWindowAt(remaining float64, resetAt *time.Time, now time.Time) (float64, *time.Time) {
	if !HasScheduledReset(resetAt) {
		return remaining, nil
	}
	if !now.IsZero() && !resetAt.After(now) {
		return 1.0, nil
	}
	t := resetAt.UTC()
	return remaining, &t
}

type poolCandidate struct {
	remaining float64
	resetAt   *time.Time
}

// PoolRemaining returns the minimum remaining fraction across windows of pool,
// or across all known pools (gemini, 3p) when pool is empty.
func (q QuotaSnapshot) PoolRemaining(pool QuotaPool) (remaining float64, resetAt *time.Time, ok bool) {
	return q.PoolRemainingAt(pool, time.Time{})
}

// PoolRemainingAt returns the minimum effective remaining fraction at now across windows of pool,
// or across all known pools (gemini, 3p) when pool is empty.
func (q QuotaSnapshot) PoolRemainingAt(pool QuotaPool, now time.Time) (remaining float64, resetAt *time.Time, ok bool) {
	var candidates []poolCandidate
	for _, b := range q.Buckets {
		if matchesPool(b.Pool, pool) {
			rem, effReset := b.EffectiveAt(now)
			candidates = append(candidates, poolCandidate{
				remaining: rem,
				resetAt:   effReset,
			})
		}
	}
	if len(candidates) > 0 {
		return reduceMinCandidate(candidates)
	}

	for _, m := range q.Models {
		inferred := q.InferPoolForModel(m.ModelID)
		if inferred == PoolOther && m.DisplayName != "" {
			inferred = classifyModelString(m.DisplayName)
		}
		if matchesPool(inferred, pool) {
			rem, effReset := m.EffectiveAt(now)
			candidates = append(candidates, poolCandidate{
				remaining: rem,
				resetAt:   effReset,
			})
		}
	}
	return reduceMinCandidate(candidates)
}

func matchesPool(candidate, target QuotaPool) bool {
	if target == "" {
		return candidate.isKnownForAggregate()
	}
	return candidate == target
}

func reduceMinCandidate(candidates []poolCandidate) (float64, *time.Time, bool) {
	if len(candidates) == 0 {
		return 0, nil, false
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.remaining < best.remaining {
			best = c
			continue
		}
		if c.remaining == best.remaining && isMoreConstrainingReset(c.remaining, c.resetAt, best.resetAt) {
			best.resetAt = c.resetAt
		}
	}
	var resetCopy *time.Time
	if best.resetAt != nil {
		t := *best.resetAt
		resetCopy = &t
	}
	return best.remaining, resetCopy, true
}

func isMoreConstrainingReset(remaining float64, candidate, current *time.Time) bool {
	if candidate == nil {
		return false
	}
	if current == nil {
		return true
	}
	if remaining == 0 {
		return candidate.After(*current)
	}
	return candidate.Before(*current)
}

// InferPoolForModel maps a model identifier or display name to its QuotaPool.
func (q QuotaSnapshot) InferPoolForModel(model string) QuotaPool {
	if pool := classifyModelString(model); pool != PoolOther {
		return pool
	}
	target := strings.TrimSpace(model)
	if target == "" {
		return PoolOther
	}
	for _, m := range q.Models {
		if strings.EqualFold(strings.TrimSpace(m.ModelID), target) ||
			strings.EqualFold(strings.TrimSpace(m.DisplayName), target) {
			if pool := classifyModelString(m.DisplayName); pool != PoolOther {
				return pool
			}
			if pool := classifyModelString(m.ModelID); pool != PoolOther {
				return pool
			}
		}
	}
	return PoolOther
}

// ClassifyPool maps a model ID, display name, or quota group label to its QuotaPool.
func ClassifyPool(s string) QuotaPool {
	return classifyModelString(s)
}

// ClassifyWindow maps a quota group ID, display name, or bucket label to its QuotaWindow.
func ClassifyWindow(s string) QuotaWindow {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch {
	case lower == "":
		return WindowUnknown
	case strings.Contains(lower, "5h") ||
		strings.Contains(lower, "5-hour") ||
		strings.Contains(lower, "5_hour") ||
		strings.Contains(lower, "five hour") ||
		strings.Contains(lower, "five-hour") ||
		strings.Contains(lower, "five_hour"):
		return Window5h
	case strings.Contains(lower, "weekly") || strings.Contains(lower, "week") || strings.Contains(lower, "7d"):
		return WindowWeekly
	default:
		return WindowUnknown
	}
}

func classifyModelString(s string) QuotaPool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return PoolOther
	}
	// Match 3P providers before gemini because aliases like gemini-claude-* contain both.
	for _, sub := range []string{"claude", "anthropic", "sonnet", "opus", "haiku", "gpt", "openai", "chatgpt"} {
		if strings.Contains(lower, sub) {
			return Pool3P
		}
	}
	for _, tok := range splitModelTokens(lower) {
		switch tok {
		case "o1", "o3", "o4", "oss", "3p":
			return Pool3P
		case "argon", "carbon", "hydrogen", "neon", "orchestrator":
			return PoolGemini
		}
	}
	if strings.Contains(lower, "gemini") {
		return PoolGemini
	}
	return PoolOther
}

func splitModelTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}
