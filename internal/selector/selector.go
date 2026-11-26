package selector

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
)

// EvalRequest describes the context and constraints for a single account selection evaluation.
type EvalRequest struct {
	CurrentKey  domain.AccountKey
	TargetPool  domain.QuotaPool
	TargetModel string
	ForceSwitch bool
	ExcludeKeys map[domain.AccountKey]bool
	Now         time.Time
}

// CandidateScore summarizes one account's eligibility and ranking inputs.
type CandidateScore struct {
	Key        domain.AccountKey `json:"key"`
	Remaining  float64           `json:"remaining"`
	ResetAt    *time.Time        `json:"reset_at,omitempty"`
	Priority   int               `json:"priority"`
	LastUsed   *time.Time        `json:"last_used,omitempty"`
	Eligible   bool              `json:"eligible"`
	SkipReason string            `json:"skip_reason,omitempty"`
}

// Selector ranks candidate accounts and produces a SwitchDecision.
type Selector interface {
	Evaluate(state domain.StoreState, req EvalRequest) domain.SwitchDecision
	Rank(state domain.StoreState, req EvalRequest) []CandidateScore
}

// DefaultSelector implements the four built-in SwitchModes with deterministic tie-breaking.
type DefaultSelector struct{}

// NewDefaultSelector returns a DefaultSelector instance.
func NewDefaultSelector() *DefaultSelector {
	return &DefaultSelector{}
}

type scoredCandidate struct {
	score      CandidateScore
	hasQuota   bool
	isCurrent  bool
	blockReset *time.Time
}

// Evaluate picks the best eligible account according to state.Policy or reports OutcomeNoneReady.
func (s *DefaultSelector) Evaluate(state domain.StoreState, req EvalRequest) domain.SwitchDecision {
	curKey := resolveCurrentKey(state, req)
	effectivePool := resolveEffectivePool(state, req)
	mode := resolveMode(state.Policy.Mode)
	ranked := s.rankCandidates(state, req, curKey, effectivePool, mode)

	if len(ranked) > 0 && ranked[0].score.Eligible {
		best := ranked[0].score
		if curKey != "" && best.Key == curKey {
			return domain.SwitchDecision{
				Outcome:            domain.OutcomeKeepCurrent,
				FromKey:            curKey,
				ToKey:              curKey,
				Reason:             fmt.Sprintf("current account remains selected (%s)", mode),
				CandidateRemaining: best.Remaining,
				Pool:               effectivePool,
			}
		}

		curReason := findSkipReason(ranked, curKey)
		reason := fmt.Sprintf("selected by %s", mode)
		if curKey != "" && curReason != "" {
			reason = fmt.Sprintf("switched from %s (%s) by %s", curKey, curReason, mode)
		}
		return domain.SwitchDecision{
			Outcome:            domain.OutcomeSwitched,
			FromKey:            curKey,
			ToKey:              best.Key,
			Reason:             reason,
			CandidateRemaining: best.Remaining,
			Pool:               effectivePool,
		}
	}

	return domain.SwitchDecision{
		Outcome:       domain.OutcomeNoneReady,
		FromKey:       curKey,
		Reason:        "no eligible accounts available",
		Pool:          effectivePool,
		EarliestReset: findEarliestReset(ranked),
	}
}

// Rank evaluates and sorts all accounts in state, placing eligible candidates first in mode order.
func (s *DefaultSelector) Rank(state domain.StoreState, req EvalRequest) []CandidateScore {
	curKey := resolveCurrentKey(state, req)
	effectivePool := resolveEffectivePool(state, req)
	mode := resolveMode(state.Policy.Mode)
	ranked := s.rankCandidates(state, req, curKey, effectivePool, mode)

	out := make([]CandidateScore, len(ranked))
	for i, c := range ranked {
		out[i] = c.score
	}
	return out
}

func (s *DefaultSelector) rankCandidates(
	state domain.StoreState,
	req EvalRequest,
	curKey domain.AccountKey,
	effectivePool domain.QuotaPool,
	mode domain.SwitchMode,
) []scoredCandidate {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	candidates := make([]scoredCandidate, 0, len(state.Accounts))
	for _, acc := range state.Accounts {
		candidates = append(candidates, scoreAccount(acc, state.Policy, req, curKey, effectivePool, now))
	}

	slices.SortFunc(candidates, func(a, b scoredCandidate) int {
		if a.score.Eligible != b.score.Eligible {
			if a.score.Eligible {
				return -1
			}
			return 1
		}
		if !a.score.Eligible {
			return strings.Compare(string(a.score.Key), string(b.score.Key))
		}
		return compareEligible(a, b, mode)
	})
	return candidates
}

func scoreAccount(
	acc domain.Account,
	policy domain.SelectionPolicy,
	req EvalRequest,
	curKey domain.AccountKey,
	effectivePool domain.QuotaPool,
	now time.Time,
) scoredCandidate {
	score := CandidateScore{
		Key:      acc.Key,
		Priority: acc.Priority,
		LastUsed: copyTimePtr(acc.LastUsedAt),
	}

	var hasPoolData bool
	var poolRem float64
	var poolReset *time.Time
	hasAnyQuota := acc.Quota != nil && (len(acc.Quota.Buckets) > 0 || len(acc.Quota.Models) > 0)
	if hasAnyQuota {
		poolRem, poolReset, hasPoolData = acc.Quota.PoolRemainingAt(effectivePool, now)
		if hasPoolData {
			score.Remaining = poolRem
			score.ResetAt = copyTimePtr(poolReset)
		}
	}

	if req.ExcludeKeys[acc.Key] {
		score.SkipReason = "excluded"
		var blockReset *time.Time
		if acc.Health.EffectiveStatus(now) == domain.HealthCooldown {
			blockReset = copyTimePtr(acc.Health.CooldownUntil)
		}
		return scoredCandidate{score: score, blockReset: blockReset}
	}

	if req.ForceSwitch && curKey != "" && acc.Key == curKey {
		score.SkipReason = "force_switch_current"
		return scoredCandidate{score: score}
	}

	effHealth := acc.Health.EffectiveStatus(now)
	if effHealth != domain.HealthReady {
		score.SkipReason = "health_" + string(effHealth)
		var blockReset *time.Time
		if effHealth == domain.HealthCooldown {
			blockReset = laterTime(copyTimePtr(acc.Health.CooldownUntil), blockedQuotaReset(hasPoolData, poolRem, policy.MinRemainingThreshold, poolReset))
			if blockReset != nil {
				score.ResetAt = copyTimePtr(blockReset)
			}
		}
		return scoredCandidate{score: score, blockReset: blockReset}
	}

	if hasAnyQuota {
		if !hasPoolData {
			score.SkipReason = "pool_unavailable"
			return scoredCandidate{score: score}
		}
		if poolRem <= 0 {
			score.SkipReason = "quota_exhausted"
			return scoredCandidate{score: score, hasQuota: true, blockReset: copyTimePtr(poolReset)}
		}
		if poolRem < policy.MinRemainingThreshold {
			score.SkipReason = "below_threshold"
			return scoredCandidate{score: score, hasQuota: true, blockReset: copyTimePtr(poolReset)}
		}
	}

	score.Eligible = true
	return scoredCandidate{
		score:     score,
		hasQuota:  hasPoolData,
		isCurrent: curKey != "" && acc.Key == curKey && !req.ForceSwitch,
	}
}

func compareEligible(a, b scoredCandidate, mode domain.SwitchMode) int {
	switch mode {
	case domain.SwitchHighestRemaining:
		if a.hasQuota != b.hasQuota {
			if a.hasQuota {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(b.score.Remaining, a.score.Remaining); c != 0 {
			return c
		}
		return compareTieBreak(a, b)

	case domain.SwitchFillFirst:
		if a.isCurrent != b.isCurrent {
			if a.isCurrent {
				return -1
			}
			return 1
		}
		if a.hasQuota != b.hasQuota {
			if a.hasQuota {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.score.Remaining, b.score.Remaining); c != 0 {
			return c
		}
		return compareTieBreak(a, b)

	case domain.SwitchRoundRobin:
		if c := compareTimeOldest(a.score.LastUsed, b.score.LastUsed); c != 0 {
			return c
		}
		if c := cmp.Compare(b.score.Priority, a.score.Priority); c != 0 {
			return c
		}
		return strings.Compare(string(a.score.Key), string(b.score.Key))

	case domain.SwitchPriority:
		return compareTieBreak(a, b)

	default:
		if c := cmp.Compare(b.score.Remaining, a.score.Remaining); c != 0 {
			return c
		}
		return compareTieBreak(a, b)
	}
}

func compareTieBreak(a, b scoredCandidate) int {
	if c := cmp.Compare(b.score.Priority, a.score.Priority); c != 0 {
		return c
	}
	if c := compareTimeOldest(a.score.LastUsed, b.score.LastUsed); c != 0 {
		return c
	}
	return strings.Compare(string(a.score.Key), string(b.score.Key))
}

func compareTimeOldest(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case a.Before(*b):
		return -1
	case b.Before(*a):
		return 1
	default:
		return 0
	}
}

func resolveCurrentKey(state domain.StoreState, req EvalRequest) domain.AccountKey {
	if req.CurrentKey != "" {
		return req.CurrentKey
	}
	return state.ActiveKey
}

func resolveEffectivePool(state domain.StoreState, req EvalRequest) domain.QuotaPool {
	if req.TargetPool != "" {
		return req.TargetPool
	}
	model := strings.TrimSpace(req.TargetModel)
	if model != "" {
		if p := (domain.QuotaSnapshot{}).InferPoolForModel(model); p != domain.PoolOther {
			return p
		}
		for _, acc := range state.Accounts {
			if acc.Quota == nil {
				continue
			}
			if p := acc.Quota.InferPoolForModel(model); p != domain.PoolOther {
				return p
			}
		}
	}
	return state.Policy.TargetPool
}

func resolveMode(m domain.SwitchMode) domain.SwitchMode {
	if m.IsValid() {
		return m
	}
	return domain.SwitchHighestRemaining
}

func findSkipReason(ranked []scoredCandidate, key domain.AccountKey) string {
	if key == "" {
		return ""
	}
	for _, c := range ranked {
		if c.score.Key == key {
			return c.score.SkipReason
		}
	}
	return ""
}

func findEarliestReset(ranked []scoredCandidate) *time.Time {
	var earliest *time.Time
	for _, c := range ranked {
		if c.blockReset == nil {
			continue
		}
		if earliest == nil || c.blockReset.Before(*earliest) {
			earliest = copyTimePtr(c.blockReset)
		}
	}
	return earliest
}

func blockedQuotaReset(hasPoolData bool, rem, threshold float64, poolReset *time.Time) *time.Time {
	if !hasPoolData || (rem > 0 && rem >= threshold) {
		return nil
	}
	return copyTimePtr(poolReset)
}

func laterTime(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.After(*a):
		return b
	default:
		return a
	}
}

func copyTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

var (
	quotaExhaustedSubstrings = []string{
		"resource_exhausted",
		"quota_exhausted",
		"quota exceeded",
		"rate limit exceeded",
		"rate_limit_exceeded",
		"too many requests",
		"model_capacity_exhausted",
		"exhausted your capacity",
		"usage limit reached",
		"individual quota reached",
		"weekly limit",
		"weekly quota",
		"daily limit",
		"free tier limit",
		"5-hour",
		"spend-cap",
		"prepaid-balance",
		"insufficient_g1_credits",
	}
	http429Pattern     = regexp.MustCompile(`(?:^|[^0-9a-zA-Z_-])429(?:[^0-9a-zA-Z_-]|$)`)
	goDurationPattern  = regexp.MustCompile(`(?i)(?:resets?\s+(?:in|after)|retry[-_\s]*(?:after|in|delay)|try\s+again\s+in|available\s+in)"?\s*[:=]?\s*"?((?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)\s*)+)(?:[^a-zA-Z]|$)`)
	retryAfterSecRegex = regexp.MustCompile(`(?i)retry[-_\s]*after"?\s*[:=]\s*"?(\d+)"?(?:\s|$|[,;}])`)
	humanDurationRegex = regexp.MustCompile(`(?i)(?:resets?\s+(?:in|after)|retry[-_\s]*(?:after|in)|try\s+again\s+in|available\s+in)\s+((?:\d+\s*(?:days?|hours?|hrs?|minutes?|mins?|seconds?|secs?)(?:[\s,]+(?:and\s+)?)?)+)`)
	humanUnitPairRegex = regexp.MustCompile(`(?i)(\d+)\s*(days?|hours?|hrs?|minutes?|mins?|seconds?|secs?)`)
)

// IsQuotaExhaustedError classifies error text from agy/CloudCode as quota exhaustion
// and extracts an optional retry/reset duration hint if present.
func IsQuotaExhaustedError(text string) (bool, *time.Duration) {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false, nil
	}

	matched := http429Pattern.MatchString(lower)
	if !matched {
		for _, sub := range quotaExhaustedSubstrings {
			if strings.Contains(lower, sub) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return false, nil
	}

	if d := extractRetryDuration(text); d > 0 {
		return true, &d
	}
	return true, nil
}

func extractRetryDuration(text string) time.Duration {
	if m := humanDurationRegex.FindStringSubmatch(text); len(m) == 2 {
		var total time.Duration
		for _, pair := range humanUnitPairRegex.FindAllStringSubmatch(m[1], -1) {
			if len(pair) != 3 {
				continue
			}
			n, err := strconv.Atoi(pair[1])
			if err != nil || n <= 0 {
				continue
			}
			unit := strings.ToLower(pair[2])
			switch {
			case strings.HasPrefix(unit, "day"):
				total += time.Duration(n) * 24 * time.Hour
			case strings.HasPrefix(unit, "hour"), strings.HasPrefix(unit, "hr"):
				total += time.Duration(n) * time.Hour
			case strings.HasPrefix(unit, "min"):
				total += time.Duration(n) * time.Minute
			case strings.HasPrefix(unit, "sec"):
				total += time.Duration(n) * time.Second
			}
		}
		if total > 0 {
			return total
		}
	}
	if m := goDurationPattern.FindStringSubmatch(text); len(m) == 2 {
		compact := strings.Join(strings.Fields(strings.ToLower(m[1])), "")
		compact = strings.TrimRight(compact, `.,;:"')}]`)
		if d, err := time.ParseDuration(compact); err == nil && d > 0 {
			return d
		}
	}
	if m := retryAfterSecRegex.FindStringSubmatch(text); len(m) == 2 {
		if sec, err := strconv.Atoi(m[1]); err == nil && sec > 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return 0
}

// MarkAccountCooldown transitions acc to HealthCooldown until resetAt (when in the future)
// or now + fallback otherwise.
func MarkAccountCooldown(acc *domain.Account, resetAt *time.Time, reason string, fallback time.Duration, now time.Time) {
	if acc == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	var until time.Time
	if resetAt != nil && resetAt.After(now) {
		until = resetAt.UTC()
	} else if fallback > 0 {
		until = now.Add(fallback)
	} else {
		until = now.Add(domain.DefaultSelectionPolicy().CooldownDefault)
	}

	acc.Health = domain.AccountHealth{
		Status:        domain.HealthCooldown,
		Reason:        strings.TrimSpace(reason),
		CooldownUntil: &until,
		UpdatedAt:     now,
	}
}

// MarkPoolExhausted zeroes cached remaining fractions for pool in acc.Quota so offline views reflect exhaustion immediately.
func MarkPoolExhausted(acc *domain.Account, pool domain.QuotaPool, resetAt *time.Time) {
	if acc == nil || acc.Quota == nil || pool == "" || pool == domain.PoolOther {
		return
	}
	snap := *acc.Quota
	changed := false

	if len(snap.Buckets) > 0 {
		buckets := slices.Clone(snap.Buckets)
		var has5h, hasWeekly bool
		for _, b := range buckets {
			if b.Pool != pool {
				continue
			}
			switch b.Window {
			case domain.Window5h:
				has5h = true
			case domain.WindowWeekly:
				hasWeekly = true
			}
		}
		only5h := has5h && hasWeekly && resetAt != nil && !acc.Health.UpdatedAt.IsZero() &&
			resetAt.After(acc.Health.UpdatedAt) && resetAt.Sub(acc.Health.UpdatedAt) <= 6*time.Hour

		for i := range buckets {
			if buckets[i].Pool != pool {
				continue
			}
			if only5h && buckets[i].Window != domain.Window5h {
				continue
			}
			buckets[i].RemainingFraction = 0
			if resetAt != nil {
				buckets[i].ResetAt = copyTimePtr(resetAt)
			}
			changed = true
		}
		snap.Buckets = buckets
	}

	if len(snap.Models) > 0 {
		models := slices.Clone(snap.Models)
		for i := range models {
			inferred := snap.InferPoolForModel(models[i].ModelID)
			if inferred == domain.PoolOther && models[i].DisplayName != "" {
				inferred = domain.ClassifyPool(models[i].DisplayName)
			}
			if inferred != pool {
				continue
			}
			models[i].RemainingFraction = 0
			if resetAt != nil {
				models[i].ResetAt = copyTimePtr(resetAt)
			}
			changed = true
		}
		snap.Models = models
	}

	if changed {
		acc.Quota = &snap
	}
}
