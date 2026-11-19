package domain

import "time"

// SwitchMode determines how candidate accounts are ranked during selection.
type SwitchMode string

const (
	SwitchHighestRemaining SwitchMode = "highest_remaining"
	SwitchFillFirst        SwitchMode = "fill_first"
	SwitchRoundRobin       SwitchMode = "round_robin"
	SwitchPriority         SwitchMode = "priority"
)

// IsValid reports whether m is a recognized SwitchMode value.
func (m SwitchMode) IsValid() bool {
	switch m {
	case SwitchHighestRemaining, SwitchFillFirst, SwitchRoundRobin, SwitchPriority:
		return true
	default:
		return false
	}
}

// SelectionPolicy configures automatic account selection and refresh thresholds.
type SelectionPolicy struct {
	Mode                  SwitchMode    `json:"mode"`
	TargetPool            QuotaPool     `json:"target_pool,omitempty"`
	MinRemainingThreshold float64       `json:"min_remaining_threshold"`
	CooldownDefault       time.Duration `json:"cooldown_default"`
	RefreshSkew           time.Duration `json:"refresh_skew"`
}

// DefaultSelectionPolicy returns the baseline policy for account selection and token refresh.
func DefaultSelectionPolicy() SelectionPolicy {
	return SelectionPolicy{
		Mode:                  SwitchHighestRemaining,
		MinRemainingThreshold: 0.05,
		CooldownDefault:       5 * time.Minute,
		RefreshSkew:           5 * time.Minute,
	}
}

// SwitchOutcome describes the result of an account selection evaluation.
type SwitchOutcome string

const (
	OutcomeKeepCurrent SwitchOutcome = "keep_current"
	OutcomeSwitched    SwitchOutcome = "switched"
	OutcomeNoneReady   SwitchOutcome = "none_ready"
)

// SwitchDecision captures the selector's recommendation before persisting or applying it.
type SwitchDecision struct {
	Outcome            SwitchOutcome `json:"outcome"`
	FromKey            AccountKey    `json:"from_key,omitempty"`
	ToKey              AccountKey    `json:"to_key,omitempty"`
	Reason             string        `json:"reason,omitempty"`
	CandidateRemaining float64       `json:"candidate_remaining,omitempty"`
	Pool               QuotaPool     `json:"pool,omitempty"`
	EarliestReset      *time.Time    `json:"earliest_reset,omitempty"`
}

// SwitchAuditEntry records the last executed account switch decision in StoreState.
type SwitchAuditEntry struct {
	At      time.Time     `json:"at"`
	Outcome SwitchOutcome `json:"outcome"`
	FromKey AccountKey    `json:"from_key,omitempty"`
	ToKey   AccountKey    `json:"to_key,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Pool    QuotaPool     `json:"pool,omitempty"`
	Trigger string        `json:"trigger,omitempty"`
}
