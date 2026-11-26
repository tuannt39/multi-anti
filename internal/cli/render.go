package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
)

const (
	defaultBarWidth = 10
	maxCellTextLen  = 72
)

// HealthView is the redacted JSON representation of an account's health state.
type HealthView struct {
	Status            domain.HealthStatus `json:"status"`
	EffectiveStatus   domain.HealthStatus `json:"effective_status"`
	Reason            string              `json:"reason,omitempty"`
	CooldownUntil     *time.Time          `json:"cooldown_until,omitempty"`
	CooldownRemaining string              `json:"cooldown_remaining,omitempty"`
	UpdatedAt         time.Time           `json:"updated_at,omitzero"`
}

// QuotaBucketView is the JSON representation of a single quota pool bucket.
type QuotaBucketView struct {
	GroupID           string             `json:"group_id,omitempty"`
	DisplayName       string             `json:"display_name,omitempty"`
	Pool              domain.QuotaPool   `json:"pool"`
	Window            domain.QuotaWindow `json:"window"`
	RemainingFraction float64            `json:"remaining_fraction"`
	RemainingPercent  int                `json:"remaining_percent"`
	ResetAt           *time.Time         `json:"reset_at,omitempty"`
}

// ModelQuotaView is the JSON representation of per-model quota availability.
type ModelQuotaView struct {
	ModelID           string           `json:"model_id"`
	DisplayName       string           `json:"display_name,omitempty"`
	Pool              domain.QuotaPool `json:"pool"`
	RemainingFraction float64          `json:"remaining_fraction"`
	RemainingPercent  int              `json:"remaining_percent"`
	ResetAt           *time.Time       `json:"reset_at,omitempty"`
	SupportsThinking  bool             `json:"supports_thinking,omitempty"`
}

// QuotaSnapshotView is the JSON representation of an account's quota snapshot.
type QuotaSnapshotView struct {
	FetchedAt        time.Time               `json:"fetched_at"`
	Source           domain.QuotaSource      `json:"source,omitempty"`
	EndpointHost     string                  `json:"endpoint_host,omitempty"`
	Tier             domain.SubscriptionTier `json:"tier"`
	Credits          []domain.CreditInfo     `json:"credits,omitempty"`
	Buckets          []QuotaBucketView       `json:"buckets,omitempty"`
	Models           []ModelQuotaView        `json:"models,omitempty"`
	SummaryForbidden bool                    `json:"summary_forbidden,omitempty"`
	FetchError       string                  `json:"fetch_error,omitempty"`
}

// AccountView is a strictly redacted view of domain.Account without any OAuth tokens.
type AccountView struct {
	Key              domain.AccountKey       `json:"key"`
	Email            string                  `json:"email,omitempty"`
	AccountID        string                  `json:"account_id,omitempty"`
	DisplayName      string                  `json:"display_name,omitempty"`
	Active           bool                    `json:"active"`
	Priority         int                     `json:"priority"`
	Health           HealthView              `json:"health"`
	Tier             domain.SubscriptionTier `json:"tier"`
	PrimaryRemaining *float64                `json:"primary_remaining,omitempty"`
	PrimaryResetAt   *time.Time              `json:"primary_reset_at,omitempty"`
	HasRefreshToken  bool                    `json:"has_refresh_token"`
	HasAccessToken   bool                    `json:"has_access_token"`
	TokenExpiry      *time.Time              `json:"token_expiry,omitempty"`
	AddedAt          time.Time               `json:"added_at,omitzero"`
	LastUsedAt       *time.Time              `json:"last_used_at,omitempty"`
	Quota            *QuotaSnapshotView      `json:"quota,omitempty"`
}

// PolicyView is the JSON representation of domain.SelectionPolicy with human-readable durations.
type PolicyView struct {
	Mode                  domain.SwitchMode `json:"mode"`
	TargetPool            domain.QuotaPool  `json:"target_pool,omitempty"`
	MinRemainingThreshold float64           `json:"min_remaining_threshold"`
	CooldownDefault       string            `json:"cooldown_default"`
	RefreshSkew           string            `json:"refresh_skew"`
}

// AccountsListView is the redacted JSON output of `accounts`.
type AccountsListView struct {
	ActiveKey domain.AccountKey `json:"active_key,omitempty"`
	Policy    PolicyView        `json:"policy"`
	Accounts  []AccountView     `json:"accounts"`
}

// ImportResultView is the redacted JSON output of `import` and `login`.
type ImportResultView struct {
	ActiveKey domain.AccountKey `json:"active_key,omitempty"`
	Imported  []AccountView     `json:"imported"`
	Warnings  []string          `json:"warnings,omitempty"`
}

// QuotaAccountView combines ranked selection status and redacted quota details for one account.
type QuotaAccountView struct {
	Rank             int                     `json:"rank"`
	Key              domain.AccountKey       `json:"key"`
	Email            string                  `json:"email,omitempty"`
	DisplayName      string                  `json:"display_name,omitempty"`
	Active           bool                    `json:"active"`
	Eligible         bool                    `json:"eligible"`
	SkipReason       string                  `json:"skip_reason,omitempty"`
	Priority         int                     `json:"priority"`
	Health           HealthView              `json:"health"`
	Tier             domain.SubscriptionTier `json:"tier"`
	Remaining        *float64                `json:"remaining,omitempty"`
	RemainingPercent *int                    `json:"remaining_percent,omitempty"`
	ResetAt          *time.Time              `json:"reset_at,omitempty"`
	RefreshedAuth    bool                    `json:"refreshed_auth,omitempty"`
	Error            string                  `json:"error,omitempty"`
	Quota            *QuotaSnapshotView      `json:"quota,omitempty"`
}

// QuotaReportView is the redacted JSON output of `quota`.
type QuotaReportView struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Pool        domain.QuotaPool   `json:"pool,omitempty"`
	Refreshed   bool               `json:"refreshed"`
	ActiveKey   domain.AccountKey  `json:"active_key,omitempty"`
	Accounts    []QuotaAccountView `json:"accounts"`
}

// SwitchResultView is the redacted JSON output of `switch` / `next`.
type SwitchResultView struct {
	Outcome   domain.SwitchOutcome `json:"outcome"`
	FromKey   domain.AccountKey    `json:"from_key,omitempty"`
	ToKey     domain.AccountKey    `json:"to_key,omitempty"`
	Pool      domain.QuotaPool     `json:"pool,omitempty"`
	Reason    string               `json:"reason,omitempty"`
	Remaining *float64             `json:"remaining,omitempty"`
	Account   *AccountView         `json:"account,omitempty"`
}

// DoctorStatus is the severity of a single doctor check.
type DoctorStatus string

const (
	DoctorOK   DoctorStatus = "ok"
	DoctorWarn DoctorStatus = "warn"
	DoctorFail DoctorStatus = "fail"
	DoctorInfo DoctorStatus = "info"
)

// DoctorCheckView reports a single diagnostic check outcome.
type DoctorCheckView struct {
	Name    string       `json:"name"`
	Status  DoctorStatus `json:"status"`
	Summary string       `json:"summary"`
	Detail  string       `json:"detail,omitempty"`
}

// DoctorReportView is the redacted JSON output of `doctor`.
type DoctorReportView struct {
	Healthy  bool              `json:"healthy"`
	AgyBin   string            `json:"agy_bin,omitempty"`
	AgyVer   string            `json:"agy_version,omitempty"`
	Paths    DoctorPathsView   `json:"paths"`
	Plugin   hook.PluginStatus `json:"plugin"`
	Accounts AccountsCountView `json:"accounts"`
	Checks   []DoctorCheckView `json:"checks"`
}

// DoctorPathsView lists resolved filesystem paths without leaking credentials.
type DoctorPathsView struct {
	DataDir      string `json:"data_dir"`
	HomeDir      string `json:"home_dir"`
	StateFile    string `json:"state_file"`
	NativeToken  string `json:"native_token"`
	AgySettings  string `json:"agy_settings"`
	NativePlugin string `json:"native_plugin"`
}

// AccountsCountView summarizes account counts by health state.
type AccountsCountView struct {
	Total       int               `json:"total"`
	Ready       int               `json:"ready"`
	Cooldown    int               `json:"cooldown"`
	NeedsReauth int               `json:"needs_reauth"`
	Disabled    int               `json:"disabled"`
	ActiveKey   domain.AccountKey `json:"active_key,omitempty"`
}

func buildPolicyView(p domain.SelectionPolicy) PolicyView {
	return PolicyView{
		Mode:                  p.Mode,
		TargetPool:            p.TargetPool,
		MinRemainingThreshold: p.MinRemainingThreshold,
		CooldownDefault:       p.CooldownDefault.String(),
		RefreshSkew:           p.RefreshSkew.String(),
	}
}

func buildHealthView(h domain.AccountHealth, now time.Time) HealthView {
	eff := h.EffectiveStatus(now)
	view := HealthView{
		Status:          h.Status,
		EffectiveStatus: eff,
		Reason:          h.Reason,
		CooldownUntil:   copyTimePtr(h.CooldownUntil),
		UpdatedAt:       h.UpdatedAt,
	}
	if eff == domain.HealthCooldown && h.CooldownUntil != nil && h.CooldownUntil.After(now) {
		view.CooldownRemaining = formatDurationShort(h.CooldownUntil.Sub(now))
	}
	return view
}

func buildQuotaSnapshotView(q *domain.QuotaSnapshot, includeModels bool, filterPool domain.QuotaPool, now time.Time) *QuotaSnapshotView {
	if q == nil {
		return nil
	}
	view := &QuotaSnapshotView{
		FetchedAt:        q.FetchedAt,
		Source:           q.Source,
		EndpointHost:     q.EndpointHost,
		Tier:             q.Tier,
		Credits:          slices.Clone(q.Credits),
		SummaryForbidden: q.SummaryForbidden,
		FetchError:       q.FetchError,
	}
	for _, b := range q.Buckets {
		if filterPool != "" && b.Pool != filterPool {
			continue
		}
		rem, resetAt := b.EffectiveAt(now)
		view.Buckets = append(view.Buckets, QuotaBucketView{
			GroupID:           b.GroupID,
			DisplayName:       b.DisplayName,
			Pool:              b.Pool,
			Window:            b.Window,
			RemainingFraction: clampFraction(rem),
			RemainingPercent:  roundPercent(rem),
			ResetAt:           copyTimePtr(resetAt),
		})
	}
	if includeModels || len(q.Buckets) == 0 {
		for _, m := range q.Models {
			pool := q.InferPoolForModel(m.ModelID)
			if pool == domain.PoolOther && m.DisplayName != "" {
				pool = (domain.QuotaSnapshot{}).InferPoolForModel(m.DisplayName)
			}
			if filterPool != "" && pool != filterPool {
				continue
			}
			rem, resetAt := m.EffectiveAt(now)
			view.Models = append(view.Models, ModelQuotaView{
				ModelID:           m.ModelID,
				DisplayName:       m.DisplayName,
				Pool:              pool,
				RemainingFraction: clampFraction(rem),
				RemainingPercent:  roundPercent(rem),
				ResetAt:           copyTimePtr(resetAt),
				SupportsThinking:  m.SupportsThinking,
			})
		}
	}
	return view
}

func buildAccountView(acc domain.Account, activeKey domain.AccountKey, pool domain.QuotaPool, includeQuota bool, now time.Time) AccountView {
	tier := domain.TierUnknown
	var remPtr *float64
	var resetPtr *time.Time
	var qView *QuotaSnapshotView

	if acc.Quota != nil {
		tier = acc.Quota.Tier
		if rem, resetAt, ok := acc.Quota.PoolRemainingAt(pool, now); ok {
			clamped := clampFraction(rem)
			remPtr = &clamped
			resetPtr = copyTimePtr(resetAt)
		}
		if includeQuota {
			qView = buildQuotaSnapshotView(acc.Quota, false, pool, now)
		}
	}

	var expiryPtr *time.Time
	if !acc.Creds.Expiry.IsZero() {
		t := acc.Creds.Expiry.UTC()
		expiryPtr = &t
	}

	return AccountView{
		Key:              acc.Key,
		Email:            acc.Email,
		AccountID:        acc.AccountID,
		DisplayName:      acc.DisplayName,
		Active:           acc.Key == activeKey,
		Priority:         acc.Priority,
		Health:           buildHealthView(acc.Health, now),
		Tier:             tier,
		PrimaryRemaining: remPtr,
		PrimaryResetAt:   resetPtr,
		HasRefreshToken:  strings.TrimSpace(acc.Creds.RefreshToken) != "",
		HasAccessToken:   strings.TrimSpace(acc.Creds.AccessToken) != "",
		TokenExpiry:      expiryPtr,
		AddedAt:          acc.AddedAt,
		LastUsedAt:       copyTimePtr(acc.LastUsedAt),
		Quota:            qView,
	}
}

func buildQuotaReportView(
	state domain.StoreState,
	ranked []selector.CandidateScore,
	results []quota.AccountRefreshResult,
	targetPool domain.QuotaPool,
	includeModels bool,
	refreshed bool,
	now time.Time,
) QuotaReportView {
	resByKey := make(map[domain.AccountKey]quota.AccountRefreshResult, len(results))
	for _, r := range results {
		resByKey[r.Key] = r
	}

	report := QuotaReportView{
		GeneratedAt: now,
		Pool:        targetPool,
		Refreshed:   refreshed,
		ActiveKey:   state.ActiveKey,
		Accounts:    make([]QuotaAccountView, 0, len(ranked)),
	}

	for i, c := range ranked {
		acc, ok := state.Accounts[c.Key]
		if !ok {
			continue
		}
		tier := domain.TierUnknown
		var fetchErr string
		if acc.Quota != nil {
			tier = acc.Quota.Tier
			fetchErr = acc.Quota.FetchError
		}
		var refreshedAuth bool
		if res, hasRes := resByKey[c.Key]; hasRes {
			refreshedAuth = res.RefreshedAuth
			if res.Err != nil {
				fetchErr = res.Err.Error()
			}
		}

		var remPtr *float64
		var pctPtr *int
		hasData := acc.Quota != nil && (len(acc.Quota.Buckets) > 0 || len(acc.Quota.Models) > 0)
		if hasData {
			if rem, resetAt, ok := acc.Quota.PoolRemainingAt(targetPool, now); ok {
				clamped := clampFraction(rem)
				pct := roundPercent(clamped)
				remPtr = &clamped
				pctPtr = &pct
				if c.ResetAt == nil && resetAt != nil {
					c.ResetAt = copyTimePtr(resetAt)
				}
			}
		}

		report.Accounts = append(report.Accounts, QuotaAccountView{
			Rank:             i + 1,
			Key:              acc.Key,
			Email:            acc.Email,
			DisplayName:      acc.DisplayName,
			Active:           acc.Key == state.ActiveKey,
			Eligible:         c.Eligible,
			SkipReason:       c.SkipReason,
			Priority:         acc.Priority,
			Health:           buildHealthView(acc.Health, now),
			Tier:             tier,
			Remaining:        remPtr,
			RemainingPercent: pctPtr,
			ResetAt:          copyTimePtr(c.ResetAt),
			RefreshedAuth:    refreshedAuth,
			Error:            fetchErr,
			Quota:            buildQuotaSnapshotView(acc.Quota, includeModels, targetPool, now),
		})
	}
	return report
}

type nativeTokenSummary struct {
	Key     domain.AccountKey
	Label   string
	Present bool
}

func renderAccountsTable(w io.Writer, state domain.StoreState, native nativeTokenSummary, now time.Time) {
	if len(state.Accounts) == 0 {
		fmt.Fprintln(w, "No managed accounts configured. Run 'multi-anti login' or 'multi-anti import'.")
		if native.Present {
			fmt.Fprintf(w, "\nNote: native agy token holds %s (not managed; run 'multi-anti import --native' to add it)\n", native.Label)
		}
		return
	}

	keys := sortedAccountKeys(state.Accounts)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ACT\tACCOUNT\tTIER\tHEALTH\tPRIO\tGEMINI 5h/wk\tCLAUDE/GPT 5h/wk\tLAST USED")
	for _, k := range keys {
		acc := state.Accounts[k]
		act := ""
		if k == state.ActiveKey {
			act = "*"
		}
		label := formatAccountLabel(acc)
		tier := formatTier(acc.Quota)
		health := formatHealthLabel(acc.Health, now)
		gemCell := hook.FormatDualWindowCell(acc.Quota, domain.PoolGemini, now)
		cpCell := hook.FormatDualWindowCell(acc.Quota, domain.Pool3P, now)
		lastUsed := formatTimeRelative(acc.LastUsedAt, now)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", act, label, tier, health, acc.Priority, gemCell, cpCell, lastUsed)
	}
	_ = tw.Flush()

	if native.Present {
		if _, managed := state.Accounts[native.Key]; !managed {
			fmt.Fprintf(w, "\nNote: native agy token holds %s (not managed; run 'multi-anti import --native' to add it)\n", native.Label)
		} else if state.ActiveKey != "" && native.Key != state.ActiveKey {
			fmt.Fprintf(w, "\nNote: native agy token holds %s while active_key is %s\n", native.Label, state.ActiveKey)
		}
	}
}

func renderQuotaReport(w io.Writer, report QuotaReportView, includeModels bool, now time.Time) {
	if len(report.Accounts) == 0 {
		fmt.Fprintln(w, "No managed accounts configured. Run 'multi-anti login' or 'multi-anti import'.")
		return
	}

	poolLabel := "all"
	if report.Pool != "" {
		poolLabel = string(report.Pool)
	}
	modeLabel := "cached"
	if report.Refreshed {
		modeLabel = "live"
	}
	fmt.Fprintf(w, "Quota (%s, pool=%s, %s)\n", modeLabel, poolLabel, now.UTC().Format("15:04:05Z"))

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RANK\tACT\tACCOUNT\tTIER\tHEALTH\tQUOTA\tRESET\tCREDITS\tNOTE")
	for _, a := range report.Accounts {
		act := ""
		if a.Active {
			act = "*"
		}
		label := formatAccountLabelRaw(a.Key, a.Email, a.DisplayName)
		tier := string(a.Tier)
		if tier == "" || tier == string(domain.TierUnknown) {
			tier = "-"
		}
		health := formatHealthViewLabel(a.Health)
		quotaCell := "-"
		if a.RemainingPercent != nil && a.Remaining != nil {
			quotaCell = fmt.Sprintf("%s %3d%%", renderProgressBar(*a.Remaining, defaultBarWidth), *a.RemainingPercent)
		}
		resetCell := formatResetCountdown(a.ResetAt, now)
		if a.Remaining != nil && *a.Remaining >= 0.9999 {
			resetCell = "-"
		}
		creditsCell := "-"
		if a.Quota != nil && len(a.Quota.Credits) > 0 {
			creditsCell = formatCredits(a.Quota.Credits)
		}
		note := a.SkipReason
		if a.Error != "" {
			if strings.Contains(a.Error, "missing OAuth client_id") {
				note = "stale (set OAuth client_id to refresh offline)"
			} else {
				note = "err: " + truncateText(sanitizeSingleLine(a.Error), maxCellTextLen)
			}
		}
		if note == "" {
			note = "-"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Rank, act, label, tier, health, quotaCell, resetCell, creditsCell, note)
	}
	_ = tw.Flush()

	renderQuotaBreakdown(w, report.Accounts, now)

	if includeModels {
		for _, a := range report.Accounts {
			if a.Quota == nil || len(a.Quota.Models) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n  Models for %s:\n", formatAccountLabelRaw(a.Key, a.Email, a.DisplayName))
			mtw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			fmt.Fprintln(mtw, "  MODEL\tPOOL\tQUOTA\tRESET")
			for _, m := range a.Quota.Models {
				name := m.ModelID
				if m.DisplayName != "" && !strings.EqualFold(m.DisplayName, m.ModelID) {
					name = fmt.Sprintf("%s (%s)", m.ModelID, m.DisplayName)
				}
				bar := fmt.Sprintf("%s %3d%%", renderProgressBar(m.RemainingFraction, defaultBarWidth), m.RemainingPercent)
				fmt.Fprintf(mtw, "  %s\t%s\t%s\t%s\n", name, m.Pool, bar, formatResetCountdown(m.ResetAt, now))
			}
			_ = mtw.Flush()
		}
	}
}

type quotaPoolLabel struct {
	Pool  domain.QuotaPool
	Label string
}

var quotaPoolLabels = []quotaPoolLabel{
	{Pool: domain.PoolGemini, Label: "gemini"},
	{Pool: domain.Pool3P, Label: "claude/gpt"},
	{Pool: domain.PoolOther, Label: "other"},
}

func poolDisplayLabel(pool domain.QuotaPool) string {
	for _, entry := range quotaPoolLabels {
		if entry.Pool == pool {
			return entry.Label
		}
	}
	return string(pool)
}

func renderQuotaBreakdown(w io.Writer, accounts []QuotaAccountView, now time.Time) {
	for _, a := range accounts {
		if a.Quota == nil || (len(a.Quota.Buckets) == 0 && len(a.Quota.Models) == 0) {
			continue
		}

		header := formatAccountLabelRaw(a.Key, a.Email, a.DisplayName)
		if a.Tier != "" && a.Tier != domain.TierUnknown {
			header += " (" + string(a.Tier) + ")"
		}
		if a.Active {
			header += " [*]"
		}
		fmt.Fprintf(w, "\n  %s\n", header)

		bt := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		if len(a.Quota.Buckets) > 0 {
			for _, spec := range quotaPoolLabels {
				poolBuckets := filterQuotaBucketsByPool(a.Quota.Buckets, spec.Pool)
				if len(poolBuckets) == 0 {
					continue
				}
				sortQuotaBucketsForDisplay(poolBuckets)
				cells := make([]string, 0, len(poolBuckets))
				for _, b := range poolBuckets {
					cells = append(cells, formatCompactBucketCell(b, now))
				}
				fmt.Fprintf(bt, "    %s\t%s\n", spec.Label, strings.Join(cells, "  |  "))
			}
		} else {
			for _, m := range a.Quota.Models {
				name := strings.TrimSpace(m.DisplayName)
				if name == "" {
					name = m.ModelID
				}
				clamped := clampFraction(m.RemainingFraction)
				fmt.Fprintf(bt, "    %s\t%s\t%s %6.2f%%\t%s\n",
					name,
					poolDisplayLabel(m.Pool),
					renderProgressBar(clamped, defaultBarWidth),
					clamped*100,
					formatCompactReset(clamped, m.ResetAt, now))
			}
		}
		_ = bt.Flush()
	}
}

func formatCompactBucketCell(b QuotaBucketView, now time.Time) string {
	clamped := clampFraction(b.RemainingFraction)
	return fmt.Sprintf("%s %s %6.2f%% %s",
		quotaWindowTag(b),
		renderProgressBar(clamped, defaultBarWidth),
		clamped*100,
		formatCompactReset(clamped, b.ResetAt, now))
}

func quotaWindowTag(b QuotaBucketView) string {
	switch b.Window {
	case domain.Window5h:
		return "5h"
	case domain.WindowWeekly:
		return "wk"
	case domain.WindowUnknown:
		if s := strings.TrimSpace(b.DisplayName); s != "" {
			return s
		}
		if s := strings.TrimSpace(b.GroupID); s != "" {
			return s
		}
	}
	return "quota"
}

func formatCompactReset(rem float64, resetAt *time.Time, now time.Time) string {
	if rem >= 0.9999 || resetAt == nil || resetAt.IsZero() {
		return "-"
	}
	if !resetAt.After(now) {
		return "due"
	}
	d := resetAt.Sub(now)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(math.Ceil(d.Seconds())))
	}
	totalMins := int(d / time.Minute)
	hours := totalMins / 60
	mins := totalMins % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func filterQuotaBucketsByPool(buckets []QuotaBucketView, pool domain.QuotaPool) []QuotaBucketView {
	var out []QuotaBucketView
	for _, b := range buckets {
		if b.Pool == pool {
			out = append(out, b)
		}
	}
	return out
}

func sortQuotaBucketsForDisplay(buckets []QuotaBucketView) {
	slices.SortFunc(buckets, func(a, b QuotaBucketView) int {
		ra, rb := quotaWindowDisplayOrder(a.Window), quotaWindowDisplayOrder(b.Window)
		if ra != rb {
			return ra - rb
		}
		if c := strings.Compare(a.DisplayName, b.DisplayName); c != 0 {
			return c
		}
		return strings.Compare(a.GroupID, b.GroupID)
	})
}

func quotaWindowDisplayOrder(w domain.QuotaWindow) int {
	switch w {
	case domain.Window5h:
		return 0
	case domain.WindowWeekly:
		return 1
	default:
		return 2
	}
}

func renderPolicy(w io.Writer, p domain.SelectionPolicy) {
	pool := "all"
	if p.TargetPool != "" {
		pool = string(p.TargetPool)
	}
	fmt.Fprintf(w, "mode:          %s\n", p.Mode)
	fmt.Fprintf(w, "target_pool:   %s\n", pool)
	fmt.Fprintf(w, "threshold:     %.2f (%.0f%%)\n", p.MinRemainingThreshold, p.MinRemainingThreshold*100)
	fmt.Fprintf(w, "cooldown:      %s\n", p.CooldownDefault)
	fmt.Fprintf(w, "refresh_skew:  %s\n", p.RefreshSkew)
}

func renderPluginStatus(w io.Writer, status hook.PluginStatus) {
	fmt.Fprintf(w, "plugin_dir:          %s\n", status.PluginDir)
	fmt.Fprintf(w, "installed:           %t\n", status.Installed)
	fmt.Fprintf(w, "disabled_in_config:  %t\n", status.DisabledInConfig)
	if len(status.MissingFiles) > 0 {
		fmt.Fprintf(w, "missing_files:       %s\n", strings.Join(status.MissingFiles, ", "))
	}
	fmt.Fprintf(w, "statusline_enabled:  %t\n", status.StatusLineEnabled)
	if status.StatusLineCommand != "" {
		fmt.Fprintf(w, "statusline_command:  %s\n", status.StatusLineCommand)
	}
}

func renderDoctorReport(w io.Writer, report DoctorReportView) {
	overall := "PASS"
	if !report.Healthy {
		overall = "ISSUES FOUND"
	}
	fmt.Fprintf(w, "multi-anti doctor: %s\n", overall)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, c := range report.Checks {
		tag := "[" + strings.ToUpper(string(c.Status)) + "]"
		detail := ""
		if c.Detail != "" {
			detail = " (" + c.Detail + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s%s\n", tag, c.Name, c.Summary, detail)
	}
	_ = tw.Flush()
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func renderProgressBar(fraction float64, width int) string {
	if width <= 0 {
		width = defaultBarWidth
	}
	clamped := clampFraction(fraction)
	filled := int(math.Round(clamped * float64(width)))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", width-filled) + "]"
}

func formatDurationShort(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(math.Ceil(d.Seconds())))
	}
	totalMins := int(d / time.Minute)
	days := totalMins / (60 * 24)
	hours := (totalMins % (60 * 24)) / 60
	mins := totalMins % 60

	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	case hours > 0 && mins > 0:
		return fmt.Sprintf("%dh%dm", hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

func formatTimeRelative(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	diff := now.Sub(*t)
	if diff < 0 {
		return t.UTC().Format("15:04Z")
	}
	if diff < time.Minute {
		return "just now"
	}
	return formatDurationShort(diff) + " ago"
}

func formatResetCountdown(resetAt *time.Time, now time.Time) string {
	if resetAt == nil || resetAt.IsZero() {
		return "-"
	}
	utc := resetAt.UTC()
	if !utc.After(now) {
		return "due (" + utc.Format("15:04Z") + ")"
	}
	return fmt.Sprintf("%s (%s)", formatDurationShort(utc.Sub(now)), utc.Format("15:04Z"))
}

func formatHealthLabel(h domain.AccountHealth, now time.Time) string {
	return formatHealthViewLabel(buildHealthView(h, now))
}

func formatHealthViewLabel(h HealthView) string {
	if h.EffectiveStatus == domain.HealthCooldown && h.CooldownRemaining != "" {
		return fmt.Sprintf("cooldown (%s)", h.CooldownRemaining)
	}
	return string(h.EffectiveStatus)
}

func formatTier(q *domain.QuotaSnapshot) string {
	if q == nil || q.Tier == "" || q.Tier == domain.TierUnknown {
		return "-"
	}
	return string(q.Tier)
}

func formatCredits(credits []domain.CreditInfo) string {
	parts := make([]string, 0, len(credits))
	for _, c := range credits {
		val := fmt.Sprintf("%.0f", c.Remaining)
		if math.Abs(c.Remaining-math.Round(c.Remaining)) > 0.01 {
			val = fmt.Sprintf("%.2f", c.Remaining)
		}
		if c.Unit != "" {
			val += " " + c.Unit
		}
		if c.Provider != "" {
			parts = append(parts, c.Provider+":"+val)
		} else {
			parts = append(parts, val)
		}
	}
	return truncateText(strings.Join(parts, ","), 32)
}

func formatAccountLabel(acc domain.Account) string {
	return formatAccountLabelRaw(acc.Key, acc.Email, acc.DisplayName)
}

func formatAccountLabelRaw(key domain.AccountKey, email, displayName string) string {
	base := strings.TrimSpace(email)
	if base == "" {
		base = string(key)
	}
	alias := strings.TrimSpace(displayName)
	if alias != "" && !strings.EqualFold(alias, base) && !strings.EqualFold(alias, string(key)) {
		return fmt.Sprintf("%s (%s)", base, truncateText(alias, 20))
	}
	return base
}

func sortedAccountKeys(accounts map[domain.AccountKey]domain.Account) []domain.AccountKey {
	keys := make([]domain.AccountKey, 0, len(accounts))
	for k := range accounts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func clampFraction(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func roundPercent(rem float64) int {
	return int(math.Round(clampFraction(rem) * 100))
}

func copyTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

func sanitizeSingleLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func truncateText(s string, maxLen int) string {
	if maxLen <= 3 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
