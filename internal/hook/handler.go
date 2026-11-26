package hook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

const (
	transcriptTailBytes   = 16 * 1024
	statusLineStoreBudget = 300 * time.Millisecond
	stopHookDedupWindow   = 15 * time.Second
	maxReasonLen          = 160
)

// HookInput captures the camelCase JSON payload delivered by agy on hook stdin.
type HookInput struct {
	ConversationID        string   `json:"conversationId,omitempty"`
	WorkspacePaths        []string `json:"workspacePaths,omitempty"`
	TranscriptPath        string   `json:"transcriptPath,omitempty"`
	ArtifactDirectoryPath string   `json:"artifactDirectoryPath,omitempty"`
	ModelName             string   `json:"modelName,omitempty"`
	LastUserInput         string   `json:"lastUserInput,omitempty"`
	HookEventName         string   `json:"hookEventName,omitempty"`
	CWD                   string   `json:"cwd,omitempty"`
	ExecutionNum          int      `json:"executionNum,omitempty"`
	TerminationReason     string   `json:"terminationReason,omitempty"`
	Error                 string   `json:"error,omitempty"`
	FullyIdle             bool     `json:"fullyIdle,omitempty"`
	ContinuationActive    bool     `json:"continuationActive,omitempty"`
}

// StatusLineQuotaBucket captures one quota bucket reading piped to statusLine stdin.
type StatusLineQuotaBucket struct {
	RemainingFraction *float64 `json:"remaining_fraction,omitempty"`
	ResetTime         string   `json:"reset_time,omitempty"`
	ResetInSeconds    *float64 `json:"reset_in_seconds,omitempty"`
}

// StatusLineModel captures the active model metadata piped to statusLine stdin.
type StatusLineModel struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// StatusLineInput captures the JSON payload piped by agy to the statusLine command.
type StatusLineInput struct {
	Email          string                           `json:"email,omitempty"`
	PlanTier       string                           `json:"plan_tier,omitempty"`
	Quota          map[string]StatusLineQuotaBucket `json:"quota,omitempty"`
	AgentState     string                           `json:"agent_state,omitempty"`
	ConversationID string                           `json:"conversation_id,omitempty"`
	Model          *StatusLineModel                 `json:"model,omitempty"`
}

// SessionStartSystemMessage renders a system or user-facing markdown step on SessionStart.
type SessionStartSystemMessage struct {
	SystemMessage string         `json:"systemMessage"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// SessionStartStep represents a single step injected on SessionStart.
type SessionStartStep struct {
	SystemMessage *SessionStartSystemMessage `json:"systemMessage,omitempty"`
}

// SessionStartOutput is the JSON response emitted by the SessionStart hook.
type SessionStartOutput struct {
	InjectSteps []SessionStartStep `json:"injectSteps,omitempty"`
}

// StopOutput is the JSON response emitted by the Stop hook.
type StopOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// HandlerConfig configures a hook Handler.
type HandlerConfig struct {
	Store    store.Store
	Selector selector.Selector
	OAuth    oauth.OAuthClient
	Now      func() time.Time
}

// Handler processes agy SessionStart, Stop, and statusLine invocations.
type Handler struct {
	store    store.Store
	selector selector.Selector
	oauth    oauth.OAuthClient
	now      func() time.Time
}

// NewHandler constructs a Handler with defaults for omitted Selector or Now.
func NewHandler(cfg HandlerConfig) *Handler {
	sel := cfg.Selector
	if sel == nil {
		sel = selector.NewDefaultSelector()
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Handler{
		store:    cfg.Store,
		selector: sel,
		oauth:    cfg.OAuth,
		now:      nowFn,
	}
}

func (h *Handler) currentTime() time.Time {
	return h.now().UTC()
}

// HandleSessionStart returns user-facing status markdown for the active account without bloating model context.
func (h *Handler) HandleSessionStart(ctx context.Context, stdin []byte) ([]byte, error) {
	var input HookInput
	_ = parseJSONTolerant(stdin, &input)

	if h.store == nil {
		return marshalJSONLine(SessionStartOutput{})
	}
	now := h.currentTime()
	syncCtx, syncCancel := context.WithTimeout(ctx, statusLineStoreBudget)
	if isFileAuthSyncActive() {
		_, _, _ = quota.UpsertTokenFromFile(syncCtx, h.store, h.store.Paths().NativeAgyTokenPath(), quota.TokenSyncOptions{
			SetActive:  true,
			RecordUsed: true,
			Now:        now,
		})
	} else {
		_, _ = quota.SyncNativeTokenIfFresher(syncCtx, h.store, now)
	}
	syncCancel()

	state, err := h.store.Load(ctx)
	if err != nil || len(state.Accounts) == 0 {
		return marshalJSONLine(SessionStartOutput{})
	}

	paths := h.store.Paths()
	activeKey := resolveActiveAccountKey(paths, state)
	if acc, ok := state.Accounts[activeKey]; ok {
		needLastUsed := acc.LastUsedAt == nil || !acc.LastUsedAt.Equal(now)
		nativeMatch := os.Getenv("MULTI_ANTI_ISOLATED") != "1" && readNativeTokenKey(paths) == activeKey && state.ActiveKey != activeKey
		if needLastUsed || nativeMatch {
			updCtx, updCancel := context.WithTimeout(ctx, statusLineStoreBudget)
			if updated, updErr := h.store.Update(updCtx, func(s *domain.StoreState) error {
				cur, exists := s.Accounts[activeKey]
				if !exists {
					return errors.New("active account missing")
				}
				usedAt := now
				cur.LastUsedAt = &usedAt
				s.Accounts[activeKey] = cur
				if os.Getenv("MULTI_ANTI_ISOLATED") != "1" && readNativeTokenKey(paths) == activeKey && s.ActiveKey != activeKey {
					s.ActiveKey = activeKey
				}
				return nil
			}); updErr == nil {
				state = updated
			}
			updCancel()
		}
	}

	readyCount := countReadyAccounts(state, now)

	var md string
	if acc, ok := state.Accounts[activeKey]; ok {
		pool := resolveTargetPool(acc, state.Policy.TargetPool, input.ModelName)
		remStr := "quota n/a"
		if acc.Quota != nil {
			if rem, resetAt, hasPool := acc.Quota.PoolRemainingAt(pool, now); hasPool {
				pct := roundPercent(rem)
				remStr = fmt.Sprintf("%d%% remaining", pct)
				if pct < 100 {
					if rt, ok := domain.DescribeReset(resetAt, now, time.UTC); ok && !rt.Due {
						remStr += ", resets in " + rt.Compact
					}
				}
			}
		}
		eff := acc.Health.EffectiveStatus(now)
		status := string(eff)
		if eff == domain.HealthCooldown {
			if rt, ok := domain.DescribeReset(acc.Health.CooldownUntil, now, time.UTC); ok && !rt.Due {
				status = "cooldown " + rt.Compact
			}
		}
		md = fmt.Sprintf("**multi-anti** active: `%s` (%s, %s) | ready: %d/%d",
			displayAccount(acc), status, remStr, readyCount, len(state.Accounts))
	} else {
		md = fmt.Sprintf("**multi-anti** active: none selected | ready: %d/%d", readyCount, len(state.Accounts))
	}

	out := SessionStartOutput{
		InjectSteps: []SessionStartStep{
			{
				SystemMessage: &SessionStartSystemMessage{
					SystemMessage: "",
					Metadata: map[string]any{
						"user_markdown": md,
					},
				},
			},
		},
	}
	return marshalJSONLine(out)
}

// HandleStop checks for quota exhaustion on Stop events, cools down the failing account,
// stages the next ready account, and records a HookSwitchSignal for the launcher.
func (h *Handler) HandleStop(ctx context.Context, stdin []byte) ([]byte, error) {
	var input HookInput
	if err := parseJSONTolerant(stdin, &input); err != nil {
		return marshalStopAllow("")
	}

	exhausted, retryDur, errSnippet := detectStopQuotaError(input)
	if !exhausted || h.store == nil {
		return marshalStopAllow("")
	}

	now := h.currentTime()
	paths := h.store.Paths()
	state, err := h.store.Load(ctx)
	if err != nil || len(state.Accounts) == 0 {
		return marshalStopAllow("")
	}

	launchedKey := domain.AccountKey(strings.TrimSpace(os.Getenv("MULTI_ANTI_ACCOUNT")))
	tokenKey := readNativeTokenKey(paths)
	rootConvID := resolveRootConversationID(input.ConversationID, input.TranscriptPath)

	if msg, alreadyAcc, skip := h.detectAlreadySwitched(paths, state, input, rootConvID, launchedKey, tokenKey, now); skip {
		h.syncSkippedStopSwitch(ctx, paths, state, input, rootConvID, launchedKey, alreadyAcc, retryDur, errSnippet, now)
		return marshalStopAllow(msg)
	}

	currentKey := pickFailingAccountKey(state, launchedKey, tokenKey)
	if currentKey == "" {
		return marshalStopAllow("")
	}

	if _, err := h.store.EnsureNativeBackup(ctx); err != nil {
		return marshalStopAllow("")
	}
	_, _ = quota.SyncNativeTokenIfFresher(ctx, h.store, now)

	cooldownReason := formatCooldownReason(errSnippet)
	var curAcc domain.Account
	var decision domain.SwitchDecision
	_, err = h.store.Update(ctx, func(s *domain.StoreState) error {
		acc, ok := s.Accounts[currentKey]
		if !ok {
			return fmt.Errorf("account %q not found", currentKey)
		}
		markAccountQuotaCooldown(&acc, s.Policy, input.ModelName, retryDur, cooldownReason, now)
		usedAt := now
		acc.LastUsedAt = &usedAt
		s.Accounts[currentKey] = acc
		curAcc = acc

		decision = h.selector.Evaluate(*s, selector.EvalRequest{
			CurrentKey:  currentKey,
			TargetModel: input.ModelName,
			ForceSwitch: true,
			Now:         now,
		})
		if decision.Outcome != domain.OutcomeSwitched {
			s.LastSwitch = &domain.SwitchAuditEntry{
				At:      now,
				Outcome: decision.Outcome,
				FromKey: currentKey,
				Reason:  decision.Reason,
				Pool:    decision.Pool,
				Trigger: "hook_stop",
			}
		}
		return nil
	})
	if err != nil {
		return marshalStopAllow("")
	}

	if decision.Outcome != domain.OutcomeSwitched || decision.ToKey == "" {
		return marshalStopAllow(formatNoneReadyReason(decision, now))
	}

	targetAcc, encoded, finalDecision, ok := h.prepareStopSwitchTarget(ctx, currentKey, input.ModelName, decision, now)
	if !ok {
		return marshalStopAllow(formatNoneReadyReason(finalDecision, now))
	}

	_, err = h.store.Update(ctx, func(s *domain.StoreState) error {
		target, exists := s.Accounts[targetAcc.Key]
		if !exists {
			return fmt.Errorf("target account %q missing", targetAcc.Key)
		}
		if os.Getenv("MULTI_ANTI_ISOLATED") != "1" {
			if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), encoded, true); err != nil {
				return err
			}
		}
		usedAt := now
		target.LastUsedAt = &usedAt
		s.Accounts[targetAcc.Key] = target
		s.ActiveKey = targetAcc.Key
		s.LastSwitch = &domain.SwitchAuditEntry{
			At:      now,
			Outcome: domain.OutcomeSwitched,
			FromKey: currentKey,
			ToKey:   targetAcc.Key,
			Reason:  finalDecision.Reason,
			Pool:    finalDecision.Pool,
			Trigger: "hook_stop",
		}
		return nil
	})
	if err != nil {
		return marshalStopAllow("")
	}

	_ = WriteSwitchSignal(paths, domain.HookSwitchSignal{
		ConversationID: rootConvID,
		FromKey:        currentKey,
		ToKey:          targetAcc.Key,
		Reason:         finalDecision.Reason,
		At:             now,
	})

	return marshalStopAllow(fmt.Sprintf("multi-anti switched from %s to %s (%s)",
		displayAccount(curAcc), displayAccount(targetAcc), finalDecision.Reason))
}

// HandleStatusLine opportunistically updates cached quota fractions and returns a compact multi-line status table.
func (h *Handler) HandleStatusLine(ctx context.Context, stdin []byte) (string, error) {
	input, isJSONObj := parseStatusLineInput(stdin)
	now := h.currentTime()
	if isJSONObj && strings.TrimSpace(input.Email) == "" && !hasStatusLineQuotaReading(input.Quota) {
		if h.store != nil && isFileAuthSyncActive() {
			clearCtx, cancel := context.WithTimeout(ctx, statusLineStoreBudget)
			_, _ = quota.ClearActiveKeyIfLoggedOut(clearCtx, h.store, h.store.Paths().NativeAgyTokenPath(), "")
			cancel()
		}
		return "", nil
	}

	if h.store == nil {
		return sanitizeMultiLine(renderStatusWithoutStore(input, now)), nil
	}

	storeCtx, cancel := context.WithTimeout(ctx, statusLineStoreBudget)
	defer cancel()

	paths := h.store.Paths()
	if os.Getenv("MULTI_ANTI_ISOLATED") != "1" && strings.TrimSpace(input.Email) != "" {
		_, _, _ = quota.UpsertTokenFromFile(storeCtx, h.store, paths.NativeAgyTokenPath(), quota.TokenSyncOptions{
			ExpectedEmail: input.Email,
			SetActive:     true,
			Now:           now,
		})
	}

	state, err := h.store.Load(storeCtx)
	if err != nil {
		return sanitizeMultiLine(renderStatusWithoutStore(input, now)), nil
	}

	activeKey := resolveStatusLineAccountKey(paths, state, input.Email)
	if activeKey != "" && len(input.Quota) > 0 {
		if updatedState, updated := h.mergeStatusLineQuota(storeCtx, state, activeKey, input, now); updated {
			state = updatedState
		}
	}

	return sanitizeMultiLine(h.renderStatusLine(state, activeKey, input, now)), nil
}

func isFileAuthSyncActive() bool {
	if os.Getenv("MULTI_ANTI_ISOLATED") == "1" {
		return false
	}
	return strings.TrimSpace(os.Getenv("SSH_TTY")) != "" || os.Getenv("MULTI_ANTI_MANAGED") == "1"
}

func (h *Handler) detectAlreadySwitched(
	paths platform.Paths,
	state domain.StoreState,
	input HookInput,
	rootConvID string,
	launchedKey domain.AccountKey,
	tokenKey domain.AccountKey,
	now time.Time,
) (string, domain.Account, bool) {
	isolated := os.Getenv("MULTI_ANTI_ISOLATED") == "1"
	if !isolated && launchedKey != "" && tokenKey != "" && tokenKey != launchedKey {
		if tokAcc, ok := state.Accounts[tokenKey]; ok && tokAcc.Health.CanSelect(now) {
			return fmt.Sprintf("multi-anti: already switched to %s", displayAccount(tokAcc)), tokAcc, true
		}
	}

	if !isolated && tokenKey != "" && state.ActiveKey != "" && tokenKey != state.ActiveKey {
		if tokAcc, ok := state.Accounts[tokenKey]; ok && tokAcc.Health.CanSelect(now) {
			return fmt.Sprintf("multi-anti: already switched to %s", displayAccount(tokAcc)), tokAcc, true
		}
	}

	cids := make([]string, 0, 2)
	if r := strings.TrimSpace(rootConvID); r != "" {
		cids = append(cids, r)
	}
	if in := strings.TrimSpace(input.ConversationID); in != "" && (len(cids) == 0 || cids[0] != in) {
		cids = append(cids, in)
	}
	for _, cid := range cids {
		if sig, ok, _ := ReadSwitchSignal(paths, cid); ok && sig.ToKey != "" {
			if tokAcc, exists := state.Accounts[sig.ToKey]; exists && tokAcc.Health.CanSelect(now) {
				if (isolated && launchedKey != "" && sig.ToKey != launchedKey) ||
					(!isolated && tokenKey == sig.ToKey && !sig.At.IsZero() && now.Sub(sig.At) >= 0 && now.Sub(sig.At) <= stopHookDedupWindow) {
					return fmt.Sprintf("multi-anti: already switched to %s", displayAccount(tokAcc)), tokAcc, true
				}
			}
		}
	}

	return "", domain.Account{}, false
}

func markAccountQuotaCooldown(acc *domain.Account, policy domain.SelectionPolicy, modelName string, retryDur *time.Duration, cooldownReason string, now time.Time) {
	pool := resolveTargetPool(*acc, policy.TargetPool, modelName)
	resetAt := resolveCooldownDeadline(*acc, pool, retryDur, now)
	selector.MarkAccountCooldown(acc, resetAt, cooldownReason, policy.CooldownDefault, now)
	selector.MarkPoolExhausted(acc, pool, acc.Health.CooldownUntil)
}

func (h *Handler) syncSkippedStopSwitch(
	ctx context.Context,
	paths platform.Paths,
	state domain.StoreState,
	input HookInput,
	rootConvID string,
	launchedKey domain.AccountKey,
	targetAcc domain.Account,
	retryDur *time.Duration,
	errSnippet string,
	now time.Time,
) {
	if launchedKey != "" && targetAcc.Key != "" && targetAcc.Key != launchedKey {
		if acc, ok := state.Accounts[launchedKey]; ok && acc.Health.EffectiveStatus(now) == domain.HealthReady {
			cooldownReason := formatCooldownReason(errSnippet)
			_, _ = h.store.Update(ctx, func(s *domain.StoreState) error {
				cur, exists := s.Accounts[launchedKey]
				if !exists || cur.Health.EffectiveStatus(now) != domain.HealthReady {
					return nil
				}
				markAccountQuotaCooldown(&cur, s.Policy, input.ModelName, retryDur, cooldownReason, now)
				s.Accounts[launchedKey] = cur
				return nil
			})
		}
	}
	if strings.TrimSpace(os.Getenv("MULTI_ANTI_RUN_ID")) != "" && targetAcc.Key != "" && targetAcc.Key != launchedKey {
		_ = WriteSwitchSignal(paths, domain.HookSwitchSignal{
			ConversationID: rootConvID,
			FromKey:        launchedKey,
			ToKey:          targetAcc.Key,
			Reason:         "already switched to " + displayAccount(targetAcc),
			At:             now,
		})
	}
}

func (h *Handler) prepareStopSwitchTarget(
	ctx context.Context,
	currentKey domain.AccountKey,
	modelName string,
	initialDecision domain.SwitchDecision,
	now time.Time,
) (domain.Account, []byte, domain.SwitchDecision, bool) {
	decision := initialDecision
	excluded := map[domain.AccountKey]bool{currentKey: true}

	state, err := h.store.Load(ctx)
	if err != nil {
		return domain.Account{}, nil, decision, false
	}

	maxAttempts := max(1, len(state.Accounts))
	for range maxAttempts {
		if decision.Outcome != domain.OutcomeSwitched || decision.ToKey == "" {
			return domain.Account{}, nil, decision, false
		}

		acc, ok := state.Accounts[decision.ToKey]
		if !ok {
			excluded[decision.ToKey] = true
			decision = h.evaluateNext(state, currentKey, modelName, excluded, now)
			continue
		}

		creds := acc.Creds
		if h.oauth != nil && oauth.NeedsRefresh(creds, state.Policy.RefreshSkew, now) {
			refreshed, _, revoked, refreshErr := quota.RefreshAccountToken(ctx, h.store, h.oauth, acc.Key, state.Policy.RefreshSkew, now, quota.RefreshIfExpiring)
			if revoked {
				excluded[acc.Key] = true
				state, _ = h.store.Load(ctx)
				decision = h.evaluateNext(state, currentKey, modelName, excluded, now)
				continue
			}
			if !quota.CanStageWithoutRefresh(creds, refreshErr) {
				excluded[acc.Key] = true
				decision = h.evaluateNext(state, currentKey, modelName, excluded, now)
				continue
			}
			if refreshErr == nil {
				creds = refreshed
				acc.Creds = refreshed
			}
		}

		encoded, err := oauth.EncodeVerifiedAgyToken(acc, creds)
		if err != nil {
			excluded[acc.Key] = true
			decision = h.evaluateNext(state, currentKey, modelName, excluded, now)
			continue
		}
		return acc, encoded, decision, true
	}

	return domain.Account{}, nil, decision, false
}

func (h *Handler) evaluateNext(
	state domain.StoreState,
	currentKey domain.AccountKey,
	modelName string,
	excluded map[domain.AccountKey]bool,
	now time.Time,
) domain.SwitchDecision {
	return h.selector.Evaluate(state, selector.EvalRequest{
		CurrentKey:  currentKey,
		TargetModel: modelName,
		ForceSwitch: true,
		ExcludeKeys: excluded,
		Now:         now,
	})
}

func (h *Handler) mergeStatusLineQuota(
	ctx context.Context,
	state domain.StoreState,
	key domain.AccountKey,
	input StatusLineInput,
	now time.Time,
) (domain.StoreState, bool) {
	acc, ok := state.Accounts[key]
	if !ok {
		return state, false
	}
	if _, changed := applyStatusLineBuckets(&acc, input, now); !changed {
		return state, false
	}

	updated, err := h.store.Update(ctx, func(s *domain.StoreState) error {
		target, exists := s.Accounts[key]
		if !exists {
			return errors.New("account missing")
		}
		next, didChange := applyStatusLineBuckets(&target, input, now)
		if !didChange {
			return errors.New("no quota changes")
		}
		target.Quota = next
		s.Accounts[key] = target
		return nil
	})
	if err != nil {
		return state, false
	}
	return updated, true
}

func (h *Handler) renderStatusLine(state domain.StoreState, activeKey domain.AccountKey, input StatusLineInput, now time.Time) string {
	if len(state.Accounts) == 0 && strings.TrimSpace(input.Email) == "" {
		return "[multi-anti: unconfigured]"
	}
	if len(state.Accounts) == 0 {
		return renderStatusWithoutStore(input, now)
	}

	var modelID string
	if input.Model != nil {
		modelID = strings.TrimSpace(input.Model.ID)
	}

	if len(state.Accounts) == 1 {
		if acc, hasAcc := state.Accounts[activeKey]; hasAcc &&
			acc.Health.EffectiveStatus(now) == domain.HealthReady &&
			(acc.Quota == nil || (len(acc.Quota.Buckets) == 0 && len(acc.Quota.Models) == 0)) &&
			snapshotFromStatusInput(input.Quota, now) == nil {
			return fmt.Sprintf("[multi-anti: %s]", sanitizeSingleLine(displayAccount(acc)))
		}
	}

	decision := h.selector.Evaluate(state, selector.EvalRequest{
		CurrentKey:  activeKey,
		TargetModel: modelID,
		ForceSwitch: true,
		Now:         now,
	})
	var nextKey domain.AccountKey
	if decision.Outcome == domain.OutcomeSwitched && decision.ToKey != "" && decision.ToKey != activeKey {
		nextKey = decision.ToKey
	}

	ranked := h.selector.Rank(state, selector.EvalRequest{
		CurrentKey:  activeKey,
		TargetModel: modelID,
		Now:         now,
	})

	seen := make(map[domain.AccountKey]bool, len(state.Accounts))
	rows := make([]statusTableRow, 0, len(state.Accounts))

	if acc, hasAcc := state.Accounts[activeKey]; hasAcc {
		seen[activeKey] = true
		activeSnap := acc.Quota
		if activeSnap == nil || (len(activeSnap.Buckets) == 0 && len(activeSnap.Models) == 0) {
			activeSnap = snapshotFromStatusInput(input.Quota, now)
		}
		rows = append(rows, statusTableRow{
			marker: "*",
			label:  displayAccount(acc),
			snap:   activeSnap,
			status: formatAccountRowStatus(acc, true, false, now),
		})
	}

	if nextKey != "" && !seen[nextKey] {
		if nextAcc, exists := state.Accounts[nextKey]; exists {
			seen[nextKey] = true
			rows = append(rows, statusTableRow{
				marker: ">",
				label:  displayAccount(nextAcc),
				snap:   nextAcc.Quota,
				status: formatAccountRowStatus(nextAcc, false, true, now),
			})
		}
	}

	for _, sc := range ranked {
		if seen[sc.Key] {
			continue
		}
		acc, exists := state.Accounts[sc.Key]
		if !exists {
			continue
		}
		seen[sc.Key] = true
		rows = append(rows, statusTableRow{
			marker: " ",
			label:  displayAccount(acc),
			snap:   acc.Quota,
			status: formatAccountRowStatus(acc, false, false, now),
		})
	}

	if len(seen) < len(state.Accounts) {
		var extraKeys []domain.AccountKey
		for k := range state.Accounts {
			if !seen[k] {
				extraKeys = append(extraKeys, k)
			}
		}
		slices.Sort(extraKeys)
		for _, k := range extraKeys {
			acc := state.Accounts[k]
			rows = append(rows, statusTableRow{
				marker: " ",
				label:  displayAccount(acc),
				snap:   acc.Quota,
				status: formatAccountRowStatus(acc, false, false, now),
			})
		}
	}

	return renderStatusTable(rows, now)
}

func renderStatusWithoutStore(input StatusLineInput, now time.Time) string {
	email := strings.TrimSpace(input.Email)
	if email == "" {
		return "[multi-anti: unconfigured]"
	}
	snap := snapshotFromStatusInput(input.Quota, now)
	if snap == nil {
		return fmt.Sprintf("[multi-anti: %s]", sanitizeSingleLine(email))
	}
	return renderStatusTable([]statusTableRow{
		{
			marker: "*",
			label:  sanitizeSingleLine(email),
			snap:   snap,
			status: "active",
		},
	}, now)
}

type statusTableRow struct {
	marker string
	label  string
	snap   *domain.QuotaSnapshot
	status string
}

func formatAccountRowStatus(acc domain.Account, isActive, isNext bool, now time.Time) string {
	eff := acc.Health.EffectiveStatus(now)
	var healthStr string
	switch eff {
	case domain.HealthCooldown:
		healthStr = "cooldown"
		if acc.Health.CooldownUntil != nil && acc.Health.CooldownUntil.After(now) {
			healthStr += " " + domain.FormatDurationCompact(acc.Health.CooldownUntil.Sub(now))
		}
	case domain.HealthNeedsReauth:
		healthStr = "reauth"
	case domain.HealthDisabled:
		healthStr = "disabled"
	default:
		healthStr = "ready"
	}
	if isActive {
		if eff == domain.HealthReady {
			return "active"
		}
		return fmt.Sprintf("active (%s)", healthStr)
	}
	if isNext {
		return "next"
	}
	return healthStr
}

func extractPoolSlots(snap *domain.QuotaSnapshot, pool domain.QuotaPool, now time.Time) (slot5h, slotWeekly, slotUnknown statusWindowSlot, ok bool) {
	if snap == nil {
		return slot5h, slotWeekly, slotUnknown, false
	}
	if len(snap.Buckets) > 0 {
		for _, b := range snap.Buckets {
			if b.Pool != pool {
				continue
			}
			rem, resetAt := b.EffectiveAt(now)
			switch b.Window {
			case domain.Window5h:
				slot5h.add(rem, resetAt)
			case domain.WindowWeekly:
				slotWeekly.add(rem, resetAt)
			default:
				slotUnknown.add(rem, resetAt)
			}
		}
		return slot5h, slotWeekly, slotUnknown, slot5h.has || slotWeekly.has || slotUnknown.has
	}
	if len(snap.Models) > 0 {
		rem, resetAt, has := snap.PoolRemainingAt(pool, now)
		if has {
			slotUnknown.add(rem, resetAt)
			return slot5h, slotWeekly, slotUnknown, true
		}
	}
	return slot5h, slotWeekly, slotUnknown, false
}

// FormatDualWindowCell renders a compact "5h/wk" cell for pool inside snap, using "-" for missing data.
func FormatDualWindowCell(snap *domain.QuotaSnapshot, pool domain.QuotaPool, now time.Time) string {
	slot5h, slotWeekly, slotUnknown, ok := extractPoolSlots(snap, pool, now)
	if !ok {
		return "-"
	}
	if slot5h.has || slotWeekly.has {
		left := "-"
		if slot5h.has {
			left = formatStatusWindowReading("", slot5h.rem, slot5h.resetAt, now)
		}
		right := "-"
		if slotWeekly.has {
			right = formatStatusWindowReading("", slotWeekly.rem, slotWeekly.resetAt, now)
		}
		return left + "/" + right
	}
	return formatStatusWindowReading("", slotUnknown.rem, slotUnknown.resetAt, now)
}

func formatSingleOrDualWindowCell(snap *domain.QuotaSnapshot, pool domain.QuotaPool, now time.Time) string {
	slot5h, slotWeekly, slotUnknown, ok := extractPoolSlots(snap, pool, now)
	if !ok {
		return "-"
	}
	if slot5h.has && slotWeekly.has {
		return formatStatusWindowReading("", slot5h.rem, slot5h.resetAt, now) + "/" +
			formatStatusWindowReading("", slotWeekly.rem, slotWeekly.resetAt, now)
	}
	if slotWeekly.has {
		return formatStatusWindowReading("", slotWeekly.rem, slotWeekly.resetAt, now)
	}
	if slot5h.has {
		return formatStatusWindowReading("5h", slot5h.rem, slot5h.resetAt, now)
	}
	return formatStatusWindowReading("", slotUnknown.rem, slotUnknown.resetAt, now)
}

func truncateStatusLabel(s string, maxLen int) string {
	if len(s) <= maxLen || maxLen <= 3 {
		return s
	}
	return s[:maxLen-3] + "..."
}

func renderStatusTable(rows []statusTableRow, now time.Time) string {
	hasOther := false
	hasLongStatus := false
	for _, r := range rows {
		if _, _, _, ok := extractPoolSlots(r.snap, domain.PoolOther, now); ok {
			hasOther = true
		}
		if len(r.status) > 14 {
			hasLongStatus = true
		}
	}

	maxLabelLen := 30
	if hasOther {
		maxLabelLen = 22
	} else if hasLongStatus {
		maxLabelLen = 26
	}

	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 2, 2, ' ', 0)
	if hasOther {
		fmt.Fprintln(tw, "multi-anti\tGEMINI 5h/wk\tCLAUDE/GPT 5h/wk\tOTHER\tSTATUS")
	} else {
		fmt.Fprintln(tw, "multi-anti\tGEMINI 5h/wk\tCLAUDE/GPT 5h/wk\tSTATUS")
	}

	for _, r := range rows {
		acctCell := r.marker + " " + truncateStatusLabel(sanitizeSingleLine(r.label), maxLabelLen)
		gemCell := FormatDualWindowCell(r.snap, domain.PoolGemini, now)
		cpCell := FormatDualWindowCell(r.snap, domain.Pool3P, now)
		if hasOther {
			otherCell := formatSingleOrDualWindowCell(r.snap, domain.PoolOther, now)
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", acctCell, gemCell, cpCell, otherCell, sanitizeSingleLine(r.status))
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", acctCell, gemCell, cpCell, sanitizeSingleLine(r.status))
		}
	}
	_ = tw.Flush()
	return sanitizeMultiLine(buf.String())
}

type statusWindowSlot struct {
	has     bool
	rem     float64
	resetAt *time.Time
}

func (s *statusWindowSlot) add(rem float64, resetAt *time.Time) {
	c := clampFraction(rem)
	if !s.has || c < s.rem || (c == s.rem && isStatusResetMoreConstraining(c, resetAt, s.resetAt)) {
		s.has = true
		s.rem = c
		s.resetAt = resetAt
	}
}

func isStatusResetMoreConstraining(remaining float64, candidate, current *time.Time) bool {
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

func snapshotFromStatusInput(quotaMap map[string]StatusLineQuotaBucket, now time.Time) *domain.QuotaSnapshot {
	if len(quotaMap) == 0 {
		return nil
	}
	keys := make([]string, 0, len(quotaMap))
	for k := range quotaMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	buckets := make([]domain.QuotaBucket, 0, len(keys))
	for _, k := range keys {
		b := quotaMap[k]
		if b.RemainingFraction == nil {
			continue
		}
		buckets = append(buckets, domain.QuotaBucket{
			GroupID:           k,
			DisplayName:       k,
			Pool:              inferStatusLinePool(k),
			Window:            inferStatusLineWindow(k),
			RemainingFraction: clampFraction(*b.RemainingFraction),
			ResetAt:           parseStatusLineReset(b, now),
		})
	}
	if len(buckets) == 0 {
		return nil
	}
	return &domain.QuotaSnapshot{Buckets: buckets}
}

func formatStatusWindowReading(prefix string, rem float64, resetAt *time.Time, now time.Time) string {
	pct := roundPercent(rem)
	val := fmt.Sprintf("%d%%", pct)
	if pct < 100 {
		if rt, ok := domain.DescribeReset(resetAt, now, time.UTC); ok && !rt.Due {
			val += "(" + rt.Compact + ")"
		}
	}
	if prefix != "" {
		return prefix + ":" + val
	}
	return val
}

func applyStatusLineBuckets(acc *domain.Account, input StatusLineInput, now time.Time) (*domain.QuotaSnapshot, bool) {
	if acc == nil {
		return nil, false
	}
	if len(input.Quota) == 0 {
		return acc.Quota, false
	}

	var snap domain.QuotaSnapshot
	created := false
	if acc.Quota != nil {
		snap = *acc.Quota
		snap.Buckets = slices.Clone(acc.Quota.Buckets)
		snap.Models = slices.Clone(acc.Quota.Models)
	} else {
		created = true
		snap = domain.QuotaSnapshot{
			FetchedAt: now,
			Source:    domain.QuotaSourceSummary,
			Tier:      inferTierFromStatusLine(input.PlanTier),
		}
	}

	changed := false
	keys := make([]string, 0, len(input.Quota))
	for k := range input.Quota {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, bucketKey := range keys {
		reading := input.Quota[bucketKey]
		if reading.RemainingFraction == nil {
			continue
		}
		rem := clampFraction(*reading.RemainingFraction)
		resetAt := parseStatusLineReset(reading, now)
		if mergeSingleStatusBucket(&snap, created, bucketKey, rem, resetAt) {
			changed = true
		}
	}

	if !changed {
		return acc.Quota, false
	}
	snap.FetchedAt = now
	return &snap, true
}

func mergeSingleStatusBucket(snap *domain.QuotaSnapshot, created bool, bucketKey string, rem float64, resetAt *time.Time) bool {
	matched := false
	changed := false
	for i := range snap.Buckets {
		if strings.EqualFold(snap.Buckets[i].GroupID, bucketKey) ||
			strings.EqualFold(snap.Buckets[i].DisplayName, bucketKey) {
			if updateBucketReading(&snap.Buckets[i], rem, resetAt) {
				changed = true
			}
			matched = true
		}
	}
	if matched {
		return changed
	}

	inferredPool := inferStatusLinePool(bucketKey)
	inferredWindow := inferStatusLineWindow(bucketKey)
	if inferredPool != domain.PoolOther {
		if poolMatched, poolChanged := updatePoolMatchingBuckets(snap.Buckets, inferredPool, inferredWindow, rem, resetAt); poolMatched {
			return poolChanged
		}
	}

	modelMatched := false
	for i := range snap.Models {
		if strings.EqualFold(snap.Models[i].ModelID, bucketKey) ||
			strings.EqualFold(snap.Models[i].DisplayName, bucketKey) ||
			(inferredPool != domain.PoolOther && snap.InferPoolForModel(snap.Models[i].ModelID) == inferredPool) {
			if updateModelReading(&snap.Models[i], rem, resetAt) {
				changed = true
			}
			modelMatched = true
		}
	}
	if modelMatched {
		return changed
	}

	if created || (len(snap.Buckets) == 0 && len(snap.Models) == 0) {
		snap.Buckets = append(snap.Buckets, domain.QuotaBucket{
			GroupID:           bucketKey,
			DisplayName:       bucketKey,
			Pool:              inferredPool,
			Window:            inferredWindow,
			RemainingFraction: rem,
			ResetAt:           resetAt,
		})
		return true
	}
	return false
}

func updatePoolMatchingBuckets(
	buckets []domain.QuotaBucket,
	pool domain.QuotaPool,
	window domain.QuotaWindow,
	rem float64,
	resetAt *time.Time,
) (matched bool, changed bool) {
	if window != domain.WindowUnknown {
		for i := range buckets {
			if buckets[i].Pool != pool {
				continue
			}
			if buckets[i].Window != domain.WindowUnknown && buckets[i].Window != window {
				continue
			}
			if updateBucketReading(&buckets[i], rem, resetAt) {
				changed = true
			}
			matched = true
		}
		return matched, changed
	}

	var poolIdx, unknownIdx []int
	for i := range buckets {
		if buckets[i].Pool != pool {
			continue
		}
		poolIdx = append(poolIdx, i)
		if buckets[i].Window == domain.WindowUnknown {
			unknownIdx = append(unknownIdx, i)
		}
	}
	switch {
	case len(unknownIdx) > 0:
		for _, idx := range unknownIdx {
			if updateBucketReading(&buckets[idx], rem, resetAt) {
				changed = true
			}
		}
		return true, changed
	case len(poolIdx) == 1:
		return true, updateBucketReading(&buckets[poolIdx[0]], rem, resetAt)
	case len(poolIdx) > 1:
		return true, updateUniqueResetMatchingBucket(buckets, poolIdx, rem, resetAt)
	default:
		return false, false
	}
}

func updateUniqueResetMatchingBucket(buckets []domain.QuotaBucket, poolIdx []int, rem float64, resetAt *time.Time) bool {
	if resetAt == nil {
		return false
	}
	var matchedResetIdx int
	matchCount := 0
	for _, idx := range poolIdx {
		if buckets[idx].ResetAt != nil && resetTimesMatch(*buckets[idx].ResetAt, *resetAt) {
			matchedResetIdx = idx
			matchCount++
		}
	}
	if matchCount != 1 {
		return false
	}
	return updateBucketReading(&buckets[matchedResetIdx], rem, resetAt)
}

func updateBucketReading(b *domain.QuotaBucket, rem float64, resetAt *time.Time) bool {
	changed := false
	if math.Abs(b.RemainingFraction-rem) > 1e-9 {
		b.RemainingFraction = rem
		changed = true
	}
	if resetAt != nil && !timePtrEqual(b.ResetAt, resetAt) {
		t := *resetAt
		b.ResetAt = &t
		changed = true
	}
	return changed
}

func updateModelReading(m *domain.ModelQuota, rem float64, resetAt *time.Time) bool {
	changed := false
	if math.Abs(m.RemainingFraction-rem) > 1e-9 {
		m.RemainingFraction = rem
		changed = true
	}
	if resetAt != nil && !timePtrEqual(m.ResetAt, resetAt) {
		t := *resetAt
		m.ResetAt = &t
		changed = true
	}
	return changed
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}

func parseStatusLineReset(b StatusLineQuotaBucket, now time.Time) *time.Time {
	if t, err := quota.ParseOptionalTime(b.ResetTime); err == nil && t != nil {
		return t
	}
	if b.ResetInSeconds != nil && *b.ResetInSeconds > 0 {
		utc := now.Add(time.Duration(*b.ResetInSeconds * float64(time.Second))).UTC()
		return &utc
	}
	return nil
}

func resetTimesMatch(a, b time.Time) bool {
	diff := a.Sub(b)
	if diff < 0 {
		diff = -diff
	}
	return diff <= 15*time.Minute
}

func inferStatusLinePool(bucketKey string) domain.QuotaPool {
	return domain.ClassifyPool(bucketKey)
}

func inferStatusLineWindow(bucketKey string) domain.QuotaWindow {
	return domain.ClassifyWindow(bucketKey)
}

func inferTierFromStatusLine(planTier string) domain.SubscriptionTier {
	lower := strings.ToLower(strings.TrimSpace(planTier))
	switch {
	case strings.Contains(lower, "ultra"):
		return domain.TierUltra
	case strings.Contains(lower, "pro"):
		return domain.TierPro
	case strings.Contains(lower, "enterprise") || strings.Contains(lower, "standard"):
		return domain.TierEnterprise
	case strings.Contains(lower, "free"):
		return domain.TierFree
	default:
		return domain.TierUnknown
	}
}

func detectStopQuotaError(input HookInput) (matched bool, retryDur *time.Duration, snippet string) {
	if errText := strings.TrimSpace(input.Error); errText != "" {
		ok, dur := selector.IsQuotaExhaustedError(errText)
		if ok {
			if dur == nil && strings.TrimSpace(input.TranscriptPath) != "" {
				if tail := readFileTail(input.TranscriptPath, transcriptTailBytes); tail != "" {
					if _, tailDur, _ := detectTranscriptTailQuotaError(tail); tailDur != nil {
						dur = tailDur
					}
				}
			}
			return true, dur, errText
		}
	}

	isErrorStop := strings.EqualFold(strings.TrimSpace(input.TerminationReason), "ERROR") ||
		strings.TrimSpace(input.Error) != ""
	if isErrorStop && strings.TrimSpace(input.TranscriptPath) != "" {
		if tail := readFileTail(input.TranscriptPath, transcriptTailBytes); tail != "" {
			if ok, dur, lineSnippet := detectTranscriptTailQuotaError(tail); ok {
				return true, dur, lineSnippet
			}
		}
	}
	return false, nil, ""
}

func detectTranscriptTailQuotaError(tail string) (matched bool, retryDur *time.Duration, snippet string) {
	rawLines := strings.Split(tail, "\n")
	checked := 0
	for i := len(rawLines) - 1; i >= 0 && checked < 5; i-- {
		line := strings.TrimSpace(rawLines[i])
		if line == "" {
			continue
		}
		checked++

		if strings.HasPrefix(line, "{") {
			var step struct {
				Type    string `json:"type"`
				Status  string `json:"status"`
				Error   string `json:"error"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal([]byte(line), &step); err == nil {
				isErrorStep := strings.TrimSpace(step.Error) != "" ||
					strings.EqualFold(strings.TrimSpace(step.Status), "ERROR") ||
					strings.Contains(strings.ToUpper(strings.TrimSpace(step.Type)), "ERROR")
				if !isErrorStep {
					if checked > 1 {
						break
					}
					continue
				}
				for _, candidate := range []string{step.Error, step.Content} {
					c := strings.TrimSpace(candidate)
					if c == "" {
						continue
					}
					if ok, dur := selector.IsQuotaExhaustedError(c); ok {
						return true, dur, c
					}
				}
				continue
			}
		}

		if ok, dur := selector.IsQuotaExhaustedError(line); ok {
			return true, dur, line
		}
	}
	return false, nil, ""
}

func readFileTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return ""
	}
	size := info.Size()
	if size <= 0 {
		return ""
	}
	offset := int64(0)
	if size > maxBytes {
		offset = size - maxBytes
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return ""
	}
	return string(buf)
}

func resolveActiveAccountKey(paths platform.Paths, state domain.StoreState) domain.AccountKey {
	if os.Getenv("MULTI_ANTI_ISOLATED") == "1" {
		if k := domain.AccountKey(strings.TrimSpace(os.Getenv("MULTI_ANTI_ACCOUNT"))); k != "" {
			if _, ok := state.Accounts[k]; ok {
				return k
			}
		}
	}
	if k := readNativeTokenKey(paths); k != "" {
		if _, ok := state.Accounts[k]; ok {
			return k
		}
	}
	if _, ok := state.Accounts[state.ActiveKey]; ok {
		return state.ActiveKey
	}
	return ""
}

func resolveStatusLineAccountKey(paths platform.Paths, state domain.StoreState, email string) domain.AccountKey {
	if clean := strings.TrimSpace(email); clean != "" {
		if key, err := domain.NormalizeAccountKey(clean, ""); err == nil {
			if _, ok := state.Accounts[key]; ok {
				return key
			}
		}
	}
	return resolveActiveAccountKey(paths, state)
}

func pickFailingAccountKey(state domain.StoreState, launchedKey, tokenKey domain.AccountKey) domain.AccountKey {
	if launchedKey != "" {
		if _, ok := state.Accounts[launchedKey]; ok {
			return launchedKey
		}
	}
	if tokenKey != "" {
		if _, ok := state.Accounts[tokenKey]; ok {
			return tokenKey
		}
	}
	if state.ActiveKey != "" {
		if _, ok := state.Accounts[state.ActiveKey]; ok {
			return state.ActiveKey
		}
	}
	return ""
}

func readNativeTokenKey(paths platform.Paths) domain.AccountKey {
	data, err := os.ReadFile(paths.NativeAgyTokenPath())
	if err != nil {
		return ""
	}
	id, _, err := oauth.DecodeAgyTokenFile(data)
	if err != nil {
		return ""
	}
	return id.Key
}

func resolveTargetPool(acc domain.Account, policyPool domain.QuotaPool, modelName string) domain.QuotaPool {
	if model := strings.TrimSpace(modelName); model != "" {
		if acc.Quota != nil {
			if p := acc.Quota.InferPoolForModel(model); p != domain.PoolOther {
				return p
			}
		}
		if p := (domain.QuotaSnapshot{}).InferPoolForModel(model); p != domain.PoolOther {
			return p
		}
	}
	return policyPool
}

func resolveCooldownDeadline(acc domain.Account, pool domain.QuotaPool, retryDur *time.Duration, now time.Time) *time.Time {
	if retryDur != nil && *retryDur > 0 {
		t := now.Add(*retryDur).UTC()
		return &t
	}
	if acc.Quota != nil {
		if _, resetAt, ok := acc.Quota.PoolRemainingAt(pool, now); ok && resetAt != nil && resetAt.After(now) {
			t := resetAt.UTC()
			return &t
		}
	}
	return nil
}

func formatCooldownReason(errText string) string {
	cleaned := sanitizeSingleLine(errText)
	if cleaned == "" {
		return "quota exhausted (hook_stop)"
	}
	if len(cleaned) > maxReasonLen {
		cleaned = cleaned[:maxReasonLen] + "..."
	}
	return "quota exhausted: " + cleaned
}

func formatNoneReadyReason(decision domain.SwitchDecision, now time.Time) string {
	if decision.EarliestReset != nil {
		if rt, ok := domain.DescribeReset(decision.EarliestReset, now, time.UTC); ok && !rt.Due {
			return fmt.Sprintf("multi-anti: no ready accounts available (earliest reset in %s at %s)", rt.Compact, decision.EarliestReset.UTC().Format(time.RFC3339))
		}
		return fmt.Sprintf("multi-anti: no ready accounts available (earliest reset: %s)", decision.EarliestReset.UTC().Format(time.RFC3339))
	}
	return "multi-anti: no ready accounts available"
}

func countReadyAccounts(state domain.StoreState, now time.Time) int {
	ready := 0
	for _, acc := range state.Accounts {
		if acc.Health.CanSelect(now) {
			ready++
		}
	}
	return ready
}

func displayAccount(acc domain.Account) string {
	if s := strings.TrimSpace(acc.Email); s != "" {
		return s
	}
	return string(acc.Key)
}

func roundPercent(rem float64) int {
	return int(math.Round(clampFraction(rem) * 100))
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

func sanitizeSingleLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func sanitizeMultiLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Trim(s, "\n")
}

func parseJSONTolerant(data []byte, dst any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	return json.Unmarshal(trimmed, dst)
}

func parseStatusLineInput(stdin []byte) (StatusLineInput, bool) {
	trimmed := bytes.TrimSpace(stdin)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return StatusLineInput{}, false
	}
	var input StatusLineInput
	if err := json.Unmarshal(trimmed, &input); err != nil {
		return StatusLineInput{}, false
	}
	return input, true
}

func hasStatusLineQuotaReading(quotaMap map[string]StatusLineQuotaBucket) bool {
	for _, b := range quotaMap {
		if b.RemainingFraction != nil {
			return true
		}
	}
	return false
}

func marshalJSONLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func marshalStopAllow(reason string) ([]byte, error) {
	return marshalJSONLine(StopOutput{
		Decision: "allow",
		Reason:   strings.TrimSpace(reason),
	})
}

// LatestSignalPath returns the path to the most recent Stop-hook switch signal file.
func LatestSignalPath(paths platform.Paths) string {
	return filepath.Join(paths.SignalsDir(), "latest.json")
}

var subagentSenderPattern = regexp.MustCompile(`\bsender=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

func resolveRootConversationID(conversationID, transcriptPath string) string {
	curID := strings.TrimSpace(conversationID)
	curPath := strings.TrimSpace(transcriptPath)
	if curID == "" || curPath == "" {
		return curID
	}

	visited := map[string]bool{curID: true}
	for range 8 {
		firstLine := readFirstTranscriptLine(curPath, transcriptTailBytes)
		if firstLine == "" {
			return curID
		}
		var step0 struct {
			Source  string `json:"source"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal([]byte(firstLine), &step0); err != nil {
			return curID
		}
		if !strings.EqualFold(strings.TrimSpace(step0.Source), "SYSTEM") {
			return curID
		}
		m := subagentSenderPattern.FindStringSubmatch(step0.Content)
		if len(m) != 2 {
			return curID
		}
		parentID := m[1]
		if visited[parentID] {
			return curID
		}
		visited[parentID] = true
		nextPath := replaceConversationPathSegment(curPath, curID, parentID)
		curID = parentID
		if nextPath == "" {
			return curID
		}
		if _, err := os.Stat(nextPath); err != nil {
			return curID
		}
		curPath = nextPath
	}
	return curID
}

func readFirstTranscriptLine(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil || len(buf) == 0 {
		return ""
	}
	line, _, _ := bytes.Cut(buf, []byte{'\n'})
	return strings.TrimSpace(string(line))
}

func replaceConversationPathSegment(path, fromID, toID string) string {
	cleaned := filepath.Clean(path)
	sep := string(filepath.Separator)
	parts := strings.Split(cleaned, sep)
	replaced := false
	for i, part := range parts {
		if part == fromID {
			parts[i] = toID
			replaced = true
		}
	}
	if !replaced {
		return ""
	}
	return strings.Join(parts, sep)
}

func sanitizeSignalSlug(raw, prefix string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" || len(slug) > 64 {
		sum := sha256.Sum256([]byte(raw))
		slug = fmt.Sprintf("%s-%x", prefix, sum[:8])
	}
	return slug
}

// SignalPath returns the signal file path scoped to conversationID inside SignalsDir.
func SignalPath(paths platform.Paths, conversationID string) string {
	clean := strings.TrimSpace(conversationID)
	if clean == "" {
		return LatestSignalPath(paths)
	}
	return filepath.Join(paths.SignalsDir(), sanitizeSignalSlug(clean, "conv")+".json")
}

// WriteSwitchSignal atomically persists sig to latest.json, any scoped conversationId file,
// and any active MULTI_ANTI_RUN_ID per-run signal file.
func WriteSwitchSignal(paths platform.Paths, sig domain.HookSwitchSignal) error {
	if err := platform.EnsurePrivateDir(paths.SignalsDir()); err != nil {
		return fmt.Errorf("ensure signals dir %q: %w", paths.SignalsDir(), err)
	}
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal switch signal: %w", err)
	}
	data = append(data, '\n')

	if err := platform.WriteFileAtomic(LatestSignalPath(paths), data, true); err != nil {
		return err
	}
	if cid := strings.TrimSpace(sig.ConversationID); cid != "" {
		if err := platform.WriteFileAtomic(SignalPath(paths, cid), data, true); err != nil {
			return err
		}
	}
	if runPath := RunSignalPath(paths, os.Getenv("MULTI_ANTI_RUN_ID")); runPath != "" {
		if err := platform.WriteFileAtomic(runPath, data, true); err != nil {
			return err
		}
	}
	return nil
}

// ReadLatestSwitchSignal reads the latest Stop-hook switch signal if present.
func ReadLatestSwitchSignal(paths platform.Paths) (domain.HookSwitchSignal, bool, error) {
	return readSignalFile(LatestSignalPath(paths))
}

// ReadSwitchSignal reads the switch signal for conversationID, returning (zero, false, nil) when absent.
func ReadSwitchSignal(paths platform.Paths, conversationID string) (domain.HookSwitchSignal, bool, error) {
	return readSignalFile(SignalPath(paths, conversationID))
}

func readSignalFile(path string) (domain.HookSwitchSignal, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return domain.HookSwitchSignal{}, false, nil
		}
		return domain.HookSwitchSignal{}, false, fmt.Errorf("read switch signal %q: %w", path, err)
	}
	var sig domain.HookSwitchSignal
	if err := json.Unmarshal(raw, &sig); err != nil {
		return domain.HookSwitchSignal{}, false, fmt.Errorf("parse switch signal %q: %w", path, err)
	}
	return sig, true, nil
}

// RunSignalPath returns the per-run Stop-hook switch signal file path under SignalsDir.
func RunSignalPath(paths platform.Paths, runID string) string {
	clean := strings.TrimSpace(runID)
	if clean == "" {
		return ""
	}
	return filepath.Join(paths.SignalsDir(), "run-"+sanitizeSignalSlug(clean, "run")+".json")
}

// ReadRunSwitchSignal reads the switch signal scoped to runID, returning (zero, false, nil) when absent.
func ReadRunSwitchSignal(paths platform.Paths, runID string) (domain.HookSwitchSignal, bool, error) {
	p := RunSignalPath(paths, runID)
	if p == "" {
		return domain.HookSwitchSignal{}, false, nil
	}
	return readSignalFile(p)
}

// ClearRunSwitchSignal removes the switch signal file scoped to runID if present.
func ClearRunSwitchSignal(paths platform.Paths, runID string) error {
	p := RunSignalPath(paths, runID)
	if p == "" {
		return nil
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove run signal %q: %w", p, err)
	}
	return nil
}

// ClearSwitchSignals removes all pending signal JSON files from SignalsDir.
func ClearSwitchSignals(paths platform.Paths) error {
	entries, err := os.ReadDir(paths.SignalsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read signals dir %q: %w", paths.SignalsDir(), err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if err := os.Remove(filepath.Join(paths.SignalsDir(), entry.Name())); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove signal %q: %w", entry.Name(), err)
		}
	}
	return nil
}
