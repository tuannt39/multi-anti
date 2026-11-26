package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

// ErrNoReadyAccounts indicates no configured account is currently eligible for selection.
var ErrNoReadyAccounts = errors.New("no ready accounts available")

// PrepareOptions configures pre-launch account selection, quota refresh, and staging.
type PrepareOptions struct {
	Account    domain.AccountKey
	Model      string
	TargetPool domain.QuotaPool
	Isolate    bool
	NoRefresh  bool
	Exclude    map[domain.AccountKey]bool
	Now        time.Time
}

// PreparedLaunch describes the selected account, staged token location, and child environment.
type PreparedLaunch struct {
	Account         domain.Account
	Decision        domain.SwitchDecision
	Env             []string
	HomeOverride    string
	StagedTokenPath string
	Isolated        bool
}

// PrepareLaunch refreshes quotas (unless NoRefresh), picks or validates the target account,
// refreshes expiring OAuth credentials, stages the native or isolated profile, and updates state.
func PrepareLaunch(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	fetcher quota.QuotaFetcher,
	sel selector.Selector,
	opts PrepareOptions,
) (PreparedLaunch, error) {
	if st == nil {
		return PreparedLaunch{}, errors.New("prepare launch: nil store")
	}
	if sel == nil {
		sel = selector.NewDefaultSelector()
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	if _, err := st.EnsureNativeBackup(ctx); err != nil {
		return PreparedLaunch{}, fmt.Errorf("ensure native backup: %w", err)
	}

	if !opts.Isolate {
		_, _ = quota.SyncNativeTokenIfFresher(ctx, st, now)
	}

	initialState, err := st.Load(ctx)
	if err != nil {
		return PreparedLaunch{}, err
	}
	if len(initialState.Accounts) == 0 {
		return PreparedLaunch{}, fmt.Errorf("%w: no accounts configured", ErrNoReadyAccounts)
	}

	explicitKey, err := resolveExplicitAccount(initialState, opts.Account)
	if err != nil {
		return PreparedLaunch{}, err
	}

	if !opts.NoRefresh && fetcher != nil {
		var refreshKeys []domain.AccountKey
		if explicitKey != "" {
			refreshKeys = []domain.AccountKey{explicitKey}
		}
		if _, err := quota.RefreshAndFetchAll(ctx, st, oauthClient, fetcher, refreshKeys, quota.FetchOptions{Now: now}); err != nil {
			return PreparedLaunch{}, fmt.Errorf("refresh quotas: %w", err)
		}
	}

	paths := st.Paths()
	excluded := make(map[domain.AccountKey]bool, len(opts.Exclude))
	for k, v := range opts.Exclude {
		if v {
			excluded[k] = true
		}
	}

	var chosen domain.Account
	var decision domain.SwitchDecision
	var encodedToken []byte

	state, err := st.Load(ctx)
	if err != nil {
		return PreparedLaunch{}, err
	}

	maxAttempts := max(1, len(state.Accounts))
	selected := false
	for range maxAttempts {
		if explicitKey != "" {
			if excluded[explicitKey] {
				return PreparedLaunch{}, fmt.Errorf("account %q is excluded", explicitKey)
			}
			acc, ok := state.Accounts[explicitKey]
			if !ok {
				return PreparedLaunch{}, fmt.Errorf("account %q not found", explicitKey)
			}
			eff := acc.Health.EffectiveStatus(now)
			if eff == domain.HealthDisabled || eff == domain.HealthNeedsReauth {
				return PreparedLaunch{}, fmt.Errorf("account %q is %s: %s", acc.Key, eff, acc.Health.Reason)
			}
			outcome := domain.OutcomeKeepCurrent
			if state.ActiveKey != "" && state.ActiveKey != acc.Key {
				outcome = domain.OutcomeSwitched
			}
			decision = domain.SwitchDecision{
				Outcome: outcome,
				FromKey: state.ActiveKey,
				ToKey:   acc.Key,
				Reason:  "explicit account selected",
			}
			chosen = acc
		} else {
			decision = sel.Evaluate(state, selector.EvalRequest{
				CurrentKey:  state.ActiveKey,
				TargetPool:  opts.TargetPool,
				TargetModel: opts.Model,
				ExcludeKeys: excluded,
				Now:         now,
			})
			if decision.Outcome == domain.OutcomeNoneReady || decision.ToKey == "" {
				return PreparedLaunch{Decision: decision}, formatNoReadyError(decision, now)
			}
			acc, ok := state.Accounts[decision.ToKey]
			if !ok {
				excluded[decision.ToKey] = true
				continue
			}
			chosen = acc
		}

		if oauthClient != nil && oauth.NeedsRefresh(chosen.Creds, state.Policy.RefreshSkew, now) {
			refreshed, _, revoked, refreshErr := quota.RefreshAccountToken(ctx, st, oauthClient, chosen.Key, state.Policy.RefreshSkew, now, quota.RefreshIfExpiring)
			if revoked {
				if explicitKey != "" {
					return PreparedLaunch{}, refreshErr
				}
				excluded[chosen.Key] = true
				state, err = st.Load(ctx)
				if err != nil {
					return PreparedLaunch{}, err
				}
				continue
			}
			if !quota.CanStageWithoutRefresh(chosen.Creds, refreshErr) {
				if explicitKey != "" {
					return PreparedLaunch{}, refreshErr
				}
				excluded[chosen.Key] = true
				continue
			}
			if refreshErr == nil {
				chosen.Creds = refreshed
			}
		}

		encoded, encErr := oauth.EncodeVerifiedAgyToken(chosen, chosen.Creds)
		if encErr != nil {
			return PreparedLaunch{}, encErr
		}
		encodedToken = encoded
		selected = true
		break
	}

	if !selected {
		return PreparedLaunch{Decision: decision}, formatNoReadyError(decision, now)
	}

	var stagedPath string
	var homeOverride string
	var childEnv []string

	if opts.Isolate {
		profDir := paths.ProfileDir(chosen.Key)
		if err := platform.EnsurePrivateDir(profDir); err != nil {
			return PreparedLaunch{}, fmt.Errorf("ensure profile dir %q: %w", profDir, err)
		}
		stagedPath = filepath.Join(profDir, ".gemini", "antigravity-cli", "antigravity-oauth-token")
		if err := platform.WriteFileAtomic(stagedPath, encodedToken, true); err != nil {
			return PreparedLaunch{}, fmt.Errorf("stage isolated token %q: %w", stagedPath, err)
		}
		if err := projectSharedAgyFiles(paths, profDir); err != nil {
			return PreparedLaunch{}, err
		}
		homeOverride = profDir
		childEnv = buildIsolatedEnv(paths, profDir, chosen.Key)
	} else {
		stagedPath = paths.NativeAgyTokenPath()
		childEnv = buildDefaultEnv(paths, chosen.Key)
	}

	updatedState, err := st.Update(ctx, func(s *domain.StoreState) error {
		acc, ok := s.Accounts[chosen.Key]
		if !ok {
			return fmt.Errorf("account %q disappeared before launch", chosen.Key)
		}
		if !opts.Isolate {
			if err := platform.WriteFileAtomic(stagedPath, encodedToken, true); err != nil {
				return fmt.Errorf("stage native token %q: %w", stagedPath, err)
			}
		}
		usedAt := now
		acc.LastUsedAt = &usedAt
		s.Accounts[chosen.Key] = acc
		s.ActiveKey = chosen.Key
		if decision.Outcome == domain.OutcomeSwitched {
			s.LastSwitch = &domain.SwitchAuditEntry{
				At:      now,
				Outcome: decision.Outcome,
				FromKey: decision.FromKey,
				ToKey:   chosen.Key,
				Reason:  decision.Reason,
				Pool:    decision.Pool,
				Trigger: "launcher",
			}
		}
		return nil
	})
	if err != nil {
		return PreparedLaunch{}, err
	}
	chosen = updatedState.Accounts[chosen.Key]

	return PreparedLaunch{
		Account:         chosen,
		Decision:        decision,
		Env:             childEnv,
		HomeOverride:    homeOverride,
		StagedTokenPath: stagedPath,
		Isolated:        opts.Isolate,
	}, nil
}

// SyncBackStagedToken persists OAuth token updates written by agy back to the store
// only when the staged token still belongs to expectedEmail and credentials changed.
func SyncBackStagedToken(ctx context.Context, st store.Store, stagedPath string, expectedEmail string) error {
	if st == nil || strings.TrimSpace(stagedPath) == "" {
		return nil
	}
	raw, err := os.ReadFile(stagedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read staged token %q: %w", stagedPath, err)
	}

	decodedID, decodedCreds, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return fmt.Errorf("decode staged token %q: %w", stagedPath, err)
	}

	wantEmail := strings.TrimSpace(expectedEmail)
	if wantEmail != "" && !strings.EqualFold(strings.TrimSpace(decodedID.Email), wantEmail) {
		return nil
	}

	state, err := st.Load(ctx)
	if err != nil {
		return err
	}
	targetKey, acc, ok := findMatchingAccount(state, decodedID.Key, wantEmail)
	if !ok || !credentialsChanged(acc.Creds, decodedCreds) {
		return nil
	}

	_, err = st.Update(ctx, func(s *domain.StoreState) error {
		cur, exists := s.Accounts[targetKey]
		if !exists {
			return nil
		}
		if wantEmail != "" && cur.Email != "" && !strings.EqualFold(strings.TrimSpace(cur.Email), wantEmail) {
			return nil
		}
		if !credentialsChanged(cur.Creds, decodedCreds) {
			return nil
		}
		syncNow := time.Now().UTC()
		merged := decodedCreds
		if strings.TrimSpace(merged.ClientID) == "" {
			merged.ClientID = cur.Creds.ClientID
		}
		if strings.TrimSpace(merged.RefreshToken) == "" {
			merged.RefreshToken = cur.Creds.RefreshToken
		}
		if strings.TrimSpace(merged.IDToken) == "" {
			merged.IDToken = cur.Creds.IDToken
		}
		cur.Creds = merged
		if cur.Health.Status == domain.HealthNeedsReauth {
			cur.Health = domain.AccountHealth{
				Status:    domain.HealthReady,
				UpdatedAt: syncNow,
			}
		}
		if cur.Quota != nil && cur.Quota.FetchError != "" && !oauth.NeedsRefresh(merged, 0, syncNow) {
			qCopy := *cur.Quota
			qCopy.FetchError = ""
			cur.Quota = &qCopy
		}
		s.Accounts[targetKey] = cur
		return nil
	})
	return err
}

func syncSessionAuthAfterRun(ctx context.Context, st store.Store, prepared PreparedLaunch, now time.Time) {
	if st == nil || strings.TrimSpace(prepared.StagedTokenPath) == "" {
		return
	}
	raw, err := os.ReadFile(prepared.StagedTokenPath)
	if err != nil {
		if os.IsNotExist(err) && !prepared.Isolated {
			_, _ = quota.ClearActiveKeyIfLoggedOut(ctx, st, prepared.StagedTokenPath, "")
		}
		return
	}
	decodedID, _, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return
	}
	wantEmail := strings.TrimSpace(prepared.Account.Email)
	sameAccount := decodedID.Key == prepared.Account.Key ||
		(wantEmail != "" && strings.EqualFold(strings.TrimSpace(decodedID.Email), wantEmail))
	if sameAccount {
		_ = SyncBackStagedToken(ctx, st, prepared.StagedTokenPath, prepared.Account.Email)
		return
	}
	_, _, _ = quota.UpsertTokenFromFile(ctx, st, prepared.StagedTokenPath, quota.TokenSyncOptions{
		SetActive:  !prepared.Isolated,
		RecordUsed: true,
		Now:        now,
	})
}

func resolveExplicitAccount(state domain.StoreState, rawKey domain.AccountKey) (domain.AccountKey, error) {
	trimmed := strings.TrimSpace(string(rawKey))
	if trimmed == "" {
		return "", nil
	}
	if _, ok := state.Accounts[domain.AccountKey(trimmed)]; ok {
		return domain.AccountKey(trimmed), nil
	}
	if norm, err := domain.NormalizeAccountKey(trimmed, ""); err == nil {
		if _, ok := state.Accounts[norm]; ok {
			return norm, nil
		}
	}
	return "", fmt.Errorf("account %q not found", rawKey)
}

func projectSharedAgyFiles(paths platform.Paths, profDir string) error {
	settingsSrc := paths.NativeAgySettingsPath()
	if info, err := os.Stat(settingsSrc); err == nil && !info.IsDir() {
		settingsDst := filepath.Join(profDir, ".gemini", "antigravity-cli", "settings.json")
		if err := platform.ProjectFile(settingsSrc, settingsDst); err != nil {
			return fmt.Errorf("project settings.json: %w", err)
		}
	}

	cfgSrc := paths.NativeGeminiConfigDir()
	if info, err := os.Stat(cfgSrc); err == nil && info.IsDir() {
		cfgDst := filepath.Join(profDir, ".gemini", "config")
		if err := platform.ProjectDir(cfgSrc, cfgDst); err != nil {
			return fmt.Errorf("project gemini config dir: %w", err)
		}
	}
	return nil
}

func buildDefaultEnv(paths platform.Paths, accountKey domain.AccountKey) []string {
	return mergeEnv(os.Environ(), []string{
		"SSH_TTY=multi-anti",
		"MULTI_ANTI_MANAGED=1",
		"MULTI_ANTI_ACCOUNT=" + string(accountKey),
		"MULTI_ANTI_HOME=" + paths.DataDir(),
	})
}

func buildIsolatedEnv(paths platform.Paths, profDir string, accountKey domain.AccountKey) []string {
	base := os.Environ()
	realHome := resolveRealUserHome()

	overrides := []string{
		"HOME=" + profDir,
		"USERPROFILE=" + profDir,
		"SSH_TTY=multi-anti",
		"MULTI_ANTI_MANAGED=1",
		"MULTI_ANTI_ISOLATED=1",
		"MULTI_ANTI_ACCOUNT=" + string(accountKey),
		"MULTI_ANTI_HOME=" + paths.DataDir(),
		"MULTI_ANTI_AGY_HOME=" + paths.HomeDir(),
	}

	if runtime.GOOS != "windows" && realHome != "" {
		xdgDefaults := []struct {
			key string
			rel string
		}{
			{"XDG_CONFIG_HOME", ".config"},
			{"XDG_DATA_HOME", filepath.Join(".local", "share")},
			{"XDG_CACHE_HOME", ".cache"},
			{"GIT_CONFIG_GLOBAL", ".gitconfig"},
		}
		for _, item := range xdgDefaults {
			if strings.TrimSpace(os.Getenv(item.key)) == "" {
				overrides = append(overrides, item.key+"="+filepath.Join(realHome, item.rel))
			}
		}
	}

	return mergeEnv(base, overrides)
}

func resolveRealUserHome() string {
	if runtime.GOOS == "windows" {
		if h := strings.TrimSpace(os.Getenv("USERPROFILE")); h != "" {
			return h
		}
	}
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return h
	}
	h, err := os.UserHomeDir()
	if err == nil {
		return strings.TrimSpace(h)
	}
	return ""
}

func findMatchingAccount(state domain.StoreState, key domain.AccountKey, email string) (domain.AccountKey, domain.Account, bool) {
	if acc, ok := state.Accounts[key]; ok {
		return key, acc, true
	}
	if email != "" {
		for k, acc := range state.Accounts {
			if strings.EqualFold(strings.TrimSpace(acc.Email), email) {
				return k, acc, true
			}
		}
	}
	return "", domain.Account{}, false
}

func credentialsChanged(a, b domain.AccountCredentials) bool {
	if a.AccessToken != b.AccessToken || a.RefreshToken != b.RefreshToken || a.IDToken != b.IDToken {
		return true
	}
	if !a.Expiry.Equal(b.Expiry) {
		return true
	}
	return false
}

func formatNoReadyError(decision domain.SwitchDecision, now time.Time) error {
	if decision.EarliestReset != nil {
		if rt, ok := domain.DescribeReset(decision.EarliestReset, now, time.UTC); ok && !rt.Due {
			return fmt.Errorf("%w (earliest reset in %s at %s)", ErrNoReadyAccounts, rt.Compact, decision.EarliestReset.UTC().Format(time.RFC3339))
		}
		return fmt.Errorf("%w (earliest reset: %s)", ErrNoReadyAccounts, decision.EarliestReset.UTC().Format(time.RFC3339))
	}
	return ErrNoReadyAccounts
}

func mergeEnv(base, extra []string) []string {
	merged := slices.Clone(base)
	indexByKey := make(map[string]int, len(merged))
	for i, kv := range merged {
		if k, _, ok := strings.Cut(kv, "="); ok {
			indexByKey[envKeyNorm(k)] = i
		}
	}
	for _, kv := range extra {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		norm := envKeyNorm(k)
		if idx, exists := indexByKey[norm]; exists {
			merged[idx] = kv
		} else {
			indexByKey[norm] = len(merged)
			merged = append(merged, kv)
		}
	}
	return merged
}

func envKeyNorm(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}
