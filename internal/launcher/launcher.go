package launcher

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

const headlessCaptureMaxBytes = 64 * 1024

// RunOptions configures launching and managing an agy child process.
type RunOptions struct {
	Binary       string
	Args         []string
	Account      domain.AccountKey
	Model        string
	TargetPool   domain.QuotaPool
	Isolate      bool
	NoRefresh    bool
	AutoRelaunch bool
	// MaxSwitches caps automatic switch-and-relaunch attempts after the initial run (0 disables relaunches).
	MaxSwitches int
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	ExtraEnv    []string
	Now         func() time.Time
}

// RunResult summarizes the child exit code and any account switches executed during Run.
type RunResult struct {
	ExitCode    int
	Switches    []domain.SwitchAuditEntry
	LastAccount domain.AccountKey
	Decision    domain.SwitchDecision
}

type pendingSwitch struct {
	fromKey domain.AccountKey
	reason  string
	trigger string
	at      time.Time
}

// Run prepares an eligible account, executes agy (directly attached in interactive mode or
// output-teed in headless -p mode), syncs back refreshed tokens, and performs bounded automatic
// relaunches/retries on quota exhaustion.
func Run(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	fetcher quota.QuotaFetcher,
	sel selector.Selector,
	opts RunOptions,
) (RunResult, error) {
	if st == nil {
		return RunResult{ExitCode: 1}, errors.New("launcher run: nil store")
	}
	if sel == nil {
		sel = selector.NewDefaultSelector()
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	binary := strings.TrimSpace(opts.Binary)
	if binary == "" {
		binary = "agy"
	}

	paths := st.Paths()
	_ = hook.ClearSwitchSignals(paths)

	headless := isHeadlessArgs(opts.Args)
	args := slices.Clone(opts.Args)
	excluded := make(map[domain.AccountKey]bool)
	nextAccount := opts.Account
	switchesUsed := 0
	var pending *pendingSwitch
	var result RunResult

	for {
		now := nowFn().UTC()
		prepared, err := prepareWithFallback(ctx, st, oauthClient, fetcher, sel, PrepareOptions{
			Account:    nextAccount,
			Model:      opts.Model,
			TargetPool: opts.TargetPool,
			Isolate:    opts.Isolate,
			NoRefresh:  opts.NoRefresh,
			Exclude:    excluded,
			Now:        now,
		}, nextAccount != opts.Account)
		if err != nil {
			result.ExitCode = 1
			if prepared.Decision.Outcome != "" {
				result.Decision = prepared.Decision
			}
			return result, err
		}

		result.LastAccount = prepared.Account.Key
		result.Decision = prepared.Decision

		if pending != nil {
			entry := domain.SwitchAuditEntry{
				At:      pending.at,
				Outcome: domain.OutcomeSwitched,
				FromKey: pending.fromKey,
				ToKey:   prepared.Account.Key,
				Reason:  pending.reason,
				Pool:    prepared.Decision.Pool,
				Trigger: pending.trigger,
			}
			result.Switches = append(result.Switches, entry)
			_, _ = st.Update(ctx, func(s *domain.StoreState) error {
				s.LastSwitch = &entry
				return nil
			})
			pending = nil
		}

		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = mergeEnv(prepared.Env, opts.ExtraEnv)

		var capBuf *cappedTailBuffer
		if headless {
			stdout := opts.Stdout
			if stdout == nil {
				stdout = os.Stdout
			}
			stderr := opts.Stderr
			if stderr == nil {
				stderr = os.Stderr
			}
			capBuf = newCappedTailBuffer(headlessCaptureMaxBytes)
			cmd.Stdin = opts.Stdin
			cmd.Stdout = io.MultiWriter(stdout, capBuf)
			cmd.Stderr = io.MultiWriter(stderr, capBuf)
		} else {
			if opts.Stdin != nil {
				cmd.Stdin = opts.Stdin
			} else {
				cmd.Stdin = os.Stdin
			}
			if opts.Stdout != nil {
				cmd.Stdout = opts.Stdout
			} else {
				cmd.Stdout = os.Stdout
			}
			if opts.Stderr != nil {
				cmd.Stderr = opts.Stderr
			} else {
				cmd.Stderr = os.Stderr
			}
		}

		runErr := cmd.Run()
		syncSessionAuthAfterRun(ctx, st, prepared, nowFn().UTC())

		if ctx.Err() != nil {
			result.ExitCode = 1
			_ = hook.ClearSwitchSignals(paths)
			return result, ctx.Err()
		}

		sig, hasSignal, _ := hook.ReadLatestSwitchSignal(paths)
		if hasSignal {
			_ = hook.ClearSwitchSignals(paths)
		}

		if runErr == nil {
			result.ExitCode = 0
			if !headless && opts.AutoRelaunch && switchesUsed < opts.MaxSwitches && hasSignal && sig.ToKey != "" && sig.ToKey != prepared.Account.Key {
				excluded[prepared.Account.Key] = true
				result.Switches = append(result.Switches, domain.SwitchAuditEntry{
					At:      sig.At,
					Outcome: domain.OutcomeSwitched,
					FromKey: prepared.Account.Key,
					ToKey:   sig.ToKey,
					Reason:  sig.Reason,
					Trigger: "hook_stop",
				})
				if !opts.Isolate {
					args = withConversationArg(args, sig.ConversationID, false)
				}
				nextAccount = sig.ToKey
				switchesUsed++
				continue
			}
			return result, nil
		}

		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			result.ExitCode = 1
			return result, runErr
		}
		result.ExitCode = exitErr.ExitCode()

		if !headless {
			if opts.AutoRelaunch && switchesUsed < opts.MaxSwitches && hasSignal && sig.ToKey != "" && sig.ToKey != prepared.Account.Key {
				excluded[prepared.Account.Key] = true
				result.Switches = append(result.Switches, domain.SwitchAuditEntry{
					At:      sig.At,
					Outcome: domain.OutcomeSwitched,
					FromKey: prepared.Account.Key,
					ToKey:   sig.ToKey,
					Reason:  sig.Reason,
					Trigger: "hook_stop",
				})
				if !opts.Isolate {
					args = withConversationArg(args, sig.ConversationID, false)
				}
				nextAccount = sig.ToKey
				switchesUsed++
				continue
			}
			return result, nil
		}

		if switchesUsed >= opts.MaxSwitches {
			return result, nil
		}

		if hasSignal && sig.ToKey != "" {
			excluded[prepared.Account.Key] = true
			result.Switches = append(result.Switches, domain.SwitchAuditEntry{
				At:      sig.At,
				Outcome: domain.OutcomeSwitched,
				FromKey: prepared.Account.Key,
				ToKey:   sig.ToKey,
				Reason:  sig.Reason,
				Trigger: "hook_stop",
			})
			if !opts.Isolate {
				args = withConversationArg(args, sig.ConversationID, true)
			}
			nextAccount = sig.ToKey
			switchesUsed++
			continue
		}

		captured := capBuf.String()
		exhausted, retryDur := selector.IsQuotaExhaustedError(captured)
		if !exhausted {
			return result, nil
		}

		switchAt := nowFn().UTC()
		markHeadlessCooldown(ctx, st, prepared.Account.Key, opts.TargetPool, opts.Model, retryDur, switchAt)
		excluded[prepared.Account.Key] = true
		nextAccount = ""
		switchesUsed++
		pending = &pendingSwitch{
			fromKey: prepared.Account.Key,
			reason:  "headless quota exhausted",
			trigger: "launcher_headless",
			at:      switchAt,
		}
	}
}

func prepareWithFallback(
	ctx context.Context,
	st store.Store,
	oauthClient oauth.OAuthClient,
	fetcher quota.QuotaFetcher,
	sel selector.Selector,
	opts PrepareOptions,
	allowFallback bool,
) (PreparedLaunch, error) {
	prepared, err := PrepareLaunch(ctx, st, oauthClient, fetcher, sel, opts)
	if err == nil || !allowFallback || opts.Account == "" || ctx.Err() != nil {
		return prepared, err
	}
	opts.Account = ""
	return PrepareLaunch(ctx, st, oauthClient, fetcher, sel, opts)
}

func markHeadlessCooldown(
	ctx context.Context,
	st store.Store,
	key domain.AccountKey,
	targetPool domain.QuotaPool,
	model string,
	retryDur *time.Duration,
	now time.Time,
) {
	_, _ = st.Update(ctx, func(s *domain.StoreState) error {
		acc, ok := s.Accounts[key]
		if !ok {
			return nil
		}
		var resetAt *time.Time
		pool := targetPool
		if pool == "" {
			pool = s.Policy.TargetPool
			if m := strings.TrimSpace(model); m != "" {
				if acc.Quota != nil {
					if inferred := acc.Quota.InferPoolForModel(m); inferred != domain.PoolOther {
						pool = inferred
					}
				} else if inferred := domain.ClassifyPool(m); inferred != domain.PoolOther {
					pool = inferred
				}
			}
		}
		if retryDur != nil && *retryDur > 0 {
			t := now.Add(*retryDur).UTC()
			resetAt = &t
		} else if acc.Quota != nil {
			if _, poolReset, hasPool := acc.Quota.PoolRemaining(pool); hasPool && poolReset != nil && poolReset.After(now) {
				t := poolReset.UTC()
				resetAt = &t
			}
		}
		selector.MarkAccountCooldown(&acc, resetAt, "quota exhausted (headless)", s.Policy.CooldownDefault, now)
		selector.MarkPoolExhausted(&acc, pool, acc.Health.CooldownUntil)
		s.Accounts[key] = acc
		return nil
	})
}

func isHeadlessArgs(args []string) bool {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "-p" || a == "--print" || a == "--prompt" ||
			strings.HasPrefix(a, "-p=") || strings.HasPrefix(a, "--print=") || strings.HasPrefix(a, "--prompt=") {
			return true
		}
	}
	return false
}

func withConversationArg(args []string, cid string, forceUpdate bool) []string {
	cleanID := strings.TrimSpace(cid)
	out := slices.Clone(args)
	if cleanID == "" {
		return out
	}

	hasAnyResumeFlag := false
	for i := 0; i < len(out); i++ {
		a := out[i]
		if a == "--" {
			break
		}
		switch {
		case a == "--conversation":
			hasAnyResumeFlag = true
			if forceUpdate && i+1 < len(out) {
				out[i+1] = cleanID
				return out
			}
		case strings.HasPrefix(a, "--conversation="):
			hasAnyResumeFlag = true
			if forceUpdate {
				out[i] = "--conversation=" + cleanID
				return out
			}
		case a == "-c" || a == "--continue" || a == "--resume" || strings.HasPrefix(a, "--resume="):
			hasAnyResumeFlag = true
		}
	}

	if hasAnyResumeFlag {
		return out
	}

	// Prepend before positional arguments so agy's stdlib flag parser sees --conversation.
	return append([]string{"--conversation", cleanID}, out...)
}

type cappedTailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newCappedTailBuffer(maxBytes int) *cappedTailBuffer {
	return &cappedTailBuffer{max: maxBytes}
}

func (b *cappedTailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.max <= 0 {
		return len(p), nil
	}
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return len(p), nil
	}
	excess := len(b.buf) + len(p) - b.max
	if excess > 0 {
		copy(b.buf, b.buf[excess:])
		b.buf = b.buf[:len(b.buf)-excess]
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *cappedTailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
