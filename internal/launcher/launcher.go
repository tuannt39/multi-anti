package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

const (
	headlessCaptureMaxBytes   = 64 * 1024
	defaultSignalPollInterval = 200 * time.Millisecond
	defaultSignalGraceDelay   = 400 * time.Millisecond
)

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
	MaxSwitches        int
	SignalPollInterval time.Duration
	SignalGraceDelay   time.Duration
	Stdin              io.Reader
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
	runID := newRunID()
	_ = os.Remove(hook.LatestSignalPath(paths))
	defer func() {
		_ = hook.ClearRunSwitchSignal(paths, runID)
	}()

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
		cmd.Env = mergeEnv(mergeEnv(prepared.Env, []string{"MULTI_ANTI_RUN_ID=" + runID}), opts.ExtraEnv)

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

		var (
			liveSig    domain.HookSwitchSignal
			hasLiveSig bool
			runErr     error
		)
		if !headless && opts.AutoRelaunch && switchesUsed < opts.MaxSwitches {
			liveSig, hasLiveSig, runErr = runInteractiveWithSignalWatch(
				ctx,
				cmd,
				paths,
				runID,
				prepared.Account.Key,
				opts.SignalPollInterval,
				opts.SignalGraceDelay,
				cmd.Stderr,
			)
		} else {
			runErr = cmd.Run()
		}
		syncSessionAuthAfterRun(ctx, st, prepared, nowFn().UTC())

		if ctx.Err() != nil {
			result.ExitCode = 1
			return result, ctx.Err()
		}

		sig, hasSignal := resolveConsumedSwitchSignal(paths, runID, prepared.Account.Key, liveSig, hasLiveSig)

		if runErr == nil {
			result.ExitCode = 0
		} else {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				result.ExitCode = 1
				return result, runErr
			}
			result.ExitCode = exitErr.ExitCode()
		}

		if !headless {
			if opts.AutoRelaunch && switchesUsed < opts.MaxSwitches && hasSignal && sig.ToKey != "" && sig.ToKey != prepared.Account.Key {
				nextAccount, args, switchesUsed = recordStopHookSwitch(&result, excluded, prepared.Account.Key, sig, args, opts.Isolate, false, switchesUsed)
				continue
			}
			return result, nil
		}

		if runErr == nil || switchesUsed >= opts.MaxSwitches {
			return result, nil
		}

		if hasSignal && sig.ToKey != "" && sig.ToKey != prepared.Account.Key {
			nextAccount, args, switchesUsed = recordStopHookSwitch(&result, excluded, prepared.Account.Key, sig, args, opts.Isolate, true, switchesUsed)
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
			if _, poolReset, hasPool := acc.Quota.PoolRemainingAt(pool, now); hasPool && poolReset != nil && poolReset.After(now) {
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

func newRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(b[:]))
	}
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UTC().UnixNano())
}

func runInteractiveWithSignalWatch(
	ctx context.Context,
	cmd *exec.Cmd,
	paths platform.Paths,
	runID string,
	fromKey domain.AccountKey,
	pollInterval time.Duration,
	graceDelay time.Duration,
	stderr io.Writer,
) (domain.HookSwitchSignal, bool, error) {
	if pollInterval <= 0 {
		pollInterval = defaultSignalPollInterval
	}
	if graceDelay <= 0 {
		graceDelay = defaultSignalGraceDelay
	}
	if err := cmd.Start(); err != nil {
		return domain.HookSwitchSignal{}, false, err
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case err := <-waitCh:
			return domain.HookSwitchSignal{}, false, err
		case <-ctx.Done():
			terminateInteractiveChild(cmd, waitCh)
			return domain.HookSwitchSignal{}, false, ctx.Err()
		case <-ticker.C:
			s, ok, _ := hook.ReadRunSwitchSignal(paths, runID)
			if !ok || s.ToKey == "" || s.ToKey == fromKey {
				continue
			}
			graceTimer := time.NewTimer(graceDelay)
			var childErr error
			exitedEarly := false
			select {
			case childErr = <-waitCh:
				graceTimer.Stop()
				exitedEarly = true
			case <-ctx.Done():
				graceTimer.Stop()
				terminateInteractiveChild(cmd, waitCh)
				return domain.HookSwitchSignal{}, false, ctx.Err()
			case <-graceTimer.C:
			}
			if refreshed, refOK, _ := hook.ReadRunSwitchSignal(paths, runID); refOK && refreshed.ToKey != "" && refreshed.ToKey != fromKey {
				s = refreshed
			}
			if exitedEarly {
				return s, true, childErr
			}
			terminateInteractiveChild(cmd, waitCh)
			if stderr != nil {
				fmt.Fprintf(stderr, "\n[multi-anti] Quota exhausted on %s; switching to %s and continuing session...\n", fromKey, s.ToKey)
			}
			return s, true, nil
		}
	}
}

func terminateInteractiveChild(cmd *exec.Cmd, waitCh <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
		<-waitCh
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-waitCh
	}
}

func resolveConsumedSwitchSignal(
	paths platform.Paths,
	runID string,
	launchedKey domain.AccountKey,
	liveSig domain.HookSwitchSignal,
	hasLiveSig bool,
) (domain.HookSwitchSignal, bool) {
	sig := liveSig
	hasSignal := hasLiveSig
	if !hasSignal {
		if runSig, ok, _ := hook.ReadRunSwitchSignal(paths, runID); ok && runSig.ToKey != "" {
			sig = runSig
			hasSignal = true
		} else if latestSig, ok, _ := hook.ReadLatestSwitchSignal(paths); ok &&
			(latestSig.FromKey == "" || latestSig.FromKey == launchedKey) {
			if latestSig.ToKey != "" {
				sig = latestSig
				hasSignal = true
			} else {
				_ = os.Remove(hook.LatestSignalPath(paths))
			}
		}
	}
	_ = hook.ClearRunSwitchSignal(paths, runID)
	if hasSignal {
		_ = os.Remove(hook.LatestSignalPath(paths))
		if cid := strings.TrimSpace(sig.ConversationID); cid != "" {
			_ = os.Remove(hook.SignalPath(paths, cid))
		}
	}
	return sig, hasSignal
}

func recordStopHookSwitch(
	result *RunResult,
	excluded map[domain.AccountKey]bool,
	fromKey domain.AccountKey,
	sig domain.HookSwitchSignal,
	args []string,
	isolate bool,
	headless bool,
	switchesUsed int,
) (domain.AccountKey, []string, int) {
	excluded[fromKey] = true
	result.Switches = append(result.Switches, domain.SwitchAuditEntry{
		At:      sig.At,
		Outcome: domain.OutcomeSwitched,
		FromKey: fromKey,
		ToKey:   sig.ToKey,
		Reason:  sig.Reason,
		Trigger: "hook_stop",
	})
	if !isolate {
		if headless {
			args = withConversationArg(args, sig.ConversationID)
		} else {
			args = withInteractiveResumeArgs(args, sig.ConversationID)
		}
	}
	return sig.ToKey, args, switchesUsed + 1
}

type parsedResumeFlag struct {
	matched    bool
	convID     string
	isContinue bool
	isConvFlag bool
	eqPrefix   string
	nextIndex  int
}

func parseResumeFlag(args []string, i int) parsedResumeFlag {
	a := args[i]
	switch {
	case a == "--conversation" || a == "--resume" || a == "-r":
		if i+1 < len(args) {
			return parsedResumeFlag{matched: true, isConvFlag: true, convID: strings.TrimSpace(args[i+1]), nextIndex: i + 1}
		}
		return parsedResumeFlag{matched: true, isConvFlag: true, nextIndex: i}
	case a == "-c" || a == "--continue":
		return parsedResumeFlag{matched: true, isContinue: true, nextIndex: i}
	}
	for _, pref := range []string{"--conversation=", "--resume=", "-r="} {
		if strings.HasPrefix(a, pref) {
			return parsedResumeFlag{
				matched:    true,
				isConvFlag: true,
				convID:     strings.TrimSpace(strings.TrimPrefix(a, pref)),
				eqPrefix:   pref,
				nextIndex:  i,
			}
		}
	}
	return parsedResumeFlag{nextIndex: i}
}

func withInteractiveResumeArgs(args []string, cid string) []string {
	splitIdx := slices.Index(args, "--")
	pre := args
	var post []string
	if splitIdx >= 0 {
		pre = args[:splitIdx]
		post = args[splitIdx:]
	}

	var existingCID string
	hadContinue := false
	filtered := make([]string, 0, len(pre))

	for i := 0; i < len(pre); i++ {
		if rf := parseResumeFlag(pre, i); rf.matched {
			if rf.isContinue {
				hadContinue = true
			} else if existingCID == "" && rf.convID != "" {
				existingCID = rf.convID
			}
			i = rf.nextIndex
			continue
		}
		a := pre[i]
		switch {
		case a == "-i" || a == "--prompt-interactive":
			if i+1 < len(pre) {
				i++
			}
		case strings.HasPrefix(a, "-i=") || strings.HasPrefix(a, "--prompt-interactive="):
		default:
			filtered = append(filtered, a)
		}
	}

	targetCID := strings.TrimSpace(cid)
	if targetCID == "" {
		targetCID = existingCID
	}
	var resume []string
	switch {
	case targetCID != "":
		resume = []string{"--conversation", targetCID, "-i", "continue"}
	case hadContinue:
		resume = []string{"--continue", "-i", "continue"}
	default:
		return slices.Clone(args)
	}

	out := make([]string, 0, len(resume)+len(filtered)+len(post))
	out = append(out, resume...)
	out = append(out, filtered...)
	out = append(out, post...)
	return out
}

func withConversationArg(args []string, cid string) []string {
	cleanID := strings.TrimSpace(cid)
	out := slices.Clone(args)
	if cleanID == "" {
		return out
	}

	hasAnyResumeFlag := false
	for i := 0; i < len(out); i++ {
		if out[i] == "--" {
			break
		}
		rf := parseResumeFlag(out, i)
		if !rf.matched {
			continue
		}
		hasAnyResumeFlag = true
		if rf.isConvFlag {
			if rf.eqPrefix != "" {
				out[i] = rf.eqPrefix + cleanID
				return out
			}
			if rf.nextIndex > i {
				out[rf.nextIndex] = cleanID
				return out
			}
		}
		i = rf.nextIndex
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
