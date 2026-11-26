package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/tuannt/multi-anti/internal/domain"
	"github.com/tuannt/multi-anti/internal/hook"
	"github.com/tuannt/multi-anti/internal/launcher"
	"github.com/tuannt/multi-anti/internal/oauth"
	"github.com/tuannt/multi-anti/internal/platform"
	"github.com/tuannt/multi-anti/internal/quota"
	"github.com/tuannt/multi-anti/internal/selector"
	"github.com/tuannt/multi-anti/internal/store"
)

const (
	defaultWatchInterval = 30 * time.Second
	defaultLoginTimeout  = 3 * time.Minute
	defaultMaxSwitches   = 3
	maxHookStdinBytes    = 4 * 1024 * 1024
)

// Config configures the multi-anti CLI runtime and injectable dependencies.
type Config struct {
	Version       string
	BinaryCommand string
	AgyBinary     string
	Paths         *platform.Paths
	Store         store.Store
	OAuth         oauth.OAuthClient
	Fetcher       quota.QuotaFetcher
	Selector      selector.Selector
	OpenBrowserFn func(url string) error
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Now           func() time.Time
}

// App dispatches multi-anti CLI commands with configured dependencies.
type App struct {
	version       string
	binCmd        string
	agyBin        string
	paths         *platform.Paths
	store         store.Store
	oauth         oauth.OAuthClient
	fetcher       quota.QuotaFetcher
	selector      selector.Selector
	openBrowserFn func(url string) error
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	now           func() time.Time
	goos          string
	hasPaths      bool
	pathsData     platform.Paths
}

// NewApp constructs an App with defaults applied for omitted Config fields.
func NewApp(cfg Config) *App {
	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = "dev"
	}
	agyBin := strings.TrimSpace(cfg.AgyBinary)
	if agyBin == "" {
		agyBin = "agy"
	}
	binCmd := strings.TrimSpace(cfg.BinaryCommand)
	if binCmd == "" {
		binCmd = resolveBinaryCommand()
	}

	oauthClient := cfg.OAuth
	if oauthClient == nil {
		oauthClient = oauth.NewGoogleOAuthClient(oauth.Config{})
	}
	fetcher := cfg.Fetcher
	if fetcher == nil {
		fetcher = quota.NewCloudCodeFetcher(quota.FetcherConfig{})
	}
	sel := cfg.Selector
	if sel == nil {
		sel = selector.NewDefaultSelector()
	}

	stdin := cfg.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	openBrowserFn := cfg.OpenBrowserFn
	if openBrowserFn == nil {
		openBrowserFn = oauth.OpenBrowser
	}

	app := &App{
		version:       version,
		binCmd:        binCmd,
		agyBin:        agyBin,
		paths:         cfg.Paths,
		store:         cfg.Store,
		oauth:         oauthClient,
		fetcher:       fetcher,
		selector:      sel,
		openBrowserFn: openBrowserFn,
		stdin:         stdin,
		stdout:        stdout,
		stderr:        stderr,
		now:           nowFn,
		goos:          runtime.GOOS,
	}
	if cfg.Store != nil {
		app.pathsData = cfg.Store.Paths()
		app.hasPaths = true
	} else if cfg.Paths != nil {
		app.pathsData = *cfg.Paths
		app.hasPaths = true
		app.store = store.NewFileStore(app.pathsData)
	}
	return app
}

// Run executes the CLI with args (excluding argv[0]) and returns the process exit code.
func Run(ctx context.Context, args []string, cfg Config) int {
	return NewApp(cfg).Run(ctx, args)
}

// Run executes the CLI command specified by args and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printRootHelp(a.stdout)
		return 0
	}

	cmd := strings.TrimSpace(args[0])
	rest := args[1:]

	switch cmd {
	case "help", "-h", "--help":
		return a.cmdHelp(rest)
	case "version", "-v", "--version":
		return a.cmdVersion(rest)
	case "login":
		return a.cmdLogin(ctx, rest)
	case "import":
		return a.cmdImport(ctx, rest)
	case "accounts", "list", "ls":
		return a.cmdAccounts(ctx, rest)
	case "quota", "usage", "status":
		return a.cmdQuota(ctx, rest)
	case "switch":
		return a.cmdSwitch(ctx, rest, false)
	case "next":
		return a.cmdSwitch(ctx, rest, true)
	case "run", "agy":
		return a.cmdRun(ctx, rest)
	case "policy":
		return a.cmdPolicy(ctx, rest)
	case "enable":
		return a.cmdSetHealth(ctx, "enable", rest)
	case "disable":
		return a.cmdSetHealth(ctx, "disable", rest)
	case "priority":
		return a.cmdPriority(ctx, rest)
	case "remove", "rm":
		return a.cmdRemove(ctx, rest)
	case "plugin":
		return a.cmdPlugin(ctx, rest)
	case "statusline":
		return a.cmdStatusLine(ctx, rest)
	case "hook":
		return a.cmdHook(ctx, rest)
	case "doctor":
		return a.cmdDoctor(ctx, rest)
	case "restore", "restore-native":
		return a.cmdRestore(ctx, rest)
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\nRun 'multi-anti help' for usage.\n", cmd)
		return 2
	}
}

func (a *App) currentTime() time.Time {
	return a.now().UTC()
}

func (a *App) ensurePaths() (platform.Paths, error) {
	if a.hasPaths {
		return a.pathsData, nil
	}
	p, err := platform.ResolvePaths()
	if err != nil {
		return platform.Paths{}, err
	}
	a.pathsData = p
	a.hasPaths = true
	return p, nil
}

func (a *App) ensureStore() (store.Store, platform.Paths, error) {
	paths, err := a.ensurePaths()
	if err != nil {
		return nil, platform.Paths{}, err
	}
	if a.store == nil {
		a.store = store.NewFileStore(paths)
	}
	return a.store, a.store.Paths(), nil
}

func (a *App) fail(err error) int {
	fmt.Fprintf(a.stderr, "error: %v\n", err)
	return 1
}

func (a *App) usageFail(msg string) int {
	fmt.Fprintf(a.stderr, "error: %s\n", msg)
	return 2
}

func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func (a *App) cmdVersion(args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("version", a.stdout)
		return 0
	}
	if len(args) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", args[0]))
	}
	fmt.Fprintf(a.stdout, "multi-anti %s\n", a.version)
	return 0
}

func (a *App) cmdHelp(args []string) int {
	if len(args) == 0 {
		a.printRootHelp(a.stdout)
		return 0
	}
	if !a.printSubcommandHelp(args[0], a.stdout) {
		fmt.Fprintf(a.stderr, "unknown command %q\n", args[0])
		a.printRootHelp(a.stderr)
		return 2
	}
	return 0
}

func (a *App) cmdLogin(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("login", a.stdout)
		return 0
	}

	fs := a.newFlagSet("login")
	noBrowser := fs.Bool("no-browser", false, "")
	timeout := fs.Duration("timeout", defaultLoginTimeout, "")
	priority := fs.Int("priority", 0, "")
	alias := fs.String("alias", "", "")
	noRefresh := fs.Bool("no-refresh", false, "")
	agyBinFlag := fs.String("agy-bin", "", "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[0]))
	}
	if *timeout <= 0 {
		return a.usageFail("--timeout must be positive")
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	effectiveAgyBin := a.agyBin
	if strings.TrimSpace(*agyBinFlag) != "" {
		effectiveAgyBin = strings.TrimSpace(*agyBinFlag)
	}

	identity, creds, err := a.oauth.Login(ctx, oauth.LoginOptions{
		NoBrowser:    *noBrowser,
		ManualInput:  a.stdin,
		PromptOutput: a.stderr,
		Timeout:      *timeout,
	})
	if errors.Is(err, oauth.ErrMissingClientID) {
		identity, creds, err = a.loginViaAgy(ctx, effectiveAgyBin, *noBrowser, *timeout)
	}
	if err != nil {
		return a.fail(err)
	}

	key := identity.Key
	if strings.TrimSpace(string(key)) == "" {
		key, err = domain.NormalizeAccountKey(identity.Email, identity.AccountID)
		if err != nil {
			return a.fail(err)
		}
		identity.Key = key
	}

	now := a.currentTime()
	hasPriority := flagVisited(fs, "priority")
	hasAlias := flagVisited(fs, "alias")

	state, err := st.Update(ctx, func(s *domain.StoreState) error {
		upsertAccount(s, identity, creds, upsertOptions{
			Priority:    *priority,
			HasPriority: hasPriority,
			Alias:       *alias,
			HasAlias:    hasAlias,
			Now:         now,
		})
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	var warnings []string
	if !*noRefresh && a.fetcher != nil {
		results, refErr := quota.RefreshAndFetchAll(ctx, st, a.oauth, a.fetcher, []domain.AccountKey{key}, quota.FetchOptions{Now: now})
		if refErr != nil {
			warnings = append(warnings, fmt.Sprintf("quota refresh failed: %v", refErr))
		} else {
			for _, r := range results {
				if r.Err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: quota refresh failed: %v", r.Key, r.Err))
				}
			}
		}
		if latest, loadErr := st.Load(ctx); loadErr == nil {
			state = latest
		}
	}

	acc := state.Accounts[key]
	if *jsonOut {
		view := ImportResultView{
			ActiveKey: state.ActiveKey,
			Imported:  []AccountView{buildAccountView(acc, state.ActiveKey, state.Policy.TargetPool, true, now)},
			Warnings:  warnings,
		}
		if err := writeJSON(a.stdout, view); err != nil {
			return a.fail(err)
		}
		return 0
	}

	for _, w := range warnings {
		fmt.Fprintf(a.stderr, "warning: %s\n", w)
	}
	activeNote := ""
	if state.ActiveKey == key {
		activeNote = " (active)"
	}
	fmt.Fprintf(a.stdout, "Logged in %s%s\n", formatAccountLabel(acc), activeNote)
	return 0
}

const agyAuthURLPrefix = "https://accounts.google.com/"

func (a *App) loginViaAgy(ctx context.Context, agyBin string, noBrowser bool, timeout time.Duration) (domain.AccountIdentity, domain.AccountCredentials, error) {
	resolvedAgy, err := exec.LookPath(agyBin)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("resolve agy binary %q: %w", agyBin, err)
	}

	tmpHome, err := os.MkdirTemp("", "multi-anti-agy-login-*")
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("create isolated login home: %w", err)
	}
	defer os.RemoveAll(tmpHome)

	agyDir := filepath.Join(tmpHome, ".gemini", "antigravity-cli")
	dirs := []string{agyDir}
	if runtime.GOOS != "windows" {
		dirs = append(dirs,
			filepath.Join(tmpHome, ".config"),
			filepath.Join(tmpHome, ".local", "share"),
			filepath.Join(tmpHome, ".cache"),
		)
	}
	for _, d := range dirs {
		if err := platform.EnsurePrivateDir(d); err != nil {
			return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("prepare isolated agy dir %q: %w", d, err)
		}
	}

	if timeout <= 0 {
		timeout = defaultLoginTimeout
	}
	loginCtx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()
	agyCtx, cancelAgy := context.WithCancel(loginCtx)
	defer cancelAgy()

	cmd := exec.CommandContext(agyCtx, resolvedAgy, "-p", "OK")
	cmd.Env = buildAgyLoginEnv(os.Environ(), tmpHome)
	cmd.Stdin = a.stdin
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("create agy stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdoutPipe.Close()
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("create agy stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("start agy login: %w", err)
	}

	forwarder := &agyOutputForwarder{
		stderr:        a.stderr,
		openBrowserFn: a.openBrowserFn,
		noBrowser:     noBrowser,
	}

	var pipeWG sync.WaitGroup
	pipeWG.Add(2)
	go func() {
		defer pipeWG.Done()
		forwarder.streamPipe(stdoutPipe)
	}()
	go func() {
		defer pipeWG.Done()
		forwarder.streamPipe(stderrPipe)
	}()

	waitDone := make(chan error, 1)
	go func() {
		// Drain pipe readers before Wait so Wait never closes pipes out from under active reads.
		pipeWG.Wait()
		waitDone <- cmd.Wait()
	}()

	finishAgyProcess := func() {
		cancelAgy()
		timer := time.NewTimer(cmd.WaitDelay + time.Second)
		defer timer.Stop()
		select {
		case <-waitDone:
		case <-timer.C:
			_ = stdoutPipe.Close()
			_ = stderrPipe.Close()
			<-waitDone
		}
		pipeWG.Wait()
	}

	tokenPath := filepath.Join(agyDir, "antigravity-oauth-token")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if id, creds, ok := readValidAgyLoginToken(tokenPath); ok {
				forwarder.Mute()
				finishAgyProcess()
				return id, creds, nil
			}
		case waitErr := <-waitDone:
			pipeWG.Wait()
			if id, creds, ok := readValidAgyLoginToken(tokenPath); ok {
				return id, creds, nil
			}
			if waitErr != nil {
				return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("agy login failed: %w", waitErr)
			}
			return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("agy login failed: agy exited without writing %s", tokenPath)
		case <-loginCtx.Done():
			finishAgyProcess()
			if id, creds, ok := readValidAgyLoginToken(tokenPath); ok && ctx.Err() == nil {
				return id, creds, nil
			}
			if err := ctx.Err(); err != nil {
				return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("agy login failed: %w", err)
			}
			return domain.AccountIdentity{}, domain.AccountCredentials{}, fmt.Errorf("agy login failed: %w", loginCtx.Err())
		}
	}
}

type agyOutputForwarder struct {
	mu            sync.Mutex
	stderr        io.Writer
	openBrowserFn func(url string) error
	noBrowser     bool
	browserOpened bool
	muted         bool
}

func (f *agyOutputForwarder) Mute() {
	f.mu.Lock()
	f.muted = true
	f.mu.Unlock()
}

func (f *agyOutputForwarder) claimBrowserOpen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.browserOpened || f.muted {
		return false
	}
	f.browserOpened = true
	return true
}

func (f *agyOutputForwarder) streamPipe(r io.Reader) {
	const maxScanBuf = 16 * 1024
	buf := make([]byte, 4096)
	var scanBuf string
	extractURL := !f.noBrowser && f.openBrowserFn != nil

	processChunk := func(atEOF bool) {
		if !extractURL {
			return
		}
		idx := strings.Index(scanBuf, agyAuthURLPrefix)
		if idx < 0 {
			if !atEOF && len(scanBuf) > len(agyAuthURLPrefix)-1 {
				scanBuf = scanBuf[len(scanBuf)-(len(agyAuthURLPrefix)-1):]
			} else if atEOF {
				scanBuf = ""
			}
			return
		}

		rest := scanBuf[idx:]
		end := strings.IndexFunc(rest, unicode.IsSpace)
		if end < 0 {
			if !atEOF {
				if len(rest) > maxScanBuf {
					rest = rest[:maxScanBuf]
				}
				scanBuf = rest
				return
			}
			end = len(rest)
		}

		urlStr := rest[:end]
		extractURL = false
		scanBuf = ""
		if f.claimBrowserOpen() {
			if openErr := f.openBrowserFn(urlStr); openErr != nil {
				f.mu.Lock()
				if !f.muted {
					fmt.Fprintf(f.stderr, "Browser launch failed (%v); open the URL above manually.\n", openErr)
				}
				f.mu.Unlock()
			}
		}
	}

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			f.mu.Lock()
			if !f.muted {
				_, _ = f.stderr.Write(buf[:n])
			}
			f.mu.Unlock()
			if extractURL {
				scanBuf += string(buf[:n])
				processChunk(false)
			}
		}
		if readErr != nil {
			if extractURL && scanBuf != "" {
				processChunk(true)
			}
			return
		}
	}
}

func readValidAgyLoginToken(tokenPath string) (domain.AccountIdentity, domain.AccountCredentials, bool) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, false
	}
	id, creds, err := oauth.DecodeAgyTokenFile(data)
	if err != nil {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, false
	}
	if strings.TrimSpace(string(id.Key)) == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, false
	}
	if strings.TrimSpace(creds.AccessToken) == "" && strings.TrimSpace(creds.RefreshToken) == "" {
		return domain.AccountIdentity{}, domain.AccountCredentials{}, false
	}
	return id, creds, true
}

func buildAgyLoginEnv(base []string, tmpHome string) []string {
	removeKeys := map[string]bool{
		envKeyNorm("MULTI_ANTI_MANAGED"):  true,
		envKeyNorm("MULTI_ANTI_ACCOUNT"):  true,
		envKeyNorm("MULTI_ANTI_ISOLATED"): true,
		envKeyNorm("MULTI_ANTI_RUN_ID"):   true,
		envKeyNorm("MULTI_ANTI_HOME"):     true,
		envKeyNorm("MULTI_ANTI_AGY_HOME"): true,
		envKeyNorm("HOME"):                true,
		envKeyNorm("USERPROFILE"):         true,
		envKeyNorm("SSH_TTY"):             true,
	}
	overrides := []string{
		"HOME=" + tmpHome,
		"USERPROFILE=" + tmpHome,
		"SSH_TTY=multi-anti",
	}
	if runtime.GOOS != "windows" {
		removeKeys[envKeyNorm("XDG_CONFIG_HOME")] = true
		removeKeys[envKeyNorm("XDG_DATA_HOME")] = true
		removeKeys[envKeyNorm("XDG_CACHE_HOME")] = true
		overrides = append(overrides,
			"XDG_CONFIG_HOME="+filepath.Join(tmpHome, ".config"),
			"XDG_DATA_HOME="+filepath.Join(tmpHome, ".local", "share"),
			"XDG_CACHE_HOME="+filepath.Join(tmpHome, ".cache"),
		)
	}

	env := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if removeKeys[envKeyNorm(k)] {
			continue
		}
		env = append(env, kv)
	}
	return append(env, overrides...)
}

func envKeyNorm(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

type importedCredentialRecord struct {
	identity    domain.AccountIdentity
	creds       domain.AccountCredentials
	priority    int
	hasPriority bool
	alias       string
	hasAlias    bool
}

func (a *App) cmdImport(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("import", a.stdout)
		return 0
	}

	fs := a.newFlagSet("import")
	native := fs.Bool("native", false, "")
	priority := fs.Int("priority", 0, "")
	alias := fs.String("alias", "", "")
	noRefresh := fs.Bool("no-refresh", false, "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 1 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[1]))
	}
	if *native && len(pos) == 1 {
		return a.usageFail("cannot specify both [path] and --native")
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	targetPath := paths.NativeAgyTokenPath()
	if len(pos) == 1 {
		targetPath = pos[0]
	}

	records, err := a.readImportRecords(ctx, targetPath, *native)
	if err != nil {
		return a.fail(err)
	}

	now := a.currentTime()
	flagHasPriority := flagVisited(fs, "priority")
	flagHasAlias := flagVisited(fs, "alias")

	importedKeys := make([]domain.AccountKey, 0, len(records))
	state, err := st.Update(ctx, func(s *domain.StoreState) error {
		for _, rec := range records {
			effPriority := rec.priority
			effHasPriority := rec.hasPriority
			if flagHasPriority {
				effPriority = *priority
				effHasPriority = true
			}
			effAlias := rec.alias
			effHasAlias := rec.hasAlias
			if flagHasAlias {
				effAlias = *alias
				effHasAlias = true
			}
			upsertAccount(s, rec.identity, rec.creds, upsertOptions{
				Priority:    effPriority,
				HasPriority: effHasPriority,
				Alias:       effAlias,
				HasAlias:    effHasAlias,
				Now:         now,
			})
			importedKeys = append(importedKeys, rec.identity.Key)
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	var warnings []string
	if !*noRefresh && a.fetcher != nil && len(importedKeys) > 0 {
		results, refErr := quota.RefreshAndFetchAll(ctx, st, a.oauth, a.fetcher, importedKeys, quota.FetchOptions{Now: now})
		if refErr != nil {
			warnings = append(warnings, fmt.Sprintf("quota refresh failed: %v", refErr))
		} else {
			for _, r := range results {
				if r.Err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: quota refresh failed: %v", r.Key, r.Err))
				}
			}
		}
		if latest, loadErr := st.Load(ctx); loadErr == nil {
			state = latest
		}
	}

	if *jsonOut {
		views := make([]AccountView, 0, len(importedKeys))
		for _, k := range importedKeys {
			if acc, ok := state.Accounts[k]; ok {
				views = append(views, buildAccountView(acc, state.ActiveKey, state.Policy.TargetPool, true, now))
			}
		}
		view := ImportResultView{
			ActiveKey: state.ActiveKey,
			Imported:  views,
			Warnings:  warnings,
		}
		if err := writeJSON(a.stdout, view); err != nil {
			return a.fail(err)
		}
		return 0
	}

	for _, w := range warnings {
		fmt.Fprintf(a.stderr, "warning: %s\n", w)
	}
	for _, k := range importedKeys {
		acc := state.Accounts[k]
		activeNote := ""
		if state.ActiveKey == k {
			activeNote = " (active)"
		}
		fmt.Fprintf(a.stdout, "Imported %s%s\n", formatAccountLabel(acc), activeNote)
	}
	return 0
}

func (a *App) readImportRecords(ctx context.Context, path string, forceNative bool) ([]importedCredentialRecord, error) {
	if !forceNative {
		if raw, err := os.ReadFile(path); err == nil {
			if multi, ok, parseErr := tryParseMultiAccountImport(raw); ok {
				if parseErr != nil {
					return nil, parseErr
				}
				return multi, nil
			}
		}
	}

	identity, creds, err := a.oauth.ImportNativeToken(ctx, path)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(creds.AccessToken) == "" && strings.TrimSpace(creds.RefreshToken) == "" {
		return nil, oauth.ErrMissingToken
	}
	key := identity.Key
	if strings.TrimSpace(string(key)) == "" {
		key, err = domain.NormalizeAccountKey(identity.Email, identity.AccountID)
		if err != nil {
			return nil, err
		}
		identity.Key = key
	}
	return []importedCredentialRecord{{identity: identity, creds: creds}}, nil
}

func tryParseMultiAccountImport(raw []byte) ([]importedCredentialRecord, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, nil
	}

	var items []json.RawMessage
	switch trimmed[0] {
	case '[':
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, true, fmt.Errorf("parse multi-account JSON array: %w", err)
		}
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, false, nil
		}
		rawAccounts, hasAccounts := obj["accounts"]
		if !hasAccounts || isNullJSON(rawAccounts) {
			return nil, false, nil
		}
		if _, hasTok := obj["token"]; hasTok {
			return nil, false, nil
		}
		if _, hasRT := obj["refresh_token"]; hasRT {
			return nil, false, nil
		}
		if _, hasAT := obj["access_token"]; hasAT {
			return nil, false, nil
		}
		accTrim := bytes.TrimSpace(rawAccounts)
		if len(accTrim) == 0 {
			return nil, true, errors.New("multi-account JSON has empty accounts field")
		}
		switch accTrim[0] {
		case '[':
			if err := json.Unmarshal(accTrim, &items); err != nil {
				return nil, true, fmt.Errorf("parse accounts array: %w", err)
			}
		case '{':
			var accMap map[string]json.RawMessage
			if err := json.Unmarshal(accTrim, &accMap); err != nil {
				return nil, true, fmt.Errorf("parse accounts object: %w", err)
			}
			keys := make([]string, 0, len(accMap))
			for k := range accMap {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				items = append(items, accMap[k])
			}
		default:
			return nil, true, errors.New("multi-account JSON accounts must be an array or object")
		}
	default:
		return nil, false, nil
	}

	if len(items) == 0 {
		return nil, true, errors.New("multi-account JSON contains no accounts")
	}

	records := make([]importedCredentialRecord, 0, len(items))
	for i, item := range items {
		rec, err := decodeImportEntry(item)
		if err != nil {
			return nil, true, fmt.Errorf("import entry %d: %w", i, err)
		}
		records = append(records, rec)
	}
	return records, true, nil
}

func decodeImportEntry(raw json.RawMessage) (importedCredentialRecord, error) {
	var meta struct {
		Email       string          `json:"email"`
		AccountID   string          `json:"account_id"`
		DisplayName string          `json:"display_name"`
		Alias       string          `json:"alias"`
		Priority    *int            `json:"priority"`
		Creds       json.RawMessage `json:"creds"`
	}
	_ = json.Unmarshal(raw, &meta)

	decodePayload := raw
	if len(bytes.TrimSpace(meta.Creds)) > 0 && !isNullJSON(meta.Creds) {
		var merged map[string]json.RawMessage
		if err := json.Unmarshal(meta.Creds, &merged); err == nil && merged != nil {
			if meta.Email != "" && merged["email"] == nil {
				if b, err := json.Marshal(meta.Email); err == nil {
					merged["email"] = b
				}
			}
			if meta.AccountID != "" && merged["account_id"] == nil {
				if b, err := json.Marshal(meta.AccountID); err == nil {
					merged["account_id"] = b
				}
			}
			if meta.DisplayName != "" && merged["display_name"] == nil {
				if b, err := json.Marshal(meta.DisplayName); err == nil {
					merged["display_name"] = b
				}
			}
			if b, err := json.Marshal(merged); err == nil {
				decodePayload = b
			}
		}
	}

	identity, creds, err := oauth.DecodeAgyTokenFile(decodePayload)
	if err != nil {
		return importedCredentialRecord{}, err
	}
	alias := strings.TrimSpace(meta.Alias)
	hasAlias := alias != ""
	if !hasAlias && strings.TrimSpace(meta.DisplayName) != "" {
		alias = strings.TrimSpace(meta.DisplayName)
		hasAlias = true
	}

	rec := importedCredentialRecord{
		identity: identity,
		creds:    creds,
		alias:    alias,
		hasAlias: hasAlias,
	}
	if meta.Priority != nil {
		rec.priority = *meta.Priority
		rec.hasPriority = true
	}
	return rec, nil
}

type upsertOptions struct {
	Priority    int
	HasPriority bool
	Alias       string
	HasAlias    bool
	Now         time.Time
}

func upsertAccount(s *domain.StoreState, id domain.AccountIdentity, creds domain.AccountCredentials, opts upsertOptions) {
	if s.Accounts == nil {
		s.Accounts = make(map[domain.AccountKey]domain.Account)
	}
	acc, exists := s.Accounts[id.Key]
	if !exists {
		acc = domain.Account{
			Key:     id.Key,
			AddedAt: opts.Now,
		}
	} else if acc.AddedAt.IsZero() {
		acc.AddedAt = opts.Now
	}

	if e := strings.TrimSpace(id.Email); e != "" {
		acc.Email = e
	}
	if aid := strings.TrimSpace(id.AccountID); aid != "" {
		acc.AccountID = aid
	}
	if opts.HasAlias {
		acc.DisplayName = strings.TrimSpace(opts.Alias)
	} else if acc.DisplayName == "" && strings.TrimSpace(id.DisplayName) != "" {
		acc.DisplayName = strings.TrimSpace(id.DisplayName)
	}
	if opts.HasPriority {
		acc.Priority = opts.Priority
	}

	acc.Creds = creds
	acc.Health = domain.AccountHealth{
		Status:    domain.HealthReady,
		UpdatedAt: opts.Now,
	}
	s.Accounts[id.Key] = acc
	if s.ActiveKey == "" {
		s.ActiveKey = id.Key
	}
}

func (a *App) cmdAccounts(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("accounts", a.stdout)
		return 0
	}

	fs := a.newFlagSet("accounts")
	jsonOut := fs.Bool("json", false, "")
	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[0]))
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}
	now := a.currentTime()
	_, _ = quota.SyncNativeTokenIfFresher(ctx, st, now)

	state, err := st.Load(ctx)
	if err != nil {
		return a.fail(err)
	}

	if *jsonOut {
		keys := sortedAccountKeys(state.Accounts)
		views := make([]AccountView, 0, len(keys))
		for _, k := range keys {
			views = append(views, buildAccountView(state.Accounts[k], state.ActiveKey, state.Policy.TargetPool, false, now))
		}
		out := AccountsListView{
			ActiveKey: state.ActiveKey,
			Policy:    buildPolicyView(state.Policy),
			Accounts:  views,
		}
		if err := writeJSON(a.stdout, out); err != nil {
			return a.fail(err)
		}
		return 0
	}

	renderAccountsTable(a.stdout, state, readNativeTokenSummary(paths), now)
	return 0
}

func (a *App) cmdQuota(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("quota", a.stdout)
		return 0
	}

	args = preprocessWatchFlag(args, defaultWatchInterval)

	fs := a.newFlagSet("quota")
	noRefresh := fs.Bool("no-refresh", false, "")
	cached := fs.Bool("cached", false, "")
	refresh := fs.Bool("refresh", false, "")
	watch := fs.Duration("watch", 0, "")
	models := fs.Bool("models", false, "")
	poolFlag := fs.String("pool", "", "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[0]))
	}
	if (*noRefresh || *cached) && *refresh {
		return a.usageFail("cannot combine --refresh with --no-refresh/--cached")
	}
	watchSet := flagVisited(fs, "watch")
	if watchSet && *watch <= 0 {
		return a.usageFail("--watch interval must be positive")
	}
	targetPool, err := parseTargetPoolFlag(*poolFlag, true)
	if err != nil {
		return a.usageFail(err.Error())
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	liveRefresh := !*noRefresh && !*cached
	runOnce := func() error {
		now := a.currentTime()
		var results []quota.AccountRefreshResult
		if liveRefresh && a.fetcher != nil {
			res, refErr := quota.RefreshAndFetchAll(ctx, st, a.oauth, a.fetcher, nil, quota.FetchOptions{
				IncludeModels: *models,
				Now:           now,
			})
			if refErr != nil {
				return refErr
			}
			results = res
		}
		state, loadErr := st.Load(ctx)
		if loadErr != nil {
			return loadErr
		}
		evalPool := targetPool
		if evalPool == "" && !flagVisited(fs, "pool") {
			evalPool = state.Policy.TargetPool
		}
		ranked := a.selector.Rank(state, selector.EvalRequest{
			TargetPool: evalPool,
			Now:        now,
		})
		report := buildQuotaReportView(state, ranked, results, evalPool, *models, liveRefresh, now)
		if *jsonOut {
			return writeJSON(a.stdout, report)
		}
		renderQuotaReport(a.stdout, report, *models, now)
		return nil
	}

	if err := runOnce(); err != nil {
		return a.fail(err)
	}
	if !watchSet {
		return 0
	}

	ticker := time.NewTicker(*watch)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			if !*jsonOut {
				fmt.Fprintln(a.stdout)
			}
			if err := runOnce(); err != nil {
				if ctx.Err() != nil {
					return 0
				}
				return a.fail(err)
			}
		}
	}
}

func (a *App) cmdSwitch(ctx context.Context, args []string, isNext bool) int {
	cmdName := "switch"
	if isNext {
		cmdName = "next"
	}
	if hasHelpFlag(args) {
		a.printSubcommandHelp(cmdName, a.stdout)
		return 0
	}

	fs := a.newFlagSet(cmdName)
	modelFlag := fs.String("model", "", "")
	poolFlag := fs.String("pool", "", "")
	noRefresh := fs.Bool("no-refresh", false, "")
	force := fs.Bool("force", false, "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if isNext && len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("next does not accept positional target %q", pos[0]))
	}
	if len(pos) > 1 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[1]))
	}

	targetPool, err := parseTargetPoolFlag(*poolFlag, true)
	if err != nil {
		return a.usageFail(err.Error())
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}
	if _, err := st.EnsureNativeBackup(ctx); err != nil {
		return a.fail(fmt.Errorf("ensure native backup: %w", err))
	}

	now := a.currentTime()
	if len(pos) == 1 {
		return a.switchToExplicitAccount(ctx, st, paths, pos[0], *force, *jsonOut, now)
	}
	return a.switchToNextAccount(ctx, st, paths, *modelFlag, targetPool, *noRefresh, *jsonOut, now)
}

func (a *App) switchToExplicitAccount(
	ctx context.Context,
	st store.Store,
	paths platform.Paths,
	targetArg string,
	force bool,
	jsonOut bool,
	now time.Time,
) int {
	_, _ = quota.SyncNativeTokenIfFresher(ctx, st, now)
	state, err := st.Load(ctx)
	if err != nil {
		return a.fail(err)
	}
	key, err := resolveAccountKey(state, targetArg)
	if err != nil {
		return a.fail(err)
	}
	acc := state.Accounts[key]
	eff := acc.Health.EffectiveStatus(now)
	switch eff {
	case domain.HealthDisabled, domain.HealthNeedsReauth:
		return a.fail(fmt.Errorf("cannot switch to %s: account is %s (%s)", key, eff, acc.Health.Reason))
	case domain.HealthCooldown:
		if !force {
			rem := ""
			if acc.Health.CooldownUntil != nil && acc.Health.CooldownUntil.After(now) {
				rem = fmt.Sprintf(" (resets in %s; pass --force to override)", formatDurationShort(acc.Health.CooldownUntil.Sub(now)))
			} else {
				rem = " (pass --force to override)"
			}
			return a.fail(fmt.Errorf("cannot switch to %s: account is in cooldown%s", key, rem))
		}
	}

	creds := acc.Creds
	if a.oauth != nil && oauth.NeedsRefresh(creds, state.Policy.RefreshSkew, now) {
		refreshed, _, _, refreshErr := quota.RefreshAccountToken(ctx, st, a.oauth, key, state.Policy.RefreshSkew, now, quota.RefreshIfExpiring)
		if refreshErr != nil {
			if errors.Is(refreshErr, oauth.ErrRefreshRevoked) || !quota.CanStageWithoutRefresh(creds, refreshErr) {
				return a.fail(refreshErr)
			}
		} else {
			creds = refreshed
		}
	}

	encoded, err := oauth.EncodeVerifiedAgyToken(acc, creds)
	if err != nil {
		return a.fail(err)
	}
	var prevActive domain.AccountKey
	updated, err := st.Update(ctx, func(s *domain.StoreState) error {
		cur, ok := s.Accounts[key]
		if !ok {
			return fmt.Errorf("account %q not found", key)
		}
		if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), encoded, true); err != nil {
			return fmt.Errorf("stage native token: %w", err)
		}
		prevActive = s.ActiveKey
		usedAt := now
		cur.LastUsedAt = &usedAt
		s.Accounts[key] = cur
		s.ActiveKey = key
		s.LastSwitch = &domain.SwitchAuditEntry{
			At:      now,
			Outcome: domain.OutcomeSwitched,
			FromKey: prevActive,
			ToKey:   key,
			Reason:  "manual cli switch",
			Trigger: "cli_switch",
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	finalAcc := updated.Accounts[key]
	if jsonOut {
		view := SwitchResultView{
			Outcome: domain.OutcomeSwitched,
			FromKey: prevActive,
			ToKey:   key,
			Reason:  "manual cli switch",
			Account: ptrAccountView(buildAccountView(finalAcc, updated.ActiveKey, updated.Policy.TargetPool, false, now)),
		}
		if err := writeJSON(a.stdout, view); err != nil {
			return a.fail(err)
		}
		return 0
	}
	fmt.Fprintf(a.stdout, "Switched active account to %s\n", formatAccountLabel(finalAcc))
	a.printPostSwitchHints(updated, key, now)
	return 0
}

func (a *App) switchToNextAccount(
	ctx context.Context,
	st store.Store,
	paths platform.Paths,
	targetModel string,
	targetPool domain.QuotaPool,
	noRefresh bool,
	jsonOut bool,
	now time.Time,
) int {
	_, _ = quota.SyncNativeTokenIfFresher(ctx, st, now)
	if !noRefresh && a.fetcher != nil {
		if _, err := quota.RefreshAndFetchAll(ctx, st, a.oauth, a.fetcher, nil, quota.FetchOptions{Now: now}); err != nil {
			return a.fail(fmt.Errorf("refresh quotas: %w", err))
		}
	}

	state, err := st.Load(ctx)
	if err != nil {
		return a.fail(err)
	}
	if len(state.Accounts) == 0 {
		return a.fail(launcher.ErrNoReadyAccounts)
	}

	excluded := make(map[domain.AccountKey]bool)
	var decision domain.SwitchDecision
	var chosen domain.Account
	var encodedToken []byte

	maxAttempts := max(1, len(state.Accounts))
	selected := false
	for range maxAttempts {
		decision = a.selector.Evaluate(state, selector.EvalRequest{
			CurrentKey:  state.ActiveKey,
			TargetPool:  targetPool,
			TargetModel: targetModel,
			ForceSwitch: state.ActiveKey != "",
			ExcludeKeys: excluded,
			Now:         now,
		})
		if decision.Outcome == domain.OutcomeNoneReady || decision.ToKey == "" {
			return a.fail(formatNoneReadySwitchErr(decision, now))
		}

		acc, ok := state.Accounts[decision.ToKey]
		if !ok {
			excluded[decision.ToKey] = true
			continue
		}

		creds := acc.Creds
		if a.oauth != nil && oauth.NeedsRefresh(creds, state.Policy.RefreshSkew, now) {
			refreshed, _, revoked, refreshErr := quota.RefreshAccountToken(ctx, st, a.oauth, acc.Key, state.Policy.RefreshSkew, now, quota.RefreshIfExpiring)
			if revoked {
				excluded[acc.Key] = true
				state, _ = st.Load(ctx)
				continue
			}
			if !quota.CanStageWithoutRefresh(creds, refreshErr) {
				excluded[acc.Key] = true
				continue
			}
			if refreshErr == nil {
				creds = refreshed
			}
		}

		encoded, encErr := oauth.EncodeVerifiedAgyToken(acc, creds)
		if encErr != nil {
			excluded[acc.Key] = true
			continue
		}
		chosen = acc
		encodedToken = encoded
		selected = true
		break
	}

	if !selected {
		return a.fail(formatNoneReadySwitchErr(decision, now))
	}

	var prevActive domain.AccountKey
	updated, err := st.Update(ctx, func(s *domain.StoreState) error {
		cur, ok := s.Accounts[chosen.Key]
		if !ok {
			return fmt.Errorf("account %q disappeared", chosen.Key)
		}
		if err := platform.WriteFileAtomic(paths.NativeAgyTokenPath(), encodedToken, true); err != nil {
			return fmt.Errorf("stage native token: %w", err)
		}
		prevActive = s.ActiveKey
		usedAt := now
		cur.LastUsedAt = &usedAt
		s.Accounts[chosen.Key] = cur
		s.ActiveKey = chosen.Key
		s.LastSwitch = &domain.SwitchAuditEntry{
			At:      now,
			Outcome: decision.Outcome,
			FromKey: prevActive,
			ToKey:   chosen.Key,
			Reason:  decision.Reason,
			Pool:    decision.Pool,
			Trigger: "cli_switch",
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	finalAcc := updated.Accounts[chosen.Key]
	if jsonOut {
		rem := clampFraction(decision.CandidateRemaining)
		view := SwitchResultView{
			Outcome:   decision.Outcome,
			FromKey:   prevActive,
			ToKey:     chosen.Key,
			Pool:      decision.Pool,
			Reason:    decision.Reason,
			Remaining: &rem,
			Account:   ptrAccountView(buildAccountView(finalAcc, updated.ActiveKey, decision.Pool, false, now)),
		}
		if err := writeJSON(a.stdout, view); err != nil {
			return a.fail(err)
		}
		return 0
	}
	fmt.Fprintf(a.stdout, "Switched active account to %s (%s)\n", formatAccountLabel(finalAcc), decision.Reason)
	a.printPostSwitchHints(updated, chosen.Key, now)
	return 0
}

func (a *App) printPostSwitchHints(state domain.StoreState, switchedKey domain.AccountKey, now time.Time) {
	ranked := a.selector.Rank(state, selector.EvalRequest{
		CurrentKey: switchedKey,
		Now:        now,
	})
	if len(ranked) > 0 && ranked[0].Eligible && ranked[0].Key != "" && ranked[0].Key != switchedKey {
		if switchedScore, ok := findCandidateScore(ranked, switchedKey); ok && !switchedScore.Eligible {
			fmt.Fprintln(a.stdout, formatIneligibleSwitchHint(state, switchedKey, ranked[0].Key, switchedScore.SkipReason, now))
		} else if state.Policy.Mode != domain.SwitchFillFirst {
			mode := state.Policy.Mode
			if !mode.IsValid() {
				mode = domain.SwitchHighestRemaining
			}
			fmt.Fprintf(a.stdout, "Note: policy mode is %s; run 'multi-anti run --account %s' to launch this account, or 'multi-anti policy --mode fill_first' to keep switched accounts active.\n", mode, switchedKey)
		}
	}
	if strings.TrimSpace(os.Getenv("SSH_TTY")) == "" {
		fmt.Fprintf(a.stdout, "Note: SSH_TTY is unset; launch via 'multi-anti run --account %s' or %s for direct agy.\n", switchedKey, sshTTYSetHint(a.goos))
	}
}

func sshTTYSetHint(goos string) string {
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos == "windows" {
		return `set $env:SSH_TTY="multi-anti" in PowerShell`
	}
	return "export SSH_TTY=multi-anti"
}

func findCandidateScore(scores []selector.CandidateScore, key domain.AccountKey) (selector.CandidateScore, bool) {
	for _, s := range scores {
		if s.Key == key {
			return s, true
		}
	}
	return selector.CandidateScore{}, false
}

func formatIneligibleSwitchHint(state domain.StoreState, switchedKey, fallbackKey domain.AccountKey, skipReason string, now time.Time) string {
	if state.Policy.TargetPool == "" && (skipReason == "quota_exhausted" || skipReason == "below_threshold") {
		if acc, ok := state.Accounts[switchedKey]; ok && acc.Quota != nil {
			var depletedPools []string
			var readyPools []domain.QuotaPool
			allZero := true
			for _, p := range []domain.QuotaPool{domain.PoolGemini, domain.Pool3P} {
				rem, _, hasPool := acc.Quota.PoolRemainingAt(p, now)
				if !hasPool {
					continue
				}
				if rem <= 0 {
					depletedPools = append(depletedPools, string(p))
				} else if rem < state.Policy.MinRemainingThreshold {
					depletedPools = append(depletedPools, string(p))
					allZero = false
				} else {
					readyPools = append(readyPools, p)
				}
			}
			if len(depletedPools) > 0 && len(readyPools) > 0 {
				stateLabel := "exhausted quota"
				if !allZero {
					stateLabel = "low quota"
				}
				poolNoun := "pool"
				if len(depletedPools) > 1 {
					poolNoun = "pools"
				}
				suggestPool := readyPools[0]
				return fmt.Sprintf("Note: %s has %s in %s %s (target_pool=all); plain 'multi-anti run' will switch to %s. Run 'multi-anti run --account %s', pass '--pool %s', or set 'multi-anti policy --pool %s'.",
					switchedKey, stateLabel, poolNoun, strings.Join(depletedPools, ", "), fallbackKey, switchedKey, suggestPool, suggestPool)
			}
		}
	}
	if skipReason == "" {
		skipReason = "ineligible"
	}
	return fmt.Sprintf("Note: %s is ineligible for automatic selection (%s); plain 'multi-anti run' will switch to %s. Run 'multi-anti run --account %s' to launch this account.",
		switchedKey, skipReason, fallbackKey, switchedKey)
}

func readNativeTokenSummary(paths platform.Paths) nativeTokenSummary {
	raw, err := os.ReadFile(paths.NativeAgyTokenPath())
	if err != nil {
		return nativeTokenSummary{}
	}
	id, _, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return nativeTokenSummary{}
	}
	label := strings.TrimSpace(id.Email)
	if label == "" {
		label = string(id.Key)
	}
	return nativeTokenSummary{
		Key:     id.Key,
		Label:   label,
		Present: true,
	}
}

type runCLIFlags struct {
	account        string
	model          string
	pool           domain.QuotaPool
	hasPool        bool
	isolate        bool
	noRefresh      bool
	autoRelaunch   bool
	maxSwitches    int
	hasMaxSwitches bool
	agyBin         string
	showHelp       bool
	agyArgs        []string
	barePreArgs    []string
}

func (a *App) cmdRun(ctx context.Context, args []string) int {
	parsed, err := parseRunArgs(args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if parsed.showHelp {
		a.printSubcommandHelp("run", a.stdout)
		return 0
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	loadedState, loadErr := st.Load(ctx)
	haveState := loadErr == nil
	if strings.TrimSpace(parsed.account) == "" && len(parsed.barePreArgs) > 0 {
		first := parsed.barePreArgs[0]
		if isMistakenAccountPositional(first, loadedState, haveState) {
			return a.usageFail(fmt.Sprintf("unexpected argument %q; use 'multi-anti run --account %s' to select an account (or '--' to pass arguments to agy)", first, first))
		}
	}
	if !parsed.hasMaxSwitches && haveState && len(loadedState.Accounts) > parsed.maxSwitches {
		parsed.maxSwitches = len(loadedState.Accounts)
	}

	accountKey := domain.AccountKey(strings.TrimSpace(parsed.account))
	if accountKey != "" && haveState {
		if resolved, resErr := resolveAccountKey(loadedState, parsed.account); resErr == nil {
			accountKey = resolved
		}
	}

	var runPool domain.QuotaPool
	if parsed.hasPool {
		runPool = parsed.pool
	}

	agyBin := a.agyBin
	if strings.TrimSpace(parsed.agyBin) != "" {
		agyBin = strings.TrimSpace(parsed.agyBin)
	}

	res, runErr := launcher.Run(ctx, st, a.oauth, a.fetcher, a.selector, launcher.RunOptions{
		Binary:       agyBin,
		Args:         parsed.agyArgs,
		Account:      accountKey,
		Model:        parsed.model,
		TargetPool:   runPool,
		Isolate:      parsed.isolate,
		NoRefresh:    parsed.noRefresh,
		AutoRelaunch: parsed.autoRelaunch,
		MaxSwitches:  parsed.maxSwitches,
		Stdin:        a.stdin,
		Stdout:       a.stdout,
		Stderr:       a.stderr,
		Now:          a.now,
	})
	if runErr != nil {
		fmt.Fprintf(a.stderr, "error: %v\n", runErr)
		if res.ExitCode != 0 {
			return res.ExitCode
		}
		return 1
	}
	return res.ExitCode
}

func parseRunArgs(args []string) (runCLIFlags, error) {
	out := runCLIFlags{
		autoRelaunch: true,
		maxSwitches:  defaultMaxSwitches,
	}

	splitIdx := slices.Index(args, "--")
	pre := args
	var post []string
	if splitIdx >= 0 {
		pre = args[:splitIdx]
		post = args[splitIdx+1:]
	}

	prevWasAgyValueFlag := false
	for i := 0; i < len(pre); i++ {
		arg := pre[i]
		wasValue := prevWasAgyValueFlag
		prevWasAgyValueFlag = false
		switch {
		case arg == "-h" || arg == "--help":
			out.showHelp = true
			return out, nil
		case arg == "--isolate":
			out.isolate = true
		case strings.HasPrefix(arg, "--isolate="):
			v, err := parseBoolFlagValue("--isolate", strings.TrimPrefix(arg, "--isolate="))
			if err != nil {
				return out, err
			}
			out.isolate = v
		case arg == "--no-refresh":
			out.noRefresh = true
		case strings.HasPrefix(arg, "--no-refresh="):
			v, err := parseBoolFlagValue("--no-refresh", strings.TrimPrefix(arg, "--no-refresh="))
			if err != nil {
				return out, err
			}
			out.noRefresh = v
		case arg == "--auto-relaunch":
			out.autoRelaunch = true
		case strings.HasPrefix(arg, "--auto-relaunch="):
			v, err := parseBoolFlagValue("--auto-relaunch", strings.TrimPrefix(arg, "--auto-relaunch="))
			if err != nil {
				return out, err
			}
			out.autoRelaunch = v
		case arg == "--no-auto-relaunch":
			out.autoRelaunch = false
		case strings.HasPrefix(arg, "--no-auto-relaunch="):
			v, err := parseBoolFlagValue("--no-auto-relaunch", strings.TrimPrefix(arg, "--no-auto-relaunch="))
			if err != nil {
				return out, err
			}
			out.autoRelaunch = !v
		case arg == "--account":
			if i+1 >= len(pre) {
				return out, errors.New("--account requires a value")
			}
			i++
			out.account = pre[i]
		case strings.HasPrefix(arg, "--account="):
			out.account = strings.TrimPrefix(arg, "--account=")
		case arg == "--agy-bin":
			if i+1 >= len(pre) {
				return out, errors.New("--agy-bin requires a value")
			}
			i++
			out.agyBin = pre[i]
		case strings.HasPrefix(arg, "--agy-bin="):
			out.agyBin = strings.TrimPrefix(arg, "--agy-bin=")
		case arg == "--max-switches":
			if i+1 >= len(pre) {
				return out, errors.New("--max-switches requires a value")
			}
			i++
			n, err := parseNonNegInt("--max-switches", pre[i])
			if err != nil {
				return out, err
			}
			out.maxSwitches = n
			out.hasMaxSwitches = true
		case strings.HasPrefix(arg, "--max-switches="):
			n, err := parseNonNegInt("--max-switches", strings.TrimPrefix(arg, "--max-switches="))
			if err != nil {
				return out, err
			}
			out.maxSwitches = n
			out.hasMaxSwitches = true
		case arg == "--pool":
			if i+1 >= len(pre) {
				return out, errors.New("--pool requires a value")
			}
			i++
			p, err := parseTargetPoolFlag(pre[i], false)
			if err != nil {
				return out, err
			}
			out.pool = p
			out.hasPool = true
		case strings.HasPrefix(arg, "--pool="):
			p, err := parseTargetPoolFlag(strings.TrimPrefix(arg, "--pool="), false)
			if err != nil {
				return out, err
			}
			out.pool = p
			out.hasPool = true
		case arg == "--model":
			if i+1 >= len(pre) {
				return out, errors.New("--model requires a value")
			}
			i++
			out.model = pre[i]
			out.agyArgs = append(out.agyArgs, arg, pre[i])
		case strings.HasPrefix(arg, "--model="):
			out.model = strings.TrimPrefix(arg, "--model=")
			out.agyArgs = append(out.agyArgs, arg)
		default:
			out.agyArgs = append(out.agyArgs, arg)
			if !wasValue {
				if isAgyValueFlag(arg) {
					prevWasAgyValueFlag = true
				} else if !strings.HasPrefix(arg, "-") {
					out.barePreArgs = append(out.barePreArgs, arg)
				}
			}
		}
	}

	out.agyArgs = append(out.agyArgs, post...)
	if strings.TrimSpace(out.model) == "" {
		out.model = peekModelFlag(post)
	}
	return out, nil
}

func isMistakenAccountPositional(arg string, state domain.StoreState, haveState bool) bool {
	if isKnownAgySubcommand(arg) {
		return false
	}
	if looksLikeEmail(arg) {
		return true
	}
	if !haveState {
		return false
	}
	_, err := resolveAccountKey(state, arg)
	return err == nil
}

func isAgyValueFlag(arg string) bool {
	switch arg {
	case "-p", "--print", "--prompt", "--print-timeout",
		"-i", "--prompt-interactive",
		"-r", "--resume", "--conversation",
		"--add-dir", "--agent", "--effort",
		"--input-format", "--json-schema", "--log-file",
		"--mode", "--output-format", "--project", "--settings":
		return true
	default:
		return false
	}
}

func isKnownAgySubcommand(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "acp", "agent", "agents", "changelog", "help", "install",
		"mcp", "mic-serve", "models", "plugin", "plugins",
		"remote-control", "update", "chat", "auth", "login",
		"logout", "version", "completion", "doctor", "config":
		return true
	default:
		return false
	}
}

func looksLikeEmail(s string) bool {
	local, dom, ok := strings.Cut(s, "@")
	if !ok || local == "" || dom == "" || strings.Contains(dom, "@") {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n/\\") {
		return false
	}
	dot := strings.IndexByte(dom, '.')
	return dot > 0 && dot < len(dom)-1
}

func peekModelFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		if args[i] == "--model" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--model=") {
			return strings.TrimPrefix(args[i], "--model=")
		}
	}
	return ""
}

func (a *App) cmdPolicy(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("policy", a.stdout)
		return 0
	}

	fs := a.newFlagSet("policy")
	mode := fs.String("mode", "", "")
	threshold := fs.Float64("threshold", 0, "")
	cooldown := fs.Duration("cooldown", 0, "")
	refreshSkew := fs.Duration("refresh-skew", 0, "")
	pool := fs.String("pool", "", "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[0]))
	}

	setMode := flagVisited(fs, "mode")
	setThreshold := flagVisited(fs, "threshold")
	setCooldown := flagVisited(fs, "cooldown")
	setRefreshSkew := flagVisited(fs, "refresh-skew")
	setPool := flagVisited(fs, "pool")

	if setMode && !domain.SwitchMode(strings.TrimSpace(*mode)).IsValid() {
		return a.usageFail(fmt.Sprintf("invalid --mode %q (expected highest_remaining, fill_first, round_robin, or priority)", *mode))
	}
	if setThreshold && (math.IsNaN(*threshold) || math.IsInf(*threshold, 0) || *threshold < 0 || *threshold > 1) {
		return a.usageFail("--threshold must be between 0 and 1")
	}
	if setCooldown && *cooldown <= 0 {
		return a.usageFail("--cooldown must be positive")
	}
	if setRefreshSkew && *refreshSkew <= 0 {
		return a.usageFail("--refresh-skew must be positive")
	}
	var parsedPool domain.QuotaPool
	if setPool {
		parsedPool, err = parseTargetPoolFlag(*pool, true)
		if err != nil {
			return a.usageFail(err.Error())
		}
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	var state domain.StoreState
	mutated := setMode || setThreshold || setCooldown || setRefreshSkew || setPool
	if mutated {
		state, err = st.Update(ctx, func(s *domain.StoreState) error {
			if setMode {
				s.Policy.Mode = domain.SwitchMode(strings.TrimSpace(*mode))
			}
			if setThreshold {
				s.Policy.MinRemainingThreshold = *threshold
			}
			if setCooldown {
				s.Policy.CooldownDefault = *cooldown
			}
			if setRefreshSkew {
				s.Policy.RefreshSkew = *refreshSkew
			}
			if setPool {
				s.Policy.TargetPool = parsedPool
			}
			return nil
		})
	} else {
		state, err = st.Load(ctx)
	}
	if err != nil {
		return a.fail(err)
	}

	if *jsonOut {
		if err := writeJSON(a.stdout, buildPolicyView(state.Policy)); err != nil {
			return a.fail(err)
		}
		return 0
	}
	renderPolicy(a.stdout, state.Policy)
	return 0
}

func (a *App) cmdSetHealth(ctx context.Context, action string, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp(action, a.stdout)
		return 0
	}
	if len(args) != 1 {
		return a.usageFail(fmt.Sprintf("%s requires <email-or-key>", action))
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}
	now := a.currentTime()

	var targetKey domain.AccountKey
	_, err = st.Update(ctx, func(s *domain.StoreState) error {
		k, resErr := resolveAccountKey(*s, args[0])
		if resErr != nil {
			return resErr
		}
		targetKey = k
		acc := s.Accounts[k]
		if action == "enable" {
			acc.Health = domain.AccountHealth{
				Status:    domain.HealthReady,
				UpdatedAt: now,
			}
		} else {
			acc.Health = domain.AccountHealth{
				Status:    domain.HealthDisabled,
				Reason:    "disabled via cli",
				UpdatedAt: now,
			}
		}
		s.Accounts[k] = acc
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	if action == "enable" {
		fmt.Fprintf(a.stdout, "Enabled %s (ready)\n", targetKey)
	} else {
		fmt.Fprintf(a.stdout, "Disabled %s\n", targetKey)
	}
	return 0
}

func (a *App) cmdPriority(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("priority", a.stdout)
		return 0
	}
	if len(args) != 2 {
		return a.usageFail("priority requires <email-or-key> <int>")
	}
	prio, err := strconv.Atoi(args[1])
	if err != nil {
		return a.usageFail(fmt.Sprintf("invalid priority %q: must be an integer", args[1]))
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	var targetKey domain.AccountKey
	_, err = st.Update(ctx, func(s *domain.StoreState) error {
		k, resErr := resolveAccountKey(*s, args[0])
		if resErr != nil {
			return resErr
		}
		targetKey = k
		acc := s.Accounts[k]
		acc.Priority = prio
		s.Accounts[k] = acc
		return nil
	})
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "Set priority for %s to %d\n", targetKey, prio)
	return 0
}

func (a *App) cmdRemove(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("remove", a.stdout)
		return 0
	}
	if len(args) != 1 {
		return a.usageFail("remove requires <email-or-key>")
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	var targetKey domain.AccountKey
	_, err = st.Update(ctx, func(s *domain.StoreState) error {
		k, resErr := resolveAccountKey(*s, args[0])
		if resErr != nil {
			return resErr
		}
		acc := s.Accounts[k]
		if rmTokErr := removeNativeTokenIfMatches(paths.NativeAgyTokenPath(), k, acc.Email); rmTokErr != nil {
			return rmTokErr
		}
		targetKey = k
		delete(s.Accounts, k)
		if s.ActiveKey == k {
			s.ActiveKey = ""
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}

	if rmErr := os.RemoveAll(paths.ProfileDir(targetKey)); rmErr != nil {
		return a.fail(fmt.Errorf("remove profile dir for %s: %w", targetKey, rmErr))
	}
	fmt.Fprintf(a.stdout, "Removed %s\n", targetKey)
	return 0
}

func removeNativeTokenIfMatches(tokenPath string, targetKey domain.AccountKey, targetEmail string) error {
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read native token %q: %w", tokenPath, err)
	}
	id, _, err := oauth.DecodeAgyTokenFile(raw)
	if err != nil {
		return nil
	}
	wantEmail := strings.TrimSpace(targetEmail)
	matches := id.Key == targetKey || (wantEmail != "" && strings.EqualFold(strings.TrimSpace(id.Email), wantEmail))
	if !matches {
		return nil
	}
	if err := os.Remove(tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove staged native token %q: %w", tokenPath, err)
	}
	return nil
}

func (a *App) cmdPlugin(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("plugin", a.stdout)
		return 0
	}

	fs := a.newFlagSet("plugin")
	binFlag := fs.String("bin", "", "")
	noStatusLine := fs.Bool("no-statusline", false, "")
	jsonOut := fs.Bool("json", false, "")

	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) != 1 {
		return a.usageFail("plugin requires one of: install, uninstall, status")
	}

	paths, err := a.ensurePaths()
	if err != nil {
		return a.fail(err)
	}
	binCmd := strings.TrimSpace(*binFlag)
	if binCmd == "" {
		binCmd = a.binCmd
	}

	sub := pos[0]
	switch sub {
	case "install":
		if err := hook.InstallPlugin(ctx, paths, hook.InstallOptions{BinaryCommand: binCmd}); err != nil {
			return a.fail(err)
		}
		if !*noStatusLine {
			if err := hook.InstallStatusLine(paths, binCmd); err != nil {
				return a.fail(err)
			}
		}
	case "uninstall":
		if err := hook.UninstallPlugin(paths); err != nil {
			return a.fail(err)
		}
		if err := hook.UninstallStatusLine(paths); err != nil {
			return a.fail(err)
		}
	case "status":
	default:
		return a.usageFail(fmt.Sprintf("unknown plugin action %q (expected install, uninstall, or status)", sub))
	}

	status, err := hook.InspectPlugin(paths)
	if err != nil {
		return a.fail(err)
	}
	if *jsonOut {
		if err := writeJSON(a.stdout, status); err != nil {
			return a.fail(err)
		}
		return 0
	}
	switch sub {
	case "install":
		fmt.Fprintf(a.stdout, "Installed multi-anti plugin at %s\n", status.PluginDir)
	case "uninstall":
		fmt.Fprintf(a.stdout, "Uninstalled multi-anti plugin from %s\n", status.PluginDir)
	default:
		renderPluginStatus(a.stdout, status)
	}
	return 0
}

func (a *App) cmdStatusLine(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("statusline", a.stdout)
		return 0
	}

	fs := a.newFlagSet("statusline")
	binFlag := fs.String("bin", "", "")
	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 1 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[1]))
	}

	action := "render"
	if len(pos) == 1 {
		action = pos[0]
	}

	switch action {
	case "install":
		paths, err := a.ensurePaths()
		if err != nil {
			return a.fail(err)
		}
		binCmd := strings.TrimSpace(*binFlag)
		if binCmd == "" {
			binCmd = a.binCmd
		}
		if err := hook.InstallStatusLine(paths, binCmd); err != nil {
			return a.fail(err)
		}
		fmt.Fprintln(a.stdout, "Configured agy statusLine for multi-anti")
		return 0
	case "uninstall":
		paths, err := a.ensurePaths()
		if err != nil {
			return a.fail(err)
		}
		if err := hook.UninstallStatusLine(paths); err != nil {
			return a.fail(err)
		}
		fmt.Fprintln(a.stdout, "Removed multi-anti statusLine from agy settings")
		return 0
	case "render":
		var st store.Store
		if resolvedStore, _, storeErr := a.ensureStore(); storeErr == nil {
			st = resolvedStore
		}
		stdinBytes, _ := io.ReadAll(io.LimitReader(a.stdin, maxHookStdinBytes))
		h := hook.NewHandler(hook.HandlerConfig{
			Store:    st,
			Selector: a.selector,
			OAuth:    a.oauth,
			Now:      a.now,
		})
		line, handleErr := h.HandleStatusLine(ctx, stdinBytes)
		if handleErr != nil {
			line = "[multi-anti: unconfigured]"
		}
		if strings.TrimSpace(line) != "" {
			fmt.Fprintln(a.stdout, line)
		}
		return 0
	default:
		return a.usageFail(fmt.Sprintf("unknown statusline action %q (expected install, uninstall, or render)", action))
	}
}

func (a *App) cmdHook(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("hook", a.stdout)
		return 0
	}
	if len(args) != 1 {
		return a.usageFail("hook requires one of: session-start, stop")
	}

	st, _, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}
	stdinBytes, err := io.ReadAll(io.LimitReader(a.stdin, maxHookStdinBytes))
	if err != nil {
		return a.fail(fmt.Errorf("read hook stdin: %w", err))
	}

	h := hook.NewHandler(hook.HandlerConfig{
		Store:    st,
		Selector: a.selector,
		OAuth:    a.oauth,
		Now:      a.now,
	})

	var out []byte
	switch args[0] {
	case "session-start":
		out, err = h.HandleSessionStart(ctx, stdinBytes)
	case "stop":
		out, err = h.HandleStop(ctx, stdinBytes)
	default:
		return a.usageFail(fmt.Sprintf("unknown hook event %q (expected session-start or stop)", args[0]))
	}
	if err != nil {
		return a.fail(err)
	}
	if len(out) > 0 {
		if _, wErr := a.stdout.Write(out); wErr != nil {
			return a.fail(wErr)
		}
		if out[len(out)-1] != '\n' {
			_, _ = fmt.Fprintln(a.stdout)
		}
	}
	return 0
}

func (a *App) cmdDoctor(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("doctor", a.stdout)
		return 0
	}

	fs := a.newFlagSet("doctor")
	jsonOut := fs.Bool("json", false, "")
	pos, err := parseInterspersedFlags(fs, args)
	if err != nil {
		return a.usageFail(err.Error())
	}
	if len(pos) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", pos[0]))
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}
	now := a.currentTime()

	report := DoctorReportView{
		Healthy: true,
		Paths: DoctorPathsView{
			DataDir:      paths.DataDir(),
			HomeDir:      paths.HomeDir(),
			StateFile:    paths.StateFile(),
			NativeToken:  paths.NativeAgyTokenPath(),
			AgySettings:  paths.NativeAgySettingsPath(),
			NativePlugin: paths.NativePluginDir(),
		},
	}

	agyPath, agyVer, agyCheck := checkAgyBinary(ctx, a.agyBin)
	report.AgyBin = agyPath
	report.AgyVer = agyVer
	report.Checks = append(report.Checks, agyCheck)

	state, stateErr := st.Load(ctx)
	if stateErr != nil {
		report.Checks = append(report.Checks, DoctorCheckView{
			Name:    "state_store",
			Status:  DoctorFail,
			Summary: "failed to load state.json",
			Detail:  stateErr.Error(),
		})
	} else {
		stateDetail := "initialized in memory (not yet written)"
		if _, statErr := os.Stat(paths.StateFile()); statErr == nil {
			stateDetail = paths.StateFile()
		}
		report.Checks = append(report.Checks, DoctorCheckView{
			Name:    "state_store",
			Status:  DoctorOK,
			Summary: fmt.Sprintf("valid schema v%d", state.SchemaVersion),
			Detail:  stateDetail,
		})
		report.Checks = append(report.Checks, checkNativeBackup(state.NativeBackup))
		counts, accChecks := checkAccountsHealth(paths, state, now)
		report.Accounts = counts
		report.Checks = append(report.Checks, accChecks...)
	}

	pluginStatus, pluginErr := hook.InspectPlugin(paths)
	if pluginErr != nil {
		report.Checks = append(report.Checks, DoctorCheckView{
			Name:    "plugin",
			Status:  DoctorFail,
			Summary: "failed to inspect plugin installation",
			Detail:  pluginErr.Error(),
		})
	} else {
		report.Plugin = pluginStatus
		report.Checks = append(report.Checks, checkPluginInstall(ctx, agyPath, pluginStatus)...)
		report.Checks = append(report.Checks, checkStatusLineSetting(pluginStatus))
	}
	report.Checks = append(report.Checks, checkSSHTTYEnv(a.goos))
	report.Checks = append(report.Checks, checkOAuthClientConfig())

	for _, c := range report.Checks {
		if c.Status == DoctorFail {
			report.Healthy = false
			break
		}
	}

	if *jsonOut {
		if err := writeJSON(a.stdout, report); err != nil {
			return a.fail(err)
		}
		if !report.Healthy {
			return 1
		}
		return 0
	}

	renderDoctorReport(a.stdout, report)
	if !report.Healthy {
		return 1
	}
	return 0
}

func checkAgyBinary(ctx context.Context, bin string) (resolvedPath, version string, check DoctorCheckView) {
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return "", "", DoctorCheckView{
			Name:    "agy_binary",
			Status:  DoctorFail,
			Summary: fmt.Sprintf("agy binary %q not found", bin),
			Detail:  err.Error(),
		}
	}

	verCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, verErr := exec.CommandContext(verCtx, resolved, "--version").CombinedOutput()
	verText := sanitizeSingleLine(string(out))
	if verErr != nil {
		return resolved, verText, DoctorCheckView{
			Name:    "agy_binary",
			Status:  DoctorWarn,
			Summary: fmt.Sprintf("found %s, but --version failed", resolved),
			Detail:  verErr.Error(),
		}
	}
	return resolved, verText, DoctorCheckView{
		Name:    "agy_binary",
		Status:  DoctorOK,
		Summary: fmt.Sprintf("%s (%s)", resolved, verText),
	}
}

func checkNativeBackup(rec *domain.NativeBackupRecord) DoctorCheckView {
	if rec == nil {
		return DoctorCheckView{
			Name:    "native_backup",
			Status:  DoctorInfo,
			Summary: "not captured yet (created before first switch or run)",
		}
	}
	if !rec.HadFile {
		return DoctorCheckView{
			Name:    "native_backup",
			Status:  DoctorOK,
			Summary: "original environment had no native token file",
		}
	}
	data, err := os.ReadFile(rec.BackupPath)
	if err != nil {
		return DoctorCheckView{
			Name:    "native_backup",
			Status:  DoctorFail,
			Summary: "recorded backup file unreadable",
			Detail:  err.Error(),
		}
	}
	sum := sha256.Sum256(data)
	got := fmt.Sprintf("%x", sum)
	if rec.SHA256 != "" && got != rec.SHA256 {
		return DoctorCheckView{
			Name:    "native_backup",
			Status:  DoctorFail,
			Summary: "native backup SHA256 mismatch",
			Detail:  rec.BackupPath,
		}
	}
	return DoctorCheckView{
		Name:    "native_backup",
		Status:  DoctorOK,
		Summary: "native backup verified",
		Detail:  rec.BackupPath,
	}
}

func checkAccountsHealth(paths platform.Paths, state domain.StoreState, now time.Time) (AccountsCountView, []DoctorCheckView) {
	counts := AccountsCountView{
		Total:     len(state.Accounts),
		ActiveKey: state.ActiveKey,
	}
	if counts.Total == 0 {
		return counts, []DoctorCheckView{{
			Name:    "accounts",
			Status:  DoctorWarn,
			Summary: "no managed accounts configured",
		}}
	}

	var missingRefresh []string
	var missingAll []string
	var needsReauth []string

	for _, k := range sortedAccountKeys(state.Accounts) {
		acc := state.Accounts[k]
		switch acc.Health.EffectiveStatus(now) {
		case domain.HealthReady:
			counts.Ready++
		case domain.HealthCooldown:
			counts.Cooldown++
		case domain.HealthNeedsReauth:
			counts.NeedsReauth++
			needsReauth = append(needsReauth, string(k))
		case domain.HealthDisabled:
			counts.Disabled++
		}
		hasAT := strings.TrimSpace(acc.Creds.AccessToken) != ""
		hasRT := strings.TrimSpace(acc.Creds.RefreshToken) != ""
		if !hasAT && !hasRT {
			missingAll = append(missingAll, string(k))
		} else if !hasRT {
			missingRefresh = append(missingRefresh, string(k))
		}
	}

	var checks []DoctorCheckView
	status := DoctorOK
	if counts.Ready == 0 {
		status = DoctorWarn
	}
	checks = append(checks, DoctorCheckView{
		Name:    "accounts",
		Status:  status,
		Summary: fmt.Sprintf("%d total (%d ready, %d cooldown, %d needs_reauth, %d disabled)", counts.Total, counts.Ready, counts.Cooldown, counts.NeedsReauth, counts.Disabled),
	})

	if len(missingAll) > 0 {
		checks = append(checks, DoctorCheckView{
			Name:    "credentials",
			Status:  DoctorFail,
			Summary: "accounts missing both access and refresh tokens",
			Detail:  strings.Join(missingAll, ", "),
		})
	} else if len(missingRefresh) > 0 || len(needsReauth) > 0 {
		var details []string
		if len(missingRefresh) > 0 {
			details = append(details, "missing refresh_token: "+strings.Join(missingRefresh, ", "))
		}
		if len(needsReauth) > 0 {
			details = append(details, "needs_reauth: "+strings.Join(needsReauth, ", "))
		}
		checks = append(checks, DoctorCheckView{
			Name:    "credentials",
			Status:  DoctorWarn,
			Summary: "some accounts require attention",
			Detail:  strings.Join(details, "; "),
		})
	} else {
		checks = append(checks, DoctorCheckView{
			Name:    "credentials",
			Status:  DoctorOK,
			Summary: "all accounts have refresh tokens",
		})
	}

	if state.ActiveKey != "" {
		if raw, err := os.ReadFile(paths.NativeAgyTokenPath()); err == nil {
			if id, _, decErr := oauth.DecodeAgyTokenFile(raw); decErr == nil && id.Key != state.ActiveKey {
				checks = append(checks, DoctorCheckView{
					Name:    "native_staging",
					Status:  DoctorWarn,
					Summary: fmt.Sprintf("native token holds %s while active_key is %s", id.Key, state.ActiveKey),
				})
			}
		}
	}
	return counts, checks
}

func checkPluginInstall(ctx context.Context, agyPath string, st hook.PluginStatus) []DoctorCheckView {
	if !st.Installed {
		return []DoctorCheckView{{
			Name:    "plugin_files",
			Status:  DoctorWarn,
			Summary: "plugin not installed",
			Detail:  strings.Join(st.MissingFiles, ", "),
		}}
	}

	var checks []DoctorCheckView
	if st.DisabledInConfig {
		checks = append(checks, DoctorCheckView{
			Name:    "plugin_files",
			Status:  DoctorWarn,
			Summary: "plugin installed but disabled in gemini config.json",
			Detail:  st.PluginDir,
		})
	} else {
		checks = append(checks, DoctorCheckView{
			Name:    "plugin_files",
			Status:  DoctorOK,
			Summary: "plugin installed",
			Detail:  st.PluginDir,
		})
	}

	if agyPath == "" {
		return checks
	}

	valCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, valErr := exec.CommandContext(valCtx, agyPath, "plugin", "validate", "--strict", "--json", st.PluginDir).CombinedOutput()
	if valErr != nil {
		checks = append(checks, DoctorCheckView{
			Name:    "plugin_validate",
			Status:  DoctorFail,
			Summary: "agy plugin validate --strict failed",
			Detail:  truncateText(sanitizeSingleLine(string(out)), 140),
		})
		return checks
	}

	var parsed struct {
		Findings []any `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err == nil && len(parsed.Findings) > 0 {
		checks = append(checks, DoctorCheckView{
			Name:    "plugin_validate",
			Status:  DoctorWarn,
			Summary: fmt.Sprintf("agy plugin validate reported %d finding(s)", len(parsed.Findings)),
		})
		return checks
	}

	checks = append(checks, DoctorCheckView{
		Name:    "plugin_validate",
		Status:  DoctorOK,
		Summary: "agy plugin validate --strict passed",
	})
	return checks
}

func checkStatusLineSetting(st hook.PluginStatus) DoctorCheckView {
	if st.StatusLineEnabled {
		return DoctorCheckView{
			Name:    "statusline",
			Status:  DoctorOK,
			Summary: "configured",
			Detail:  st.StatusLineCommand,
		}
	}
	if st.Installed {
		return DoctorCheckView{
			Name:    "statusline",
			Status:  DoctorWarn,
			Summary: "plugin installed without multi-anti statusLine in settings.json",
		}
	}
	return DoctorCheckView{
		Name:    "statusline",
		Status:  DoctorInfo,
		Summary: "not configured",
	}
}

func checkSSHTTYEnv(goos string) DoctorCheckView {
	if v := strings.TrimSpace(os.Getenv("SSH_TTY")); v != "" {
		return DoctorCheckView{
			Name:    "file_auth_env",
			Status:  DoctorOK,
			Summary: "SSH_TTY is set (direct agy reads staged token file)",
			Detail:  v,
		}
	}
	return DoctorCheckView{
		Name:    "file_auth_env",
		Status:  DoctorInfo,
		Summary: fmt.Sprintf("SSH_TTY is unset; use 'multi-anti run' or %s for direct agy", sshTTYSetHint(goos)),
	}
}

func checkOAuthClientConfig() DoctorCheckView {
	if strings.TrimSpace(os.Getenv("MULTI_ANTI_OAUTH_CLIENT_ID")) != "" {
		return DoctorCheckView{
			Name:    "oauth_client",
			Status:  DoctorOK,
			Summary: "configured via MULTI_ANTI_OAUTH_CLIENT_ID",
		}
	}
	if strings.TrimSpace(oauth.DefaultClientID) != "" {
		return DoctorCheckView{
			Name:    "oauth_client",
			Status:  DoctorOK,
			Summary: "configured via build defaults",
		}
	}
	return DoctorCheckView{
		Name:    "oauth_client",
		Status:  DoctorInfo,
		Summary: "not configured; login uses agy fallback (set MULTI_ANTI_OAUTH_CLIENT_ID for offline quota refresh)",
	}
}

func (a *App) cmdRestore(ctx context.Context, args []string) int {
	if hasHelpFlag(args) {
		a.printSubcommandHelp("restore", a.stdout)
		return 0
	}
	if len(args) > 0 {
		return a.usageFail(fmt.Sprintf("unexpected argument %q", args[0]))
	}

	st, paths, err := a.ensureStore()
	if err != nil {
		return a.fail(err)
	}

	rec, restoreErr := st.RestoreNativeBackup(ctx)
	if restoreErr != nil && !errors.Is(restoreErr, store.ErrNoNativeBackup) {
		return a.fail(restoreErr)
	}

	if slErr := hook.UninstallStatusLine(paths); slErr != nil {
		return a.fail(fmt.Errorf("restore statusLine: %w", slErr))
	}

	if errors.Is(restoreErr, store.ErrNoNativeBackup) {
		fmt.Fprintln(a.stdout, "No native token backup recorded; restored statusLine configuration.")
		return 0
	}
	if rec.HadFile {
		fmt.Fprintf(a.stdout, "Restored original native token to %s and restored statusLine configuration.\n", paths.NativeAgyTokenPath())
	} else {
		fmt.Fprintf(a.stdout, "Removed staged native token %s (none existed originally) and restored statusLine configuration.\n", paths.NativeAgyTokenPath())
	}
	return 0
}

func resolveAccountKey(state domain.StoreState, raw string) (domain.AccountKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("account identifier cannot be empty")
	}
	if _, ok := state.Accounts[domain.AccountKey(trimmed)]; ok {
		return domain.AccountKey(trimmed), nil
	}
	if norm, err := domain.NormalizeAccountKey(trimmed, ""); err == nil {
		if _, ok := state.Accounts[norm]; ok {
			return norm, nil
		}
	}
	if normID, err := domain.NormalizeAccountKey("", trimmed); err == nil {
		if _, ok := state.Accounts[normID]; ok {
			return normID, nil
		}
	}

	var aliasMatches []domain.AccountKey
	for _, k := range sortedAccountKeys(state.Accounts) {
		acc := state.Accounts[k]
		if strings.EqualFold(strings.TrimSpace(acc.DisplayName), trimmed) ||
			(acc.AccountID != "" && strings.EqualFold(acc.AccountID, trimmed)) {
			aliasMatches = append(aliasMatches, k)
		}
	}
	if len(aliasMatches) == 1 {
		return aliasMatches[0], nil
	}
	if len(aliasMatches) > 1 {
		strs := make([]string, len(aliasMatches))
		for i, k := range aliasMatches {
			strs[i] = string(k)
		}
		return "", fmt.Errorf("ambiguous account %q matches: %s", raw, strings.Join(strs, ", "))
	}
	return "", fmt.Errorf("account %q not found", raw)
}

func parseTargetPoolFlag(raw string, allowAll bool) (domain.QuotaPool, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", nil
	}
	if trimmed == "all" {
		if allowAll {
			return "", nil
		}
		return "", errors.New("invalid --pool \"all\" (expected gemini or 3p)")
	}
	p := domain.QuotaPool(trimmed)
	switch p {
	case domain.PoolGemini, domain.Pool3P:
		return p, nil
	default:
		if allowAll {
			return "", fmt.Errorf("invalid --pool %q (expected gemini, 3p, or all)", raw)
		}
		return "", fmt.Errorf("invalid --pool %q (expected gemini or 3p)", raw)
	}
}

func parseInterspersedFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}

		if _, err := strconv.Atoi(arg); err == nil {
			positionals = append(positionals, arg)
			continue
		}

		name := strings.TrimPrefix(arg, "--")
		if name == arg {
			name = strings.TrimPrefix(arg, "-")
		}
		name, _, hasEq := strings.Cut(name, "=")

		f := fs.Lookup(name)
		if f == nil {
			flagArgs = append(flagArgs, arg)
			continue
		}
		flagArgs = append(flagArgs, arg)
		if !hasEq && !isBoolFlag(f) && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return append(positionals, fs.Args()...), nil
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlagger interface {
		IsBoolFlag() bool
	}
	bf, ok := f.Value.(boolFlagger)
	return ok && bf.IsBoolFlag()
}

func flagVisited(fs *flag.FlagSet, name string) bool {
	visited := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			visited = true
		}
	})
	return visited
}

func preprocessWatchFlag(args []string, def time.Duration) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, args[i:]...)
			break
		}
		if arg == "--watch" || arg == "-watch" {
			if i+1 < len(args) {
				if _, err := time.ParseDuration(args[i+1]); err == nil {
					out = append(out, "--watch="+args[i+1])
					i++
					continue
				}
			}
			out = append(out, "--watch="+def.String())
			continue
		}
		out = append(out, arg)
	}
	return out
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func parseBoolFlagValue(flagName, val string) (bool, error) {
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("invalid boolean value %q for %s", val, flagName)
	}
	return b, nil
}

func parseNonNegInt(flagName, val string) (int, error) {
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", flagName, val)
	}
	return n, nil
}

func resolveBinaryCommand() string {
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		return "multi-anti"
	}
	lowerBase := strings.ToLower(filepath.Base(exe))
	if strings.HasSuffix(lowerBase, ".test") || strings.HasSuffix(lowerBase, ".test.exe") {
		return "multi-anti"
	}
	return exe
}

func formatNoneReadySwitchErr(decision domain.SwitchDecision, now time.Time) error {
	if decision.EarliestReset != nil {
		return fmt.Errorf("%w (earliest reset in %s at %s)", launcher.ErrNoReadyAccounts, formatDurationShort(decision.EarliestReset.Sub(now)), decision.EarliestReset.UTC().Format(time.RFC3339))
	}
	return launcher.ErrNoReadyAccounts
}

func ptrAccountView(v AccountView) *AccountView {
	return &v
}

func isNullJSON(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

func (a *App) printRootHelp(w io.Writer) {
	fmt.Fprint(w, `multi-anti - Multi-account OAuth quota manager and auto-switcher for Antigravity CLI (agy)

Usage:
  multi-anti <command> [options]

Account Management:
  login                    Authenticate and add/update an account via OAuth PKCE
  import [path]            Import native agy token or multi-account JSON export
  accounts, list, ls       List managed accounts, health, and primary quota
  switch [email-or-key]    Stage a specific account or switch to the next ready account
  next                     Switch to the next ready account
  enable <email-or-key>    Mark an account ready
  disable <email-or-key>   Disable an account from selection
  priority <key> <int>     Set account tie-break priority (higher wins)
  remove, rm <key>         Delete an account, its isolated profile, and matching staged token

Quota & Execution:
  quota, usage, status     Fetch and rank CloudCode quota across accounts
  run, agy [flags] [--]    Launch agy with selected account and automatic failover
  policy                   View or update account selection policy

Integration & Diagnostics:
  plugin <install|uninstall|status>  Manage the agy plugin bundle and statusLine
  statusline [install|uninstall]     Render or install the agy statusLine command
  hook <session-start|stop>          Execute an agy plugin lifecycle hook
  doctor                             Inspect agy binary, state, backup, and plugin health
  restore, restore-native            Restore pre-multi-anti native token and statusLine
  version, -v, --version             Show multi-anti version
  help [command]                     Show help

Run 'multi-anti help <command>' for command-specific flags.
`)
}

func (a *App) printSubcommandHelp(cmd string, w io.Writer) bool {
	var text string
	switch cmd {
	case "login":
		text = "Usage: multi-anti login [--no-browser] [--timeout 3m] [--priority N] [--alias <name>] [--no-refresh] [--agy-bin <path>] [--json]\n"
	case "import":
		text = "Usage: multi-anti import [path] [--native] [--priority N] [--alias <name>] [--no-refresh] [--json]\n"
	case "accounts", "list", "ls":
		text = "Usage: multi-anti accounts [--json]\nAliases: list, ls\n"
	case "quota", "usage", "status":
		text = "Usage: multi-anti quota [--no-refresh|--cached] [--refresh] [--watch[=30s]] [--models] [--pool <gemini|3p|all>] [--json]\nAliases: usage, status\n"
	case "switch":
		text = "Usage: multi-anti switch [email-or-key] [--model <m>] [--pool <gemini|3p|all>] [--no-refresh] [--force] [--json]\n"
	case "next":
		text = "Usage: multi-anti next [--model <m>] [--pool <gemini|3p|all>] [--no-refresh] [--json]\n"
	case "run", "agy":
		text = `Usage: multi-anti run [multi-anti flags] [agy args...] [-- <agy args...>]
Aliases: agy

multi-anti flags (before '--'):
  --account <email-or-key>           Explicitly select an account
  --model <model>                    Select account pool for model AND forward --model to agy
  --pool <gemini|3p>                 Override target quota pool for selection
  --isolate                          Run agy in a per-account HOME directory
  --no-refresh                       Skip pre-launch quota refresh
  --auto-relaunch                    Relaunch and continue interactive agy on Stop switch signal (default true)
  --no-auto-relaunch                 Disable automatic interactive relaunch on quota switch
  --max-switches <N>                 Max auto-switch retries (default max(3, accounts))
  --agy-bin <path>                   Override agy executable path
`
	case "policy":
		text = "Usage: multi-anti policy [--mode highest_remaining|fill_first|round_robin|priority] [--threshold <0..1>] [--cooldown <dur>] [--refresh-skew <dur>] [--pool <gemini|3p|all>] [--json]\n"
	case "enable":
		text = "Usage: multi-anti enable <email-or-key>\n"
	case "disable":
		text = "Usage: multi-anti disable <email-or-key>\n"
	case "priority":
		text = "Usage: multi-anti priority <email-or-key> <int>\n"
	case "remove", "rm":
		text = "Usage: multi-anti remove <email-or-key>\nAliases: rm\n"
	case "plugin":
		text = "Usage: multi-anti plugin <install|uninstall|status> [--bin <path>] [--no-statusline] [--json]\n"
	case "statusline":
		text = "Usage: multi-anti statusline [install|uninstall|render] [--bin <path>]\n"
	case "hook":
		text = "Usage: multi-anti hook <session-start|stop>\n"
	case "doctor":
		text = "Usage: multi-anti doctor [--json]\n"
	case "restore", "restore-native":
		text = "Usage: multi-anti restore\nAliases: restore-native\n"
	case "version":
		text = "Usage: multi-anti version\n"
	default:
		return false
	}
	fmt.Fprint(w, text)
	return true
}
