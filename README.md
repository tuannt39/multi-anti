# multi-anti

`multi-anti` manages multiple Google Antigravity CLI (`agy`) OAuth accounts, monitors CloudCode quota pools (`gemini`, `3p`), and rotates accounts automatically when quota is exhausted. It builds with the Go standard library only and has zero external Go dependencies.

## Prerequisites

Make sure you have these dependencies ready before you build or run `multi-anti`:

- `agy` CLI version `1.5.10` or newer on your `PATH`. Run `agy --version` to verify.
- Go `1.26` or newer when building from source.
- **Optional.** Google OAuth desktop client credentials (`client_id` and `client_secret`). Set them only if you need direct loopback PKCE login without `agy` or offline quota refresh for idle accounts after their 1-hour `access_token` expires.

## Installation

### Download prebuilt binary

Prebuilt binaries for Linux (`amd64`, `arm64`) and Windows (`amd64`, `arm64`) are published on [GitHub Releases](https://github.com/tuannt39/multi-anti/releases). Download the file for your platform along with `SHA256SUMS.txt` and verify the checksum before installing it on your `PATH`.

```bash
# Linux (amd64 example)
curl -fsSLO https://github.com/tuannt39/multi-anti/releases/latest/download/multi-anti-linux-amd64
curl -fsSLO https://github.com/tuannt39/multi-anti/releases/latest/download/SHA256SUMS.txt
sha256sum --ignore-missing -c SHA256SUMS.txt
install -d ~/.local/bin && install -m 755 multi-anti-linux-amd64 ~/.local/bin/multi-anti
```

```powershell
# Windows PowerShell (amd64 example)
$versionDir = Join-Path $env:LOCALAPPDATA "Programs\multi-anti"
New-Item -ItemType Directory -Force -Path $versionDir | Out-Null
Invoke-WebRequest -Uri "https://github.com/tuannt39/multi-anti/releases/latest/download/multi-anti-windows-amd64.exe" -OutFile (Join-Path $versionDir "multi-anti.exe")
```

### Build from source

`multi-anti` builds with the Go standard library only and works immediately after a standard build with zero OAuth credentials. In `internal/oauth/client.go`, `DefaultClientID` and `DefaultClientSecret` default to `""`, so `multi-anti login` delegates sign-in to `agy` and `agy` refreshes staged tokens at launch.

Install `multi-anti` with Go or compile a standalone binary for your platform:

```bash
# Install into $(go env GOPATH)/bin
go install .

# Or build directly in the repository directory
CGO_ENABLED=0 go build -ldflags "-X main.version=0.1.0" -o multi-anti .

# Linux (amd64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=0.1.0" -o multi-anti .

# Linux (arm64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=0.1.0" -o multi-anti .

# macOS (Apple Silicon arm64)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=0.1.0" -o multi-anti .

# macOS (Intel amd64)
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=0.1.0" -o multi-anti .

# Windows (amd64)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=0.1.0" -o multi-anti.exe .

# Windows (arm64)
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags "-X main.version=0.1.0" -o multi-anti.exe .
```

#### Optional. Enable offline quota refresh and direct PKCE login

Without OAuth client credentials, `multi-anti quota` fetches live quota while an account's `access_token` is valid for about 1 hour, then shows cached quota with a `stale` note once an idle account's token expires. Set a Google OAuth desktop `client_id` and `client_secret` only if you want offline quota refresh for idle accounts or direct loopback PKCE login without `agy`.

You can supply OAuth credentials either through runtime environment variables or through build-time `-ldflags`.

Set runtime environment variables in your shell profile:

```bash
# Bash or Zsh (~/.bashrc or ~/.zshrc)
export MULTI_ANTI_OAUTH_CLIENT_ID="<client-id>"
export MULTI_ANTI_OAUTH_CLIENT_SECRET="<client-secret>"
```

```powershell
# PowerShell (current session)
$env:MULTI_ANTI_OAUTH_CLIENT_ID = "<client-id>"
$env:MULTI_ANTI_OAUTH_CLIENT_SECRET = "<client-secret>"

# PowerShell (persist for current user)
[Environment]::SetEnvironmentVariable("MULTI_ANTI_OAUTH_CLIENT_ID", "<client-id>", "User")
[Environment]::SetEnvironmentVariable("MULTI_ANTI_OAUTH_CLIENT_SECRET", "<client-secret>", "User")
```

Or embed `DefaultClientID` and `DefaultClientSecret` into the binary at build time with `-ldflags` so hooks invoked from non-login shells inherit them without shell profile exports:

```bash
# Bash or Zsh (Linux and macOS example)
CGO_ENABLED=0 go build -ldflags "-X main.version=0.1.0 -X github.com/tuannt/multi-anti/internal/oauth.DefaultClientID=<client-id> -X github.com/tuannt/multi-anti/internal/oauth.DefaultClientSecret=<client-secret>" -o multi-anti .
```

```powershell
# Windows PowerShell
CGO_ENABLED=0 go build -ldflags "-X main.version=0.1.0 -X github.com/tuannt/multi-anti/internal/oauth.DefaultClientID=<client-id> -X github.com/tuannt/multi-anti/internal/oauth.DefaultClientSecret=<client-secret>" -o multi-anti.exe .
```

Do not share or publish binaries compiled with embedded `-ldflags` credentials because anyone with the binary can extract `client_id` and `client_secret`.

### Install the binary on PATH

Move the compiled binary into a directory on your `PATH` so every terminal session and `agy` hook can invoke `multi-anti`.

On Linux and macOS, install the binary into `~/.local/bin` and add `~/.local/bin` to your shell `PATH`:

```bash
install -d ~/.local/bin && install -m 755 multi-anti ~/.local/bin/multi-anti
```

If `~/.local/bin` is not on your `PATH`, add this line to `~/.bashrc` or `~/.zshrc` and reload your shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

On Windows PowerShell, copy `multi-anti.exe` into `%LOCALAPPDATA%\Programs\multi-anti` and add that folder to your User `PATH`:

```powershell
$installDir = Join-Path $env:LOCALAPPDATA "Programs\multi-anti"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item .\multi-anti.exe (Join-Path $installDir "multi-anti.exe") -Force

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$parts = @($userPath -split ';' | Where-Object { $_ -ne "" })
if ($parts -notcontains $installDir) {
	$newPath = ($parts + $installDir) -join ';'
	[Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}
```

Restart PowerShell after updating your User `PATH` so the new `PATH` entry takes effect.

### Verify the binary

Check that your shell finds the installed binary and prints its version:

```bash
multi-anti version
```

The command prints `multi-anti 0.1.0` when built with `-X main.version=0.1.0`, or `multi-anti dev` when built without `-X main.version`.

## Plugin and status line setup

Before you run `multi-anti plugin install`, place `multi-anti` in its final `PATH` directory. When `--bin` is omitted, `multi-anti plugin install` records the running executable path from `os.Executable()` into `hooks.json` and `settings.json`. Moving or deleting that executable later breaks `agy` hooks and the status line.

Install the embedded plugin bundle and status line configuration:

```bash
multi-anti plugin install
```

Pass `--bin <path>` to write a specific command or path, such as `--bin multi-anti` to resolve `multi-anti` from `PATH`. Pass `--no-statusline` to skip writing `statusLine` in `settings.json`.

Running `multi-anti plugin install` makes these changes on disk:

- Writes `plugin.json`, `hooks.json`, `assets/logo.svg`, and `skills/multi-anti/SKILL.md` into `~/.gemini/config/plugins/multi-anti/`, or `%USERPROFILE%\.gemini\config\plugins\multi-anti\` on Windows.
- Sets `plugins.multi-anti.enabled` to `true` in `~/.gemini/config/config.json` if `multi-anti` was marked disabled.
- Writes `statusLine` in `~/.gemini/antigravity-cli/settings.json`, or `%USERPROFILE%\.gemini\antigravity-cli\settings.json` on Windows, unless `--no-statusline` is passed. Any prior non-`multi-anti` `statusLine` object is backed up once into `<data_dir>/backups/statusline.json`.

Verify that `multi-anti` and `agy` both see a valid plugin installation:

```bash
multi-anti plugin status
agy plugin list
agy plugin validate --strict ~/.gemini/config/plugins/multi-anti
```

On Windows PowerShell, pass the user profile plugin path to `agy plugin validate`:

```powershell
agy plugin validate --strict "$env:USERPROFILE\.gemini\config\plugins\multi-anti"
```

## Account setup and verification

Add one or more Google accounts by running `multi-anti login` or by importing existing credentials.

### Option A. Log in via `multi-anti login`

Start an interactive browser login for each Google account you want to manage:

```bash
multi-anti login
```

By default, when `MULTI_ANTI_OAUTH_CLIENT_ID` and `DefaultClientID` are unset, `multi-anti login` delegates sign-in to `agy` inside an isolated temporary profile with `SSH_TTY=multi-anti`. `multi-anti` prints the Google OAuth URL from `agy` and opens it in your browser unless you pass `--no-browser`. After you sign in, copy the authorization code from `https://antigravity.google/oauth-callback` and paste it into the terminal prompt so `multi-anti` can import the resulting token. Pass `--agy-bin <path>` if `agy` is not on your `PATH`, or pass `--no-browser` on a headless host or SSH session:

```bash
multi-anti login --no-browser
```

When `MULTI_ANTI_OAUTH_CLIENT_ID` or `DefaultClientID` is configured, `multi-anti login` uses direct loopback OAuth PKCE instead of `agy`. It starts a local callback listener on `127.0.0.1:51121` and falls back to an available ephemeral port on `127.0.0.1` if `51121` is already in use. Pass `--no-browser` to print the authorization URL and paste the redirect URL or authorization code into standard input.

### Option B. Import existing credentials

Import an existing `agy` token file or a multi-account JSON export:

```bash
# Import native ~/.gemini/antigravity-cli/antigravity-oauth-token
multi-anti import --native

# Or import a JSON file (single token, JSON array, or {"accounts": ...})
multi-anti import /path/to/export.json
```

Native `agy` writes `~/.gemini/antigravity-cli/antigravity-oauth-token` only when `agy` runs with `SSH_TTY` set, such as `SSH_TTY=1 agy`. Desktop `agy` without `SSH_TTY` writes credentials to OS Keyring on Linux and macOS, or Windows Credential Manager on Windows, so `antigravity-oauth-token` does not exist on disk initially; however, `agy` 1.5.14+ still reads a leftover `antigravity-oauth-token` file as a fallback when OS Keyring is empty. When that file is absent, sign in with `multi-anti login`, or run `SSH_TTY=1 agy` once before you run `multi-anti import --native`.

### Verify accounts, quota, and health

Confirm that your accounts, CloudCode quota pools, plugin files, and backups are healthy:

```bash
multi-anti accounts
multi-anti quota
# or: multi-anti usage
multi-anti doctor
```

`multi-anti quota` (and its `multi-anti usage` alias) prints a ranked account table followed by a compact per-account breakdown across `gemini` and `claude/gpt`. Each row lists `5h` and `wk` remaining percentages to 2 decimal places alongside both the reset countdown (`d/h/m`) and exact local reset timestamp (`YYYY-MM-DD HH:MM +07:00`), plus any active cooldown deadline and cached fetch age.

Without OAuth `client_id`, `multi-anti quota` fetches live quota while an account's `access_token` is valid for about 1 hour, and falls back to cached quota with `stale (set OAuth client_id to refresh offline)` once an idle account's token expires.

`multi-anti doctor` exits with code `0` when all required checks pass. It reports warnings or failures for `agy`, `state.json`, native backup SHA256 integrity, account refresh tokens, plugin validation, and `statusLine`, plus `[INFO]` status for `oauth_client` and `SSH_TTY`.

## Shell integration and daily usage

Run `agy` through `multi-anti run` so `multi-anti` selects the best ready account, stages its token, and retries or relaunches on quota exhaustion:

```bash
# Run a headless prompt with automatic failover on 429 or RESOURCE_EXHAUSTED
multi-anti run -- -p "Review this repository"

# Run interactively (live failover and `-i continue` relaunch on quota exhaustion are enabled by default)
multi-anti run --

# Target a specific model and pool while keeping per-account HOME isolation
multi-anti run --isolate --model claude-sonnet-4-5 -- -p "Summarize recent changes"
```

To invoke `multi-anti run --` whenever you type `agy`, add an alias or function to your shell profile:

```bash
# Bash or Zsh (~/.bashrc or ~/.zshrc)
alias agy='multi-anti run --'
```

```powershell
# PowerShell ($PROFILE)
function agy { multi-anti run -- @args }
```

When that alias is active, run `command agy` in Bash or Zsh, or `agy.exe` in PowerShell, if you need to call native `agy` directly.

To run native `agy` directly after `multi-anti switch` or `multi-anti next`, or to keep `/login` and `/logout` inside `agy` synced with `multi-anti`, scope `SSH_TTY=multi-anti` via a shell alias (or export `SSH_TTY=multi-anti` in your shell profile). `agy` then reads and writes `~/.gemini/antigravity-cli/antigravity-oauth-token` instead of OS Keyring or Windows Credential Manager:

```bash
# Bash or Zsh (recommended scoped alias)
alias agy='SSH_TTY=multi-anti agy'

# Or export globally
export SSH_TTY=multi-anti
```

```powershell
# PowerShell
$env:SSH_TTY = "multi-anti"
```

### Using native `agy` directly vs `multi-anti`

- **Direct `agy` without `SSH_TTY`.** Desktop `agy` writes credentials to OS Keyring or Windows Credential Manager and runs a local browser loopback OAuth flow, which does not enroll accounts into `state.json`. Note that `agy` 1.5.14+ still falls back to reading `~/.gemini/antigravity-cli/antigravity-oauth-token` when OS Keyring is empty, so direct `agy` will pick up a previously staged native token unless you remove that account or run `multi-anti restore`. If browser loopback sign-in fails with `consumerOAuth: token exchange failed`, sign in with `multi-anti login` instead; it runs `agy` inside a clean isolated profile with `SSH_TTY=multi-anti` using `https://antigravity.google/oauth-callback` code paste.
- **Direct `agy` with `SSH_TTY=multi-anti` or `multi-anti run`.** Once the `multi-anti` plugin is installed, `SessionStart`, `Stop`, and `statusline` hooks (along with `multi-anti run` on exit) automatically synchronize `/login` and `/logout` with `state.json`. Running `/login` inside `agy` enrolls a new account or updates fresher credentials for an existing account and sets `active_key`; running `/logout` deletes the native token file, hides the status line, and clears `active_key` while keeping saved accounts in `state.json`.
- **`next` or `switch` vs `run`.** The default policy mode (`highest_remaining` with `target_pool=all`) evaluates each account by its lowest remaining pool (`gemini` and `3p`) and causes plain `multi-anti run` to re-pick whichever eligible account currently has the most remaining quota. If an account hits `0%` in one pool (for example `3p`) while another pool (such as `gemini`) still has quota, `fill_first` still treats it as exhausted under `target_pool=all`; pass `multi-anti run --account <key>`, target a specific pool (`--pool gemini` or `multi-anti policy --pool gemini`), or launch direct `agy` with `SSH_TTY=multi-anti` (in PowerShell, `$env:SSH_TTY = "multi-anti"`).

## CLI reference

### Account management

- `multi-anti login [--no-browser] [--timeout 3m] [--priority N] [--alias <name>] [--no-refresh] [--agy-bin <path>] [--json]` authenticates a Google account. When `MULTI_ANTI_OAUTH_CLIENT_ID` and `DefaultClientID` are unset, it delegates sign-in to `agy` inside an isolated temporary profile, opens the Google OAuth URL unless `--no-browser` is passed, reads the pasted authorization code from `https://antigravity.google/oauth-callback`, and imports the token. When `client_id` is configured, it uses direct loopback OAuth PKCE on `127.0.0.1:51121` with manual redirect URL or code paste fallback. Pass `--agy-bin <path>` to override the `agy` executable path in fallback mode. `multi-anti` preserves existing `priority` and `alias` values when omitted on re-login.
- `multi-anti import [path] [--native] [--priority N] [--alias <name>] [--no-refresh] [--json]` imports a native `antigravity-oauth-token` file (defaulting to `antigravity-oauth-token` inside `MULTI_ANTI_AGY_HOME` or user home when no path is given) or a multi-account JSON array or `{"accounts": ...}` export.
- `multi-anti accounts [--json]` (also `list` or `ls`) syncs fresher native tokens for managed accounts and lists all managed accounts with active marker (`*`), tier, health or cooldown remaining, priority, per-pool quota columns (`GEMINI 5h/wk` and `CLAUDE/GPT 5h/wk` with active reset countdowns, such as `83%(1h52m)/94%(6d20h)`), and last-used time, plus a note if `~/.gemini/antigravity-cli/antigravity-oauth-token` holds an unmanaged or different account. JSON output includes full redacted `quota.buckets`, `reset_at_local`, `reset_in`, `reset_in_seconds`, `primary_reset_at_local`, `primary_reset_in`, `primary_reset_in_seconds`, `cooldown_until_local`, `cooldown_remaining_seconds`, and `fetched_at_local` without OAuth tokens.
- `multi-anti switch [email-or-key] [--model <m>] [--pool <gemini|3p|all>] [--no-refresh] [--force] [--json]` stages a specific account into native `agy` storage, or picks the next eligible account when no target is provided. Refuses `disabled` and `needs_reauth` accounts, and refuses `cooldown` accounts unless `--force` is passed. When OAuth `client_id` is unset, `switch` still stages any account that has a `refresh_token` even if its `access_token` is expired or absent so `agy` refreshes it on launch.
- `multi-anti next [--model <m>] [--pool <gemini|3p|all>] [--no-refresh] [--json]` switches away from the active account to the next eligible account ranked by policy, staging accounts with a `refresh_token` even when `client_id` is unset.
- `multi-anti enable <email-or-key>` and `multi-anti disable <email-or-key>` mark an account `ready` or `disabled`.
- `multi-anti priority <email-or-key> <int>` sets an integer priority where higher values win tie-breaks and `priority` selection mode.
- `multi-anti remove <email-or-key>` (also `rm`) deletes an account from `state.json`, clears `active_key` if matched, removes its isolated profile directory, and deletes `~/.gemini/antigravity-cli/antigravity-oauth-token` when that staged native token belongs to the removed account.

### Quota and execution

- `multi-anti quota [--no-refresh|--cached] [--refresh] [--watch[=30s]] [--models] [--pool <gemini|3p|all>] [--json]` (also `usage` or `status`) refreshes CloudCode quota across non-disabled accounts using up to 4 concurrent requests, ranks eligibility, and renders the summary ranking table followed by a compact per-account breakdown (`gemini` and `claude/gpt` with `5h` and `wk` percentages to 2 decimal places, reset countdowns in `d/h/m`, local reset timestamps, cooldown deadlines, and cached fetch ages). Use `--models` for a per-model breakdown, `--watch` to poll periodically, or `--json` for structured output with `generated_at_local`, `fetched_at_local`, `reset_at_local`, `reset_in`, `reset_in_seconds`, `cooldown_until_local`, and `cooldown_remaining_seconds`. When OAuth `client_id` is unset, `multi-anti quota` fetches live quota while an account's `access_token` is valid for about 1 hour and falls back to cached quota with a `stale (set OAuth client_id to refresh offline)` note once an idle account's `access_token` expires.
- `multi-anti run [flags] [agy args...] [-- <agy args...>]` (also `agy`) selects the best ready account, stages credentials, and launches `agy`. Always pass `--account <email-or-key>` to choose an account; bare email addresses or managed account names placed before `--` (not after `-p` or another value flag) are rejected before modifying state or invoking `agy`. Unrecognized flags before `--` (such as `-p`, `--print`, `--prompt`, `-c`, `--continue`, `--conversation`, `--effort`, and `--dangerously-skip-permissions`) and all arguments after `--` pass through to `agy`. Passing `--model <val>` selects the matching account quota pool and forwards `--model <val>` to `agy`.
  - `--account <email-or-key>` forces a specific account.
  - `--model <model>` targets the pool for that model and forwards `--model` to `agy`.
  - `--pool <gemini|3p>` overrides the target quota pool for selection.
  - `--isolate` runs `agy` in a per-account profile home directory.
  - `--no-refresh` skips the pre-launch quota refresh.
  - `--auto-relaunch` / `--no-auto-relaunch` controls automatic live failover and continuation (`--conversation <id> -i continue`) when the `Stop` hook switches accounts in interactive mode (enabled by default).
  - `--max-switches <N>` caps automatic switch-and-relaunch attempts (defaults to `max(3, account_count)`).
  - `--agy-bin <path>` overrides the `agy` executable path.
- `multi-anti policy [--mode highest_remaining|fill_first|round_robin|priority] [--threshold <0..1>] [--cooldown <dur>] [--refresh-skew <dur>] [--pool <gemini|3p|all>] [--json]` displays or updates the account selection policy. Defaults are `mode=highest_remaining`, `threshold=0.05`, `cooldown=5m`, `refresh_skew=5m`, and `target_pool=all`.

### Plugin, hooks, diagnostics, and restore

- `multi-anti plugin <install|uninstall|status> [--bin <path>] [--no-statusline] [--json]` installs, removes, or inspects the embedded plugin bundle in `~/.gemini/config/plugins/multi-anti` and configures `statusLine` in `agy` `settings.json`.
- `multi-anti statusline [install|uninstall|render] [--bin <path>]` configures or renders a compact multi-line `agy` status table across all managed accounts (`*` active, `>` next, standby, cooldown) with `GEMINI 5h/wk` and `CLAUDE/GPT 5h/wk` remaining percentages plus active reset countdowns (`83%(1h52m)/94%(6d20h)`), and status (defaults to `render`). It outputs nothing when `agy` sends a signed-out status payload (no `email` and no quota data).
- `multi-anti hook <session-start|stop>` handles `agy` plugin hook events for `SessionStart` and `Stop`.
- `multi-anti doctor [--json]` checks the `agy` binary and version, `state.json`, native backup SHA256 integrity, account health and refresh token presence, plugin files, `agy plugin validate --strict`, `statusLine` configuration, `SSH_TTY`, and an `[INFO]` `oauth_client` line noting whether OAuth client credentials are configured or using `agy` fallback.
- `multi-anti restore` (also `restore-native`) restores the pre-`multi-anti` native `antigravity-oauth-token` (or removes it if none existed originally) and restores the prior `statusLine` setting.
- `multi-anti version` (also `-v` or `--version`) prints the binary version.
- `multi-anti help [command]` (also `-h` or `--help`) prints root or command-specific help.

## Auto-switch mechanics

1. **Pre-launch selection.** `multi-anti run` refreshes non-disabled accounts unless `--no-refresh` is set, picks the highest-ranked ready account for the target pool (`gemini` or `3p`), and writes the `agy` token file. When OAuth `client_id` is configured, it refreshes expiring OAuth tokens under `refresh.lock`. When `client_id` is unset, `multi-anti run`, `switch`, and `next` still stage accounts that have a `refresh_token` even when `access_token` is expired or absent so `agy` refreshes the token on launch.
2. **SessionStart hook.** Displays the active account, cooldown duration, remaining quota percentage with active reset countdown, and ready count in the UI without injecting prompt bloat into model context. Cached quota displays and selection automatically treat any window whose scheduled `reset_at` has passed as `100%` reset.
3. **Stop hook.** When `agy` stops with a quota exhaustion error (`429`, `RESOURCE_EXHAUSTED`, spend cap, or window limit), `multi-anti hook stop` resolves subagent `conversationId`s back to the root user conversation, places the failing account on cooldown until reset, stages the next ready account, and writes a per-run switch signal (`signals/run-<id>.json`). It stages standby accounts that have a `refresh_token` even without OAuth `client_id`.
4. **Automatic retry and live interactive continuation.** In headless mode (`-p`, `--print`, or `--prompt`), `multi-anti run` detects either the `Stop` hook signal or captured `429` or `RESOURCE_EXHAUSTED` output, cools down the exhausted account, and retries with the next ready account. In interactive mode (enabled by default unless `--no-auto-relaunch` is set), `multi-anti run` watches `signals/run-<id>.json` while `agy` runs; when a quota switch fires, it cleanly terminates the in-memory `agy` session and relaunches with `--conversation <root-id> -i continue` so execution resumes on the newly staged account.
5. **Token sync-back and `/login` / `/logout` sync.** After `agy` exits (and during `SessionStart` or `statusline` hooks under `SSH_TTY=multi-anti`), `multi-anti` writes refreshed OAuth tokens back to `state.json`, automatically enrolls new accounts signed in via `/login` and switches `active_key`, and soft-clears `active_key` while preserving saved accounts if `/logout` removed the staged native token.

## Isolated profiles with `--isolate`

By default, `multi-anti` stages tokens into `~/.gemini/antigravity-cli/antigravity-oauth-token` and launches `agy` with `SSH_TTY=multi-anti` so `agy` reads the staged token file directly instead of querying OS Keyring or Windows Credential Manager.

With `multi-anti run --isolate`, each account runs under its own profile directory (`<data_dir>/profiles/<account-slug>`) via `HOME` and `USERPROFILE`:

- Writes only that account's token into `<profile>/.gemini/antigravity-cli/antigravity-oauth-token`.
- Projects shared `~/.gemini/antigravity-cli/settings.json` and `~/.gemini/config` via symlinks on Linux and macOS, or hardlinks and NTFS directory junctions on Windows, and copies `settings.json` when hardlinks cannot cross volumes.
- On Linux and macOS, sets `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and `GIT_CONFIG_GLOBAL` to your real home defaults when unset so editor, git, and tool configs stay accessible.

## Backup and restore safety

- **First-write native backup.** Before `multi-anti switch`, `multi-anti next`, `multi-anti run`, or `multi-anti hook stop` modifies `~/.gemini/antigravity-cli/antigravity-oauth-token`, `EnsureNativeBackup` captures its original bytes and SHA256 digest in `<data_dir>/backups/native-antigravity-oauth-token.bak` (or records `had_file: false` if none existed).
- **StatusLine backup.** Installing the `statusLine` backs up any existing non-`multi-anti` `statusLine` object once in `<data_dir>/backups/statusline.json`.
- **Token redaction.** `--json` outputs (`accounts`, `quota`, `login`, `import`, `switch`, `next`, `doctor`) emit redacted JSON without `access_token`, `refresh_token`, or `id_token`.
- **Full rollback.** Run `multi-anti restore` and `multi-anti plugin uninstall` to restore your original native token, `statusLine` settings, and Gemini plugin config.

## Paths and environment variables

`multi-anti` stores its own state under `<data_dir>` and reads or stages native `agy` files under `<home_dir>`:

| Path | Location |
| :--- | :--- |
| Data directory (`<data_dir>`) | `$XDG_DATA_HOME/multi-anti` or `~/.local/share/multi-anti` on Linux and macOS; `%LOCALAPPDATA%\multi-anti` on Windows. |
| State, locks, backups, signals, profiles | `state.json`, `state.lock`, `refresh.lock`, `backups/`, `signals/`, and `profiles/` inside `<data_dir>`. |
| Native `agy` token file | `~/.gemini/antigravity-cli/antigravity-oauth-token` (inside `MULTI_ANTI_AGY_HOME` when set). |
| Native `agy` settings | `~/.gemini/antigravity-cli/settings.json`. |
| Installed plugin bundle | `~/.gemini/config/plugins/multi-anti/`. |
| Gemini CLI config | `~/.gemini/config/config.json`. |

These environment variables configure `multi-anti` or are passed to child `agy` processes:

| Variable | Purpose |
| :--- | :--- |
| `MULTI_ANTI_HOME` | Override data directory (defaults to `$XDG_DATA_HOME/multi-anti` or `~/.local/share/multi-anti` on Linux and macOS, and `%LOCALAPPDATA%\multi-anti` on Windows). |
| `MULTI_ANTI_AGY_HOME` | Override home directory containing `.gemini` (defaults to OS user home directory). |
| `MULTI_ANTI_OAUTH_CLIENT_ID` | Optional. Supply or override the Google OAuth desktop `client_id` for direct PKCE login and offline token refresh. |
| `MULTI_ANTI_OAUTH_CLIENT_SECRET` | Optional. Supply or override the Google OAuth desktop `client_secret` for direct PKCE login and offline token refresh. |
| `MULTI_ANTI_MANAGED` | Set to `1` in the child `agy` environment when launched by `multi-anti run`. |
| `MULTI_ANTI_ACCOUNT` | Set in the child `agy` environment to identify the launched account key. |
| `MULTI_ANTI_ISOLATED` | Set to `1` in the child `agy` environment when launched with `--isolate`. |
| `MULTI_ANTI_RUN_ID` | Set in the child `agy` environment so `multi-anti hook stop` writes a per-run switch signal (`signals/run-<id>.json`) for live interactive continuation. |
| `SSH_TTY` | Set to `multi-anti` in the child `agy` environment so `agy` reads the staged token file instead of OS Keyring or Windows Credential Manager. |

## Upgrade

Update your `multi-anti` binary and refresh the installed plugin bundle:

1. Pull the latest repository changes and rebuild the binary. Include your `-ldflags` values if you embed OAuth credentials at build time.
2. Replace the binary at your installed `PATH` location (`~/.local/bin/multi-anti` on Linux and macOS, or `%LOCALAPPDATA%\Programs\multi-anti\multi-anti.exe` on Windows).
3. Re-run `multi-anti plugin install` so `~/.gemini/config/plugins/multi-anti/` and `settings.json` receive any updated plugin files or hook definitions.
4. Run `multi-anti doctor` to verify the upgraded binary, plugin validation, and existing accounts.

## Uninstall and rollback

Restore native `agy` state and remove `multi-anti` files in order:

1. Restore the original `antigravity-oauth-token` and prior `statusLine` configuration:

   ```bash
   multi-anti restore
   ```

2. Remove the plugin bundle from `~/.gemini/config/plugins/multi-anti`, remove the `multi-anti` entry from `~/.gemini/config/config.json`, and remove any `multi-anti` `statusLine` entry from `settings.json`:

   ```bash
   multi-anti plugin uninstall
   ```

3. Delete the binary from `PATH`:

   ```bash
   # Linux and macOS
   rm -f ~/.local/bin/multi-anti
   ```

   ```powershell
   # Windows PowerShell
   Remove-Item (Join-Path $env:LOCALAPPDATA "Programs\multi-anti\multi-anti.exe") -Force
   ```

4. Remove any `agy` alias, `SSH_TTY=multi-anti` export, or `MULTI_ANTI_OAUTH_*` variables from your shell profile (`~/.bashrc`, `~/.zshrc`, or PowerShell `$PROFILE`).
5. Optional. Delete `<data_dir>` (`~/.local/share/multi-anti` on Linux and macOS, or `%LOCALAPPDATA%\multi-anti` on Windows) to erase `state.json`, native backups, and isolated profile directories.

## Troubleshooting

### Stale quota on idle accounts without OAuth `client_id`

- **Symptom.** `multi-anti quota` shows `stale (set OAuth client_id to refresh offline)` for an idle account after its 1-hour `access_token` expires.
- **Cause.** `DefaultClientID` and `DefaultClientSecret` in `internal/oauth/client.go` default to `""`, so `multi-anti` cannot refresh tokens offline while an account sits idle. Launching or switching accounts with `multi-anti run`, `switch`, `next`, or `hook stop` still works because `agy` refreshes the staged token on launch and `SyncBackStagedToken` writes the fresh token back to `state.json` on exit.
- **Fix.** Run `multi-anti run --account <email-or-key>` so `agy` refreshes that account's token, or configure `MULTI_ANTI_OAUTH_CLIENT_ID` and `MULTI_ANTI_OAUTH_CLIENT_SECRET` in your shell environment or via `-ldflags` for offline refresh. If hooks run from an IDE or non-login shell that skips `~/.bashrc` or `~/.zshrc`, rebuild with `-ldflags` so every subprocess inherits the credentials. If you configured credentials and see `invalid_client`, verify that `MULTI_ANTI_OAUTH_CLIENT_ID` and `MULTI_ANTI_OAUTH_CLIENT_SECRET` belong to the same Google desktop OAuth client.

### Missing `antigravity-oauth-token` on `import --native`

- **Symptom.** `multi-anti import --native` fails because `~/.gemini/antigravity-cli/antigravity-oauth-token` does not exist.
- **Cause.** Desktop `agy` stores credentials in OS Keyring on Linux and macOS, or Windows Credential Manager on Windows, whenever `SSH_TTY` is unset. `agy` writes the `antigravity-oauth-token` file only when `SSH_TTY` is set.
- **Fix.** Run `multi-anti login` to sign in directly, or run `SSH_TTY=1 agy` once (on Windows PowerShell, `$env:SSH_TTY = "1"; agy`) so `agy` writes `antigravity-oauth-token`, then run `multi-anti import --native`.

### Stale binary path in `hooks.json` or `settings.json`

- **Symptom.** `agy` reports hook errors on `SessionStart` or `Stop`, or the `statusLine` stops updating after you moved or deleted the original build binary.
- **Cause.** Running `multi-anti plugin install` without `--bin` records `os.Executable()` into `~/.gemini/config/plugins/multi-anti/hooks.json` and `~/.gemini/antigravity-cli/settings.json`.
- **Fix.** Verify your `PATH` binary with `which multi-anti` (or `Get-Command multi-anti` in PowerShell), then run `multi-anti plugin install` from that installed binary or pass `--bin multi-anti`. Confirm with `multi-anti plugin status` and `multi-anti doctor`.

### Port `51121` is busy during `multi-anti login`

- **Symptom.** Another process already listens on `127.0.0.1:51121` when running `multi-anti login` in direct PKCE mode.
- **Behavior and fix.** When OAuth `client_id` is configured, `multi-anti login` automatically falls back to an available ephemeral loopback port on `127.0.0.1`. If your OAuth client rejects dynamic redirect ports or you are logged into a remote host over SSH without port forwarding, run `multi-anti login --no-browser` and paste the redirect URL or authorization code into the terminal, or stop the process holding port `51121` before retrying.

## Release automation

GitHub Actions workflows under `.github/workflows/` automate validation and tagged releases for `tuannt39/multi-anti`:

- `.github/workflows/ci.yml` runs `go vet ./...`, `go test` on Linux (`-race`) and Windows, and cross-compile checks for Linux (`amd64`, `arm64`) and Windows (`amd64`, `arm64`) on pushes to `main` or `master` and on pull requests.
- `.github/workflows/release.yml` runs on any pushed tag matching `v*`. It verifies `go vet ./...` and `go test -count=1 ./...`, builds static `CGO_ENABLED=0` binaries (`multi-anti-linux-amd64`, `multi-anti-linux-arm64`, `multi-anti-windows-amd64.exe`, `multi-anti-windows-arm64.exe`) with `-ldflags "-s -w -X main.version=${VERSION}"`, generates `SHA256SUMS.txt`, and creates or updates the GitHub Release with all assets attached.

```bash
git tag v0.1.0
git push origin v0.1.0
```
