---
name: multi-anti
description: >-
  Manage multiple Google Antigravity CLI accounts, inspect CloudCode quota pools
  and usage, and diagnose automatic account switching and status-line hooks. Use
  when the user asks about multi-anti account switching, quota limits, usage, or
  hook status.
---

# multi-anti

`multi-anti` manages multiple Antigravity CLI (`agy`) OAuth accounts, tracks quota
and usage across CloudCode pools (`gemini`, `3p`), and rotates
accounts on quota exhaustion.

## Common commands

- List managed accounts, per-pool quotas (`GEMINI 5h/wk`, `CLAUDE/GPT 5h/wk`) with active reset countdowns (`83%(1h52m)/94%(6d20h)`), cooldown states, and native token drift notes:
  `multi-anti accounts` or `multi-anti list`
- Check live quota, per-group usage, reset countdowns (`d/h/m`), and local reset timestamps across all accounts while each `access_token` is valid. Set `MULTI_ANTI_OAUTH_CLIENT_ID` optionally for offline refresh once an idle account's 1-hour `access_token` expires, or `multi-anti quota` shows cached quota with a `stale` note:
  `multi-anti quota` or `multi-anti usage`
  (add `--models`, `--pool <gemini|3p>`, or `--json`)
- Add or import an account. `multi-anti login` works out of the box via `agy`
  fallback with no OAuth credentials required:
  `multi-anti login` or `multi-anti import`
- Stage a specific account into native `agy` storage:
  `multi-anti switch <email-or-key>`
- Launch `agy` with automatic quota selection and headless `-p` retry:
  `multi-anti run -- [agy args...]`
- Launch `agy` in an isolated per-account profile directory:
  `multi-anti run --isolate -- [agy args...]`
- Inspect hook, plugin, backup, `oauth_client` mode, and credential health:
  `multi-anti doctor`
- Restore the original pre-`multi-anti` native token and status line:
  `multi-anti restore`

## Models and quota display

When the user asks for account quota or usage, run `multi-anti quota` (or
`multi-anti usage`, `multi-anti quota --models`, or `multi-anti quota --json`).
Present a concise per-account breakdown across both pools and both time windows
(`5h` and `wk`) to 2 decimal places. Include both the reset countdown (`d/h/m`)
and the exact local reset timestamp (`YYYY-MM-DD HH:MM +07:00`) for every active
`5h` and `wk` window across `gemini` and `claude/gpt`, plus any cooldown deadline
or cached fetch age. Do not collapse the response to a single percentage or print
boilerplate paragraphs.

1. `gemini` (`Gemini 4 Neon`, `Gemini 4 Carbon`, `Gemini 4 Argon`, `Gemini 4 Hydrogen`, `Orchestrator`, `Gemini 3.8 Flash`): `5h` and `wk` limits.
2. `claude/gpt` (`Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`): `5h` and `wk` limits.

## Automatic rotation behavior

1. On `SessionStart`, the plugin displays the active account, cooldown duration,
   remaining pool percentage with active reset countdown, and available standby
   count.
2. On `Stop` with a quota exhaustion error (`429`, `RESOURCE_EXHAUSTED`, spend
   cap, or window limit), the hook resolves subagent `conversationId`s to the
   root conversation, marks the current account in cooldown, stages the next
   ready account, and writes a per-run switch signal (`run-<id>.json`) so
   `multi-anti run` (interactive auto-relaunch enabled by default) cleanly
   restarts `agy` with `--conversation <id> -i continue` to resume work. Cached
   quota displays (`statusline`, `accounts`, `quota`) and selection automatically
   restore windows whose scheduled `reset_at` has passed to `100%`.
3. Even when `MULTI_ANTI_OAUTH_CLIENT_ID` is unset, `multi-anti run`, `switch`,
   `next`, and `hook stop` stage any account that has a `refresh_token`. `agy`
   refreshes the token on launch, and `multi-anti` writes the refreshed token
   back on exit.
4. `multi-anti statusline` renders a compact multi-line table with all managed
   accounts (`*` active, `>` next, standby, cooldown), `GEMINI 5h/wk` and
   `CLAUDE/GPT 5h/wk` remaining percentages with active reset countdowns
   (`83%(1h52m)/94%(6d20h)`), and status.
5. Running `agy` with `SSH_TTY=multi-anti` (such as `alias agy='SSH_TTY=multi-anti agy'`, or `$env:SSH_TTY = "multi-anti"` in PowerShell) or via `multi-anti run` automatically syncs `/login` (enrolls new accounts or refreshes credentials and sets `active_key`) and `/logout` (hides the status line and clears `active_key` while keeping managed accounts in `state.json`). Default `highest_remaining` policy with `target_pool=all` scores each account by its lowest pool (`gemini`, `3p`) and re-selects the highest-quota eligible account on `multi-anti run`; use `multi-anti run --account <key>` (never a bare email positional arg), `--pool <pool>` / `multi-anti policy --pool <pool>` when another pool is at `0%`, or `multi-anti policy --mode fill_first` when an eligible account is simply outranked.
