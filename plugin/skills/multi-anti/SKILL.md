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
and usage across CloudCode pools (`gemini`, `3p`, `gemini-argon`), and rotates
accounts on quota exhaustion.

## Common commands

- List managed accounts, per-pool quotas (`GEMINI 5h/wk`, `CLAUDE/GPT 5h/wk`, `ARGON wk`), cooldown states, and native token drift notes:
  `multi-anti accounts` or `multi-anti list`
- Check live quota and full per-group usage across all accounts while each
  `access_token` is valid. Set `MULTI_ANTI_OAUTH_CLIENT_ID` optionally for
  offline refresh once an idle account's 1-hour `access_token` expires, or
  `multi-anti quota` shows cached quota with a `stale` note:
  `multi-anti quota` or `multi-anti usage`
  (add `--models`, `--pool <gemini|3p|gemini-argon>`, or `--json`)
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
`multi-anti usage`, `multi-anti quota --models`, or `multi-anti quota --json`)
and present a concise per-account breakdown across all three pools and both time
windows (`5h` and `wk`) to 2 decimal places with reset countdowns, rather than
collapsing the response to a single percentage or printing boilerplate paragraphs:

1. `gemini` (`Gemini 4 Neon`, `Gemini 4 Hydrogen`, `Orchestrator (Neon)`, `Gemini 3.8 Flash`): `5h` and `wk` limits.
2. `claude/gpt` (`Claude Opus 5.5`, `Claude Sonnet 5.5`, `GPT-OSS 120B`): `5h` and `wk` limits.
3. `argon` (`Gemini 4 Argon`): `wk` limit (separate on paid Pro plans; included in Gemini quota on Ultra plans).

## Automatic rotation behavior

1. On `SessionStart`, the plugin displays the active account, remaining pool
   percentage, and available standby count.
2. On `Stop` with a quota exhaustion error (`429`, `RESOURCE_EXHAUSTED`, spend
   cap, or window limit), the hook marks the current account in cooldown, stages
   the next ready account, and records a handoff signal for `multi-anti run`.
3. Even when `MULTI_ANTI_OAUTH_CLIENT_ID` is unset, `multi-anti run`, `switch`,
   `next`, and `hook stop` stage any account that has a `refresh_token`. `agy`
   refreshes the token on launch, and `multi-anti` writes the refreshed token
   back on exit.
4. `multi-anti statusline` renders a compact multi-line table showing all managed accounts (`*` active, `>` next, standby, cooldown) with `GEMINI 5h/wk`, `CLAUDE/GPT 5h/wk`, `ARGON wk`, and status.
5. Running `agy` with `SSH_TTY=multi-anti` (such as `alias agy='SSH_TTY=multi-anti agy'`) or via `multi-anti run` automatically syncs `/login` (enrolls new accounts or refreshes credentials and sets `active_key`) and `/logout` (hides the status line and clears `active_key` while keeping managed accounts in `state.json`). Default `highest_remaining` policy re-selects the highest-quota account on `multi-anti run`; use `--account <key>` or `multi-anti policy --mode fill_first` to stay on a manually switched account.
