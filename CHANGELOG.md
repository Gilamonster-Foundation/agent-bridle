# Changelog

All notable changes to the agent-bridle workspace are documented here. The
format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed — `shell` tool is now a fail-closed stub (publish unblock)

To make the whole workspace publishable to crates.io (agent-bridle → newt), the
brush **git** dependency was removed: crates.io forbids any git source in a
published manifest, and `agent-bridle-tool-shell` pinned three brush crates to a
git fork (`https://github.com/hartsock/brush`, rev
`f0ef7715a02f44c670e7f5d5e59d1c7721ea282c`; audit notes also reference rev
`4e65a06`) for an in-process `CommandInterceptor` exec/open hook.

- **Removed** the three brush git dependencies (`brush-core`, `brush-builtins`,
  `brush-coreutils-builtins`) from the workspace root `Cargo.toml` and from
  `agent-bridle-tool-shell/Cargo.toml`. The `shell` feature no longer pulls
  brush or a tokio runtime; tokio is now a dev-dependency of the shell crate
  only (for its `#[tokio::test]` tests). The shell crate's bash runner uses
  `std::process::Command` + threads with a hand-rolled wall-clock timeout.
- **Replaced** the brush-backed confined `ShellTool` (and the
  `caveat_interceptor` module) with a **fail-closed stub plus an opt-in
  UNCONFINED-bash escalation ladder**, expressed as a `ShellPolicy`:
  - `ShellTool::stub()` (= `new()`, `Default`) — **Denied**: never spawns
    anything. This is the published default and what `registry()` builds.
  - `ShellTool::insecure_bash(hook)` — runs `bash -lc <command>` (falling back
    to `sh -c`) UNCONFINED, but only after an `ApprovalHook::approve` returns
    true. Reported honestly as `sandbox_kind: none`.
  - `ShellTool::dangerous_unconfined()` — runs the same UNCONFINED bash with no
    approval gate. Development only.
- **Added** `agent_bridle::registry_with_shell(shell)` (the escalation seam) and
  re-exported `ApprovalHook` / `ShellPolicy` from the facade. `registry()`
  delegates to it with `ShellTool::stub()`.
- **Added** `agent-bridle-mcp` CLI flags (hand-parsed, no clap): `--insecure`
  (per-command approval prompted on `/dev/tty`, never stdin) and
  `--dangerously-allow-all` (no gate). No flag → the stub. A one-line stderr
  banner announces any unconfined mode.
- **`linux-landlock`** still compiles in the shell crate but is currently a
  no-op there (the confined spawn path is gone). `agent-bridle-core`'s Landlock
  code is untouched and returns to use with the confined shell.

The brush-backed confined `ShellTool` and `CaveatInterceptor` are preserved in
git history at the commit that introduced this change. **RESTORE** them — and
the brush deps + `shell` feature wiring — when the `CommandInterceptor` hook is
upstreamed into `reubeno/brush` and lands as a crates.io release. Look for
`RESTORE:` comments in `Cargo.toml`, `agent-bridle-tool-shell/Cargo.toml`, and
`agent-bridle-tool-shell/src/shell_tool.rs`.
