# pi-bridle (draft / experiment)

**A [`pi`](https://github.com/earendil-works/pi) extension that runs pi's
`bash` tool — and the user's `!` commands — through the agent-bridle capability
leash.**

> **Status: experiment, in *our* repo only.** This is a draft to prove that the
> agent-bridle leash is useful against a second, independent agent harness. It
> is **not** submitted upstream to pi and must not be until it has proven its
> worth to us. See newt-agent `docs/decisions/lessons_from_pi.md`.

## Why

pi states plainly in its README that it has **no built-in permission system**:
by default it runs every tool with the full ambient authority of the user that
launched it, and points you at containerization for isolation. That is the
classic [confused-deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem)
problem — the harness holds full authority while taking arguments from an
untrusted LLM.

agent-bridle closes that gap **structurally**: every exec is checked against an
[`agent_mesh_protocol::Caveats`] grant *before* it runs, and the shell uses
brush's *carried* coreutils (not the host's), backstopped by Landlock on Linux.
This extension reuses pi's own "replace a built-in tool's operations" seam (the
same seam pi's `gondolin` example uses to route `bash` into a micro-VM) to route
`bash` into the leash instead.

```
pi  ──registerTool(bash, …)──►  this extension
                                     │  BashOperations.exec(cmd)
                                     ▼
                          agent-bridle-mcp  (stdio JSON-RPC 2.0)
                                     │  tools/call { name:"shell", arguments:{cmd} }
                                     ▼
                       registry.dispatch  →  Caveats check  →  brush shell
                                     │
                          { exit_code, stdout, stderr }
```

The leash is sourced exactly as `agent-bridle-mcp` always sources it:
`$AGENT_BRIDLE_CAVEATS` (JSON), else `~/.agent-bridle/config.toml` `[caveats]`,
else a loudly-warned unconfined default. Nothing pi-specific decides authority.

## What it does

- Replaces pi's built-in `bash` tool execution with a `BashOperations` impl that
  dispatches the command to the `shell` tool exposed by `agent-bridle-mcp`.
- Routes the user's `!` shell commands (pi's `user_bash` event) through the same
  leash.
- Adds a `/bridle` command that prints the active leash banner.

Out of scope for this draft: file tools (pi's `read`/`write`/`edit` run on the
host fs; bridle's fs caveats would need brush fs tools wired through MCP first)
and `web_fetch` (pi ships no web-fetch built-in today; `agent-bridle-tool-web`
is ready when it does).

## Known tradeoffs (this is a draft)

- **Carried shell, not host shell.** Commands run in brush's confined shell with
  carried coreutils and a restricted `PATH`. This is the security win, but it
  changes execution semantics vs. pi's host bash — same tradeoff gondolin makes
  by running in a VM. Some host-specific tools will not be present.
- **Non-streaming.** `agent-bridle-mcp` returns the full result envelope; this
  extension emits stdout once on completion rather than streaming token-by-token.
- **One shared session leash.** All commands in a pi session share the one
  granted `Caveats`. Per-tool attenuation is possible (the registry already
  does `granted.meet(required)`) but not surfaced here.

## Setup (manual, for our own evaluation)

1. Build the MCP frontend from this workspace:
   ```bash
   cargo build -p agent-bridle-mcp --features shell   # produces target/debug/agent-bridle-mcp
   ```
2. Define a leash (example: allow only a handful of programs):
   ```bash
   export AGENT_BRIDLE_CAVEATS='{"exec":{"Only":["echo","ls","cat","git"]},"max_calls":{"AtMost":50}}'
   ```
   …or put the equivalent under `~/.agent-bridle/config.toml` `[caveats]`.
3. Point the extension at the binary and run pi from your project:
   ```bash
   export PI_BRIDLE_MCP_BIN=/path/to/agent-bridle/target/debug/agent-bridle-mcp
   pi -e /path/to/agent-bridle/integrations/pi-bridle
   ```

Ask the agent to run `ls`, then to run `rm something` — the first succeeds, the
second is refused by the leash before brush ever spawns it.

## Files

- `index.ts` — the extension (the `pi` entry point + a minimal MCP stdio client).
- `package.json` — pi extension manifest (`pi.extensions`).
