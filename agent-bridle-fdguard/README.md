# agent-bridle-fdguard

Close *ambient* file descriptors on a confined spawn (agent-bridle#319).

An already-open descriptor is an object capability. A confined child must obtain
resources only by inheriting the descriptors it was *delegated* (its stdio),
never by inheriting descriptors the parent happened to leave open with `CLOEXEC`
cleared. `std::process::Command` relies on the platform CLOEXEC convention alone,
which does not close such ambient descriptors.

This crate is the single `unsafe`-permitting seam that lets
[`agent-bridle-core`](https://crates.io/crates/agent-bridle-core) keep
`#![forbid(unsafe_code)]`. It installs an async-signal-safe `pre_exec` hook that
marks every descriptor `>= 3` in the forked child close-on-exec
(`CLOSE_RANGE_CLOEXEC`), so the kernel closes them atomically at `exec` while
preserving stdio — and, crucially, without closing std's own exec-status pipe
early, so a failed `exec` is still reported as an `io::Error` rather than a bogus
`Ok`.

```rust
let mut cmd = std::process::Command::new("some-tool");
// … configure stdio / args / env …
agent_bridle_fdguard::deny_inherited_fds(&mut cmd);
let child = cmd.spawn()?;
```

## Scope

- **Linux**: `close_range(2)` with `CLOSE_RANGE_CLOEXEC` (kernel ≥ 5.11) — one
  race-free syscall marks the whole range.
- **macOS**: no `close_range` exists, so the pre-exec hook sweeps
  `fcntl(F_SETFD, FD_CLOEXEC)` over a bound computed in the parent (the larger
  of `RLIMIT_NOFILE.rlim_cur` and one past the highest open descriptor); see the
  crate docs for the bound's rationale and residual.
- On other platforms `deny_inherited_fds` is a no-op and the CLOEXEC-convention
  residual remains (on Windows the confined path spawns via
  `agent-bridle-aclaunch`'s explicit handle allowlist instead).
- **Fail-closed**: if the marking step fails at spawn time, the pre-exec hook
  returns an error, so `spawn` fails and the child never runs.

Part of the [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle)
capability-enforcement line. License: Apache-2.0.
