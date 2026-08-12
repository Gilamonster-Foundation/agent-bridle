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
closes every descriptor `>= 3` in the forked child before `exec`, preserving
stdio.

```rust
let mut cmd = std::process::Command::new("some-tool");
// … configure stdio / args / env …
agent_bridle_fdguard::deny_inherited_fds(&mut cmd);
let child = cmd.spawn()?;
```

## Scope

- **Enforcement is Linux-only** for now (`close_range(2)`, kernel ≥ 5.9 — the only
  child-safe, race-free primitive). On other platforms `deny_inherited_fds` is a
  no-op and the CLOEXEC-convention residual remains.
- **Fail-closed**: if `close_range` fails at spawn time, the pre-exec hook returns
  an error, so `spawn` fails and the child never runs.

Part of the [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle)
capability-enforcement line. License: Apache-2.0.
