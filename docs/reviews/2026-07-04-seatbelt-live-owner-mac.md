# Review — Seatbelt L3 backend, run live on a developer Mac

- Date: 2026-07-04
- Scope: run the `check-macos` kernel proofs on real Apple-Silicon hardware
  (not the GitHub `macos-latest` runner) against `main` @ `bacb3b1` — the first
  owner-Mac exercise of the Seatbelt L3 line since ADR 0019 and the host-shell
  engine (#199) landed. Includes a targeted chase of the PR #195 net-proxy CI
  flake.
- Outcome: **all Seatbelt kernel proofs pass on real hardware; ADR 0019's
  premise holds.** One latent test-serialization gap identified (not a product
  bug). No code on `main` altered by this review.
- Method: ran the exact `.github/workflows/ci.yml` `check-macos` commands with
  `RUSTFLAGS="-D warnings"` and `BRIDLE_REQUIRE_SEATBELT=1`, plus a 40× parallel
  flake-repro loop of the tool-shell lib suite.

---

## TL;DR

The macOS L3 jail is **real on real hardware**. Every kernel proof that spawns a
`sandbox-exec` child and asserts a kernel denial passed — fs read/write, exec
allow-list (incl. the interpreter-trampoline and dyld-linking cases ADR 0014
turns on), empty-net and loopback-only net, the net-proxy egress fence, the
`ShellTool` end-to-end path, and the **ADR 0019 host-shell keystone**
(`macos_dynamic_construct_runs_but_out_of_scope_write_is_seatbelt_denied`): a
`$(...)` the subset engine refuses *runs*, yet its out-of-scope write is
kernel-denied, `sandbox_kind == "seatbelt"`. `BRIDLE_REQUIRE_SEATBELT=1` means
these were genuinely exercised, not skipped
(`proof_gate_required_but_unsupported_is_a_failure` guards that). Full results
and the downstream newt adoption plan live in the embedder repo:
[`newt-agent/docs/testing/seatbelt-live-uat.md`](https://github.com/Gilamonster-Foundation/newt-agent/blob/main/docs/testing/seatbelt-live-uat.md).

## The one finding — a test-serialization gap (not a product bug)

PR #195's macOS CI leg once failed on
`net_proxy::…::fenced_child_reaches_allowed_via_proxy_denied_refused_direct_kernel_blocked`
("Empty reply from server"), while `main` stayed green. On this Mac it **did not
reproduce** (0/40 parallel runs; 41/41 including the proof run) — an M4 is too
fast/uncontended to lose the race.

But inspection pins the cause: of the 17 `net_proxy` tests, every one that binds
a loopback listener and does an HTTP exchange serializes on the module's
`net_test_lock()` — **except** this test, which is the single heaviest network
test (loopback origin + proxy + a real `curl` child) yet the only such test that
omits the lock. Run concurrently with a sibling proxy test it races on loopback,
matching the CI symptom.

**Suggested fix (one line, matches every sibling):** add
`let _serial = net_test_lock();` as the test's first statement in
`agent-bridle-tool-shell/src/net_proxy.rs`. Filed as an issue with this
evidence; a fix PR is held pending review.

## Environment

Apple M4 MacBook, macOS Darwin 25.5.0 (arm64); rustc/cargo 1.95.0 (Homebrew);
`/usr/bin/sandbox-exec` present. clippy `-D warnings` was clean on this
toolchain, and `--no-default-features --features host-shell` compiled in
isolation (the corner `--all-features` never exercises).
