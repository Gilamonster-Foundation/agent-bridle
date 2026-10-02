## Summary

Completes agent-bridle#405's macOS leg: `net: none` with zero `mach:` grants
now resolves `Bounded(∅)` at `Kernel` strength and admits under a `CONFINED`
contract, backed by a complete native deputy audit.

- Reuses the L3/L4 mechanism already drafted on a prior branch
  (`seatbelt_net_kernel_witness`, the `report.rs` Seatbelt `net` arm that
  consumes it, and the matching tests) — no new mechanism, cherry-picked
  unchanged.
- Measures every remaining ambient-IPC candidate ADR 0015/#405 listed:
  `iokit-open`, `sysctl-write`, a write-class `file-ioctl`,
  `process-info`/`signal` to an unconfined sibling process, XPC paths beyond
  `mach-lookup`, and AppleEvents. Each gets a positive control (unconfined)
  and a confined attempt against an owned local resource; nothing touches the
  real internet.
- Result: `iokit-open`, `sysctl-write`, and the write-class `file-ioctl` are
  closed by OS privilege separation (entitlement/root-gated, fails identically
  confined and unconfined — same disposition as the existing `utun` finding).
  `process-info`/`signal` is reachable both ways but is not an egress channel
  on its own (same colluding-process reasoning already applied to
  `mach-register`). XPC beyond `mach-lookup` is closed by construction: this
  spawn mechanism hands the child only plain stdio pipes, never a
  pre-connected port or fd. AppleEvents — measured from an interactive GUI
  session with Automation granted — is closed: the AppleEvent send itself
  fails via an unlisted, mach-lookup-mediated XPC service before ever
  reaching the target app, the same blanket deny as every other unlisted
  service.
- **Every channel this audit identified is now CLOSED or correctly placed out
  of the net-egress threat model.** `MACH_DEPUTY_AUDIT` flips to `Complete`
  in its own commit, as the design review for this amendment required.
- The Seatbelt `net` arm in `report.rs` now reports `Kernel` for exactly the
  deny-all, zero-grant shape; a named `mach:` grant, a loopback scope, and a
  general remote-host allowlist are unaffected and stay `Unknown`/`Advisory`.
  Seven pre-existing tests that hard-coded "Seatbelt restricted net is always
  Advisory" are updated to check the real `seatbelt_mach_deputy_audit_complete()`
  state rather than assuming it, so they stay correct on every platform
  (Advisory off macOS, where the audit doesn't exist; Kernel on macOS now).
- Added the CI kernel proof the brief asked for, through the real production
  spawn path (`Gate::authorize` + `ConfinedCommand::spawn`): `net: none` with
  zero `mach:` grants now admits (a benign command actually runs), and the
  real kernel still blocks the child's own network attempt (positive control:
  an unconfined curl reaches an owned loopback listener; confined: the same
  request never reaches it, exact exit 7).
- Fixed a verdict-logic bug in the checked-in AppleEvents probe script
  (unrelated repo): its confined/unconfined grep patterns overlapped, so a
  working positive control would have misreported the confined leg as a hit.
- `net_direct_denied` (the L3 predicate) is broader than `net_fully_denied`
  (the L4 one) — it also covers a `unix:`-only scope. Re-enabled the two
  `tests/unix_socket_grants.rs` tests `#[ignore]`d since `1ac8995` for exactly
  this promotion, and deleted the now-obsolete negative control that pinned a
  `unix:` grant refusing at L3. One sub-case (a `unix:` grant MIXED with a
  plain remote host) still refuses, for a reason independent of this audit —
  a plain host is never a structural token, so that shape was never
  `net_direct_denied` and was never going to be covered here; split into its
  own test and `#[ignore]`d with the accurate reason (a separate egress-proxy
  admission gap).

ADR 0015 gains the completed Amendment E6 evidence table; `macos-evidence.md`
is updated to match. Windows (AppContainer) is unaffected and out of scope.

## Test plan

- `cargo test -p agent-bridle-core --all-features` (Linux, gnuc): 327/327
  passed. Every Seatbelt-conditional assertion takes its Advisory/refuse
  branch here, since the audit-complete predicate is unconditionally `false`
  off macOS.
- `cargo fmt --all -- --check` / `cargo clippy -p agent-bridle-core --all-targets --all-features -- -D warnings`:
  clean on Linux and on the Mac test runner.
- `BRIDLE_REQUIRE_SEATBELT=1 cargo test -p agent-bridle-core --all-features`
  (macOS): full suite passed, including:
  - `net_none_resolves_bounded_empty_now_the_audit_is_complete` /
    `mach_grant_resolves_its_named_class_not_unknown_or_empty` /
    `loopback_and_remote_host_stay_unknown_even_with_a_complete_audit`
    (the L3 projection, through the real constant);
  - `seatbelt_net_none_reports_kernel_now_the_audit_is_complete` /
    `seatbelt_net_grant_loopback_and_remote_host_stay_advisory` (the L4
    report, through the real constant);
  - `net_none_now_admits_and_the_kernel_still_blocks_egress` (the end-to-end
    admission proof: `Gate::authorize` + `ConfinedCommand::spawn` now admits
    `net:none`, and the real kernel still refuses the child's own egress,
    positive control included).
- Native channel probes (positive control + confined differential, owned
  local targets only), and the AppleEvents GUI-session measurement: see the
  ADR 0015 Amendment E6 table for the full evidence and exact error
  codes/strings for each row.

Part of #405

🤖 Generated with [Claude Code](https://claude.com/claude-code)
