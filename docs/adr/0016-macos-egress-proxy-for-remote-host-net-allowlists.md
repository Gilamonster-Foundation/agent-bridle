# ADR 0016 — macOS egress proxy: enforce a general remote-host `net` allow-list behind the loopback kernel fence

- Status: Accepted (2026-06-30)
- Date: 2026-06-30
- Context: ADR 0015 proved SBPL cannot name a remote host (`(remote ip
  "1.2.3.4:443")` → compile error) and shipped the **loopback kernel fence** —
  `(deny network*)` + `(allow network* (remote ip "localhost:*"))` — for a
  loopback-only grant, leaving a general remote-host allow-list (`net:
  Only(["example.com"])`) honestly `net → advisory`. ADR 0015's named follow-up was
  a **local egress proxy**. This ADR ships it (#124).
- **Extends ADR 0015** (reuses its loopback fence verbatim) and is governed by
  ADR 0002 (the fence only ever *denies more*; `effective ⊑ granted` undisturbed —
  no new mint site) and ADR 0004 (per-axis honesty: report `kernel`/`interceptor`
  only for what is actually enforced there).
- Related: #124 (this axis), ADR 0015 (the fence + frontier), ADR 0008 (core
  leanness — no new core deps).

## Question

How does macOS enforce a **general remote-host** `net` allow-list for a *spawned
child*, given that SBPL cannot express it, and **without lying** in the honesty
report or bloating the lean `agent-bridle-core`?

## Decision

Kernel-fence the child's egress to loopback (the ADR 0015 rule) and route its
HTTP/HTTPS through a **loopback forward proxy** that enforces the hostname
allow-list. The child can reach *nothing* off-box directly; its only path off the
loopback interface is the proxy, and the proxy admits only allow-listed hosts.

### D1 — Two pure core predicates; the mechanism lives in the shell tool

`agent-bridle-core` gains two **pure, dependency-free** predicates (ADR 0008
leanness intact — no tokio, no networking in core):

- `net_egress_proxy_hosts(caveats) -> Option<Vec<String>>` — `Some(full host set)`
  iff `net` is `Only(set)`, non-empty, with **≥1 non-loopback host** (exactly the
  case ADR 0015 D3 leaves advisory); `None` for `All`/empty/loopback-only, which
  keep their existing owners.
- `loopback_fenced_caveats(caveats) -> Caveats` — `caveats` with `net` replaced by
  the loopback set, so its `seatbelt_profile` emits the ADR 0015 fence while the
  `fs`/`exec` rules are preserved verbatim.

The proxy itself is `agent-bridle-tool-shell/src/net_proxy.rs`, **std-only**
(`std::net` + `std::thread`, no async runtime, no new dependency). The shell's
`OsSpawner::run` routes on one helper, `egress_proxy_plan(caveats)`, which is
**self-gating**: it returns `Some` only where the loopback fence is actually
emittable (`intended_sandbox_kind(fenced) ≠ None` — today macOS + `macos-seatbelt`
+ `sandbox-exec`); everywhere else it is `None` and the ordinary paths run
unchanged (no regression, no surprise fail-closed). `run_with_egress_proxy` starts
the proxy, computes the fence prefix from the fenced caveats, and injects
`*_PROXY` (both cases) into a **clone** of the env-seam map so the child routes out.

### D2 — Honesty: the report is UNCHANGED; the proxy over-delivers

`enforcement_report` is **not touched** — a general remote-host `net` under
Seatbelt stays `net → Advisory`. No new `SandboxKind`, no new `AxisEnforcement`.
This is the honest floor, for three independent reasons:

1. **The pure report cannot know a proxy is engaged.** It is a function of
   `(caveats, SandboxKind)`; the same inputs occur with and without a proxy (e.g. a
   bare `ConfinedCommand`). It must report the value true in *all* states — the
   floor — or it would disagree with runtime (the "check and routing must agree"
   discipline already in `spawn.rs`).
2. **The kernel enforces the loopback *interface*, not the hostname.** Claiming
   `kernel`/`interceptor` for the *host* axis would overclaim: the host match is
   the userspace proxy, and `AxisEnforcement::Interceptor`'s contract explicitly
   excludes a spawned child's interior.
3. **Non-proxy-aware traffic is fenced, not filtered** (D4) — for it the host
   allow-list is genuinely only advisory.

The proxy is exactly the *"tool that gates net for its own requests and
over-delivers relative to the advisory floor — the safe direction"* that
`report.rs` already blesses. The **coarse** `sandbox_kind`, however, *is* reported
as `Seatbelt` on the proxy path (a real kernel boundary — the loopback fence, plus
any `fs`/`exec` rules — is in force); `invoke` derives it from the *same*
`egress_proxy_plan` helper the routing uses, so the reported kind and the applied
mechanism cannot diverge. A strong (`Kernel`-floor) principal still fails closed on
the advisory `net` — correct: the proxy is an over-delivery for the default
principal, not a kernel guarantee a strong principal may rely on.

### D3 — Lifecycle: RAII, fail-closed

`ProxyHandle` is a std RAII value: started before the confined child, held until
the child is reaped, then dropped — its `Drop` flips a shutdown flag and self-dials
the ephemeral loopback port to wake the blocking `accept()`. The port is
OS-picked (`127.0.0.1:0`), so concurrent runs never collide; no `/tmp` files, no
persistent listener. **Fail-closed:** if the proxy cannot bind, or the fence
wrapper is missing, the run is refused rather than spawning an unfenced child.

### D4 — Scope: `CONNECT` + `http://`; non-proxy-aware traffic fails closed

The proxy speaks HTTP `CONNECT` (HTTPS tunnelling — it never terminates TLS) and
`http://` absolute-form (rewritten to origin-form, then spliced). **Non-proxy-aware
traffic** (raw sockets, tools ignoring `*_PROXY`, custom protocols) is
kernel-fenced to loopback and therefore **blocked off-box** — fail-closed, the safe
direction; common agent tooling (curl/wget/git/python-requests/node) honours
`*_PROXY`.

## Bypass vectors and their disposition

| Vector | Disposition |
|---|---|
| Child opens a direct socket to a disallowed (or any off-box) host | **Closed** — kernel-denied at the socket by the loopback fence (proven: fenced `curl http://1.1.1.1/` exits 7). The proxy is *unbypassable*, not merely advisory. |
| Disallowed host via the proxy | **Closed** — the proxy 403s it and never dials an origin (proven on-host). |
| Non-proxy-aware / raw-TCP egress | **Fail-closed (deny-of-function)** — blocked off-box by the fence; only HTTP/HTTPS-proxy-aware clients reach allowed hosts (D4). |
| Hostname match subverted by compromising the parent | **Userspace risk (declared)** — the host match is the parent-side proxy, so it is reported `net → Advisory`, never `Kernel`. The loopback *interface* fence remains kernel-guaranteed regardless. |
| DNS: child resolves off-box directly | **Closed for the child** — its own `:53` egress is kernel-denied; proxied requests resolve in the **parent** proxy. The system-resolver (`mDNSResponder` over mach) covert channel from ADR 0015 is unchanged (pre-existing, declared). |
| DNS rebinding / IP churn | **Matched by name, not IP** — the proxy matches the CONNECT/URI host *string* against the allow-list, then resolves+dials, consistent with `check_net`'s exact-name semantics (ADR 0015 rejected IP-pinning as unsound). |
| `http://` domain-fronting — `GET http://allowed.com/` with a spoofed `Host: disallowed.com` to serve a disallowed vhost off shared/CDN infra | **Closed** — the `http://` path drops the client's `Host` and substitutes the proxy's own, derived from the **validated** authority, so the origin only ever sees the allow-listed host (proven: `http_host_header_is_normalized_to_the_validated_authority`). |
| CONNECT `allowed.com` then TLS-SNI `evil.com` | **Residual (hardening follow-up)** — the fence still prevents any egress except to the IP the proxy dialled for `allowed.com`; an SNI cross-check is a listed follow-up. |

## Consequences

**Positive**
- A general remote-host `net` allow-list is now **enforced** for a spawned child
  on macOS (was ambient): a disallowed host is refused and un-proxied egress is
  kernel-blocked. Closes the remaining #124 case for the shell tool.
- Core stays lean (two pure predicates, zero new deps); the report never overclaims
  (unchanged advisory floor); check and routing derive from one helper.

**Negative / risks**
- Coverage is **HTTP/HTTPS-proxy-aware only**; other protocols are fenced off-box
  (fail-closed deny-of-function), not host-filtered.
- Hostname matching is **userspace** (`net → Advisory`, not kernel) — honest, but a
  strong principal still fails closed on this axis.

## Options considered and rejected

- **SBPL host/IP filter** — refused by the platform (ADR 0015 Finding 1).
- **NetworkExtension content filter** — needs a signed system extension +
  entitlement + user approval + root; out of proportion for a `sandbox-exec`
  wrapper library.
- **A new `AxisEnforcement`/`SandboxKind` variant for "kernel-fenced proxy"** —
  rejected: it would make the *pure* report claim more than advisory even for a
  bare `ConfinedCommand` that runs no proxy (overclaim + report/runtime
  disagreement), and re-feed a stronger `net` into `fence_strength` /
  `confinement_unenforceable`, disturbing the fail-closed gate. Advisory + a
  coarse-`Seatbelt` kind is the honest encoding.
- **Proxy in `agent-bridle-core`** — rejected: puts a network server in the lean,
  publishable core (ADR 0008); the shell tool already owns the spawn/env-seam path.

## Follow-ups

- **Envelope disclosure**: an informational, non-lattice `net_proxy` field
  (`{engaged, allow_hosts, addr}`) on the result envelope so operators can *see* the
  over-delivery — kept OUT of `EnforcementReport` to preserve the honesty lattice.
- **`ConfinedCommand::spawn` integration** (core subprocess primitive) for
  MCP-server-style long-lived children — needs the handle tied to `ConfinedChild`'s
  drop rather than a bracketed call; the shell path is the immediate #124 win.
- **TLS SNI cross-check** (CONNECT host vs ClientHello SNI); SOCKS5 / websockets;
  per-host port policy; connection caps + metrics.
- **Linux equivalent** — blocked on a Linux kernel net-egress fence (the loopback
  primitive ADR 0015 gives on macOS does not yet exist on Linux); ADR 0015
  Follow-ups / #35.
