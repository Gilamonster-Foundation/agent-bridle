# ADR 0015 — macOS Seatbelt net axis: loopback kernel-confinement + the remote-host allow-list frontier

- Status: Accepted (2026-06-30)
- Date: 2026-06-30
- Context: The macOS `SeatbeltSandbox` (`sandbox.rs`, ADR 0006 / 0009) kernel-denies
  **all** egress when `net` is empty (`(deny network*)` → `net → Kernel`; #50
  follow-up / PR #96) and kernel-confines `fs` + `exec` (ADR 0014). But a
  **non-empty** `net` host allow-list (`net: Only([host])`) was left **ambient**
  and honestly reported `net → Advisory` — a caller granting a host allow-list got
  no kernel egress confinement for that axis (#124).
- **Extends ADR 0014** (the Seatbelt fs/exec axes) to the `net` axis, and is the
  network sibling of **ADR 0011** (the Linux exec frontier): both record a *hard
  platform limit* honestly rather than overclaim, ship the enforceable subset, and
  defer the general case to a second mechanism. **Governed by** ADR 0002 (the
  profile only ever *denies more*, so `effective ⊑ granted` holds — no new mint
  site, no new gate) and ADR 0004 (per-axis honesty: report `Kernel` only for what
  the kernel actually enforces).
- Related issues: **#124** (this axis), #104 (ADR 0014, the Seatbelt backend this
  extends), #50/#96 (the empty-net kernel case).

## Question

Can the macOS Seatbelt backend confine a **non-empty `net` host allow-list**
(`net: Only([host, …])`) at kernel grain — so `net → Kernel` is honest for
allow-list scopes, not only for deny-all — and if not fully, *how close does the
platform allow*?

## Empirical findings (macOS 15.x / Apple Silicon, verified on-host via `sandbox-exec`)

Encoded as the `BRIDLE_REQUIRE_SEATBELT` proof sweep in `sandbox.rs` so CI
re-verifies them on every change.

1. **SBPL cannot name an arbitrary remote host or IP.** A rule naming a concrete
   destination — `(allow network* (remote ip "1.1.1.1:443"))` — is a **profile
   compile error**: `sandbox-exec: host must be * or localhost in network
   address`. The `remote` node accepts only the special hosts `*` and `localhost`,
   plus a **port**. There is no hostname filter (DNS names are never matched) and
   no per-IP filter. This is the structural fact that makes a host allow-list
   inexpressible — the network analog of ADR 0011's `ld.so`-trampoline for exec.

2. **Port and socket-type filtering do work** (kernel grain): `(deny network*)`
   then `(allow network* (remote ip "*:443"))` permits `:443` and denies `:80`.
   But the `net` axis is **host**-granular (`check_net(host)`, exact-match), not
   port-granular, so a port filter does not map to the axis's meaning.

3. **`localhost` filtering works and denotes the loopback *interface*.** `(deny
   network*)` then `(allow network* (remote ip "localhost:*"))` permits egress to
   `127.0.0.1` **and** `::1`, and denies everything else — including `127.0.0.2`
   (so `localhost` ≠ all of `127.0.0.0/8`) and every off-box host. No
   `unix-socket` rule is needed for loopback TCP; `localhost` name resolution
   happens via `/etc/hosts` without egress.

4. **The empty-net deny-all case is unaffected** — `(deny network*)` still blocks
   loopback too, so it stays distinct from (and stricter than) the loopback case.

**Conclusion:** a *general* remote-host allow-list is **not** kernel-expressible in
pure SBPL (Finding 1). The one non-deny-all policy the kernel *can* enforce is
**confine egress to the loopback interface** (Finding 3).

## Decision

### D1 — Kernel-confine a loopback-only allow-list; report `net → Kernel`

When `net` is `Only(set)` with `set` non-empty and every host a loopback
identifier — `localhost`, `127.0.0.1`, `::1` ([`LOOPBACK_HOSTS`]) —
`seatbelt_profile` emits `(deny network*)` then `(allow network* (remote ip
"localhost:*"))`. The confined process's **own off-box socket egress is
kernel-denied** (`connect()`/`sendto()` to any non-loopback address fails at the
socket); `enforcement_report`'s Seatbelt `net` arm returns `Kernel`. This is the
common, security-relevant case — *"this agent may reach my local Ollama/DB but
cannot open a socket to phone home."* (The one residual off-box path — DNS via the
**system resolver daemon**, which runs outside the process sandbox — is a
pre-existing macOS limitation shared verbatim with the empty-net kernel case; see
the bypass table.) The wrapper engages on a loopback-only
`net` grant alone (it joins `restricts_fs` / `net_fully_denied` / `restricts_exec`
in `effective_sandbox_kind` and `command_prefix`), even with fs/exec unrestricted.

### D2 — The kernel confines the *interface*; admission refines the *host*

`(remote ip "localhost:*")` confines egress to the loopback interface as a whole
(`127.0.0.1` **and** `::1`) — the finest grain SBPL can name. This is coarser than
a grant of exactly one loopback address, and the split is subtler than the fs
axes': for fs, `(subpath <root>)` and admission's `check_path_*` enforce the
**same set** (the root and its descendants), so a spawned child gets exactly the
grant; for net loopback the kernel set `{127.0.0.1, ::1}` is **strictly broader**
than a single-address grant. A **spawned external child** makes its own syscalls
and is governed *only* by the kernel rule — never by the in-process
`ToolContext::check_net` (exact-match) — so under `net: Only([127.0.0.1])` that
child can also reach `::1`. This widening is **strictly within loopback** (the
same machine; no off-box egress), so the primary property is intact: *no egress
leaves the loopback interface, kernel-guaranteed*. `net → Kernel` therefore claims
the axis is kernel-confined **to the loopback interface**, never that the kernel
matches the exact host string — that per-address precision is admission's, and it
gates the engine's own operations, not a spawned child's. (To make admission and
kernel enforce the identical set, a future change could normalize the loopback
synonyms in `check_net`; deliberately out of scope here — it changes the
exact-match net leash for every backend, not just Seatbelt.)

### D3 — A general remote-host allow-list stays `Advisory` (honesty)

Any `net: Only(set)` with a non-loopback member (e.g. `example.com`, `127.0.0.2`,
a public IP) is **not** loopback-only. SBPL cannot name it (Finding 1), so the
profile emits **no** network rule — the axis is left ambient and reported
`Advisory`, never silently dropped and never overclaimed. A single non-loopback
host taints an otherwise-loopback set (the whole allow-list falls to advisory)
rather than emit a rule that would silently drop the remote entry.

### D4 — No change to the empty-net or the honesty oracle

`net: Only({})` (deny-all) keeps its `(deny network*)` / `net → Kernel` path,
mutually exclusive with D1. The `noop_host_never_reports_kernel` oracle and the
`effective ⊑ granted` law are undisturbed (the net rules only ever deny more).

## Bypass vectors and their disposition

| Vector | Disposition on macOS |
|---|---|
| Off-box `connect()` / `curl` to any remote host under a loopback grant | **Closed** — kernel-denied at the socket (Finding 3); curl exits 7. |
| Direct DNS egress (a process opening its own UDP/TCP :53 socket to a resolver) | **Closed** — `:53` egress is off-loopback, so kernel-denied at the socket (verified: `nslookup` → `bind: Operation not permitted`); `localhost` resolves via `/etc/hosts` with no egress. |
| DNS **exfiltration via the system resolver** (`getaddrinfo`/`dscacheutil` → `mDNSResponder` over mach; the daemon egresses the query) | **Not closed — declared, pre-existing.** `mDNSResponder` runs *outside* the process sandbox, so a query it forwards can carry data off-box (a low-bandwidth covert channel). This is **identical under the already-shipped empty-net `net → kernel` case** — not introduced here — and is why `net → Kernel` claims *the process's own socket egress* is kernel-confined, not that every covert channel is closed. A local egress proxy (which also owns DNS) is the path to close it (Follow-ups). |
| `127.0.0.2` / other `127/8` under a loopback grant | **Closed** — `localhost` is `127.0.0.1`+`::1` only (Finding 3); other `127/8` is kernel-denied. |
| Reaching a *different* loopback service (`::1` when only `127.0.0.1` granted) | **Kernel-permitted within loopback (declared, D2)** — the kernel confines to the loopback *interface* (`127.0.0.1`+`::1`); a spawned child, not gated by `check_net`, may reach either. Strictly on-box (no exfiltration); the engine's *own* ops are still narrowed to the exact host by admission. |
| Local IPC to an on-box service — `AF_UNIX` socket or a mach port (e.g. a running daemon that could relay off-box) | **Not closed — declared, pre-existing.** `(deny network*)` governs the process's own *network* egress; mach lookups are kept ambient (a normal process needs them) and `AF_UNIX`/mach are on-box IPC. Identical under the empty-net kernel case — not introduced here. Closing indirect relay is the local-egress-proxy's job (Follow-ups). |
| General remote host allow-list (`example.com`) | **Advisory (declared)** — inexpressible in SBPL (D3); enforced only by the application leash, honestly reported. A local egress proxy is the path to close it (Follow-ups). |
| No `sandbox-exec` (incapable host) | **Fails closed** — `command_prefix` returns `Err`, never an unconfined prefix. |

## Consequences

**Positive**
- A loopback-only `net` grant is now **kernel-confined**: the process's own off-box
  socket egress is kernel-denied, honestly reported `net → Kernel` (modulo the
  shared system-resolver residual). Closes the loopback slice of #124.
- The kernel primitive shipped here — *confine egress to loopback* — is exactly
  what a future local egress proxy pins the child to, so this is also the
  foundation for closing the general remote-host case.

**Negative / risks**
- **A general remote-host allow-list is still `Advisory` on macOS.** #124 is only
  *partly* closed: hostname allow-lists are enforced solely by the in-process leash
  until an egress proxy lands. This is declared, not hidden.
- `localhost` is the loopback *interface* (v4 + v6), coarser than a single-address
  grant (D2) — the exact address is an admission-grain, not a kernel-grain, claim.

## Options considered and rejected

- **SBPL `(remote ip "<host>:<port>")` host/IP filters** — rejected: **empirically
  refused** ("host must be * or localhost", Finding 1). Resolving hostnames to IPs
  at profile-build time and pinning those IPs was also rejected: it is unsound
  (DNS rebinding / CDN IP churn → both a leak *and* a deny-of-function) and SBPL
  rejects the IP literal anyway.
- **A NetworkExtension content-filter** — rejected for this increment: requires a
  signed **system extension** with a restricted entitlement, user approval, and
  root install — impractical for a `sandbox-exec`-wrapper library and out of
  proportion to the axis.
- **A local egress proxy the profile pins to** — the *correct* path for the general
  remote-host case, but deferred: it is a separate mechanism (a proxy process,
  child `*_PROXY` env wiring via the env seam, CONNECT/SNI host filtering) whose
  host filtering is **userspace** (proxy-grain), so it would report the host axis
  as `Interceptor` behind a kernel *loopback* guarantee — a larger, honestly
  different posture. Recorded as a follow-up; this ADR ships the kernel loopback
  primitive it depends on.

## Follow-ups

- **#124** — the general remote-host allow-list: closed here for the **loopback**
  case; the local-egress-proxy mechanism (kernel-pin egress to a loopback proxy
  that enforces the hostname allow-list) remains, to report the host axis honestly
  as proxy-enforced behind the kernel loopback fence.
- Landlock/Linux net axis is still ungated (advisory) — a separate frontier.
