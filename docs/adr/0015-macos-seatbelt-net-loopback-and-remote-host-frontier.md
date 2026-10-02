# ADR 0015 — macOS Seatbelt net axis: loopback kernel-confinement + the remote-host allow-list frontier

- Status: **Partially superseded (2026-08-11); amended E5 (2026-09-28), E6 (2026-09-29)** — the
  SBPL direct-socket findings remain valid, but every claim below that a
  restricted Seatbelt net scope is a complete `Kernel` witness or is admissible
  is superseded by the E4 ruling in this document. The E4 ambient Mach
  re-allow list is replaced by the zero floor + named operator grants of
  amendment E5 (agent-bridle#405).
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

## Superseding E4 ruling (2026-08-11)

The original decision measured the child's own network syscalls. It did not
model ambient Mach/XPC services that can perform network work outside the
sandbox on the child's behalf. Native characterization has since demonstrated
one such path: a background `URLSession` can delegate a transfer to
`com.apple.nsurlsessiond` even while the child is under `(deny network*)`.

The E4 profile adds a default-deny Mach-lookup floor and excludes that service.
Native evidence establishes the narrow result that this demonstrated deputy is
closed. It does **not** establish deputy-complete no-egress: the profile
re-allows a minimal set of Mach services needed for usable processes, and
neither those services nor every other ambient IPC route have been
comprehensively certified against child-controlled egress.

Therefore the operative authority ruling is fail-closed:

- `SeatbeltSandbox::resolved_authority().net` is `Unknown` for **every**
  restricted net scope, including `net:none` and every loopback shape.
- Admission refuses those scopes. The emitted SBPL direct-network and Mach rules
  are defense in depth only; they are not a support or `Kernel`-witness
  promotion.
- The loopback egress-proxy design from ADR 0016 is held/unavailable on macOS
  until a deputy-complete native proof supports a faithful projection.

The remainder of this ADR records the 2026-06 direct-socket findings and the
superseded decision for history. Where it says a restricted net shape is
`Kernel`, exact, admitted, or supported, this 2026-08-11 ruling controls.

## Amendment E5 — zero Mach floor, services are operator grants (2026-09-28, agent-bridle#405)

The E4 profile default-denied Mach lookup and then re-allowed twelve services
ambiently so ordinary tools kept working. None of those services had native
evidence that it cannot act as a network deputy for the child, so the ambient
re-allow was an unproven floor. This amendment removes it.

**Decision.** Nothing ambient. Under a network-denied Seatbelt profile
(`net:none`, or `unix:`/`mach:` entries only) the Mach-lookup floor is
**zero**: `(deny mach-lookup)` with no default re-allow. A service is reachable
only when the operator grants it by name with a `net` scope entry
`mach:<global-name>` (for example `mach:com.apple.system.opendirectoryd.libinfo`),
which the profile re-allows as an exact `(global-name …)` literal after the
deny. The grant is an ordinary scope entry: narrowed by `meet`, validated
(launchd label characters only, fail-closed), Seatbelt-only (AppContainer
refuses it; the egress proxy never treats it as a host).

**Resolution.** A grant is projected as the named class
`seatbelt-mach-service:<name>`, following the `appcontainer-loopback-exemption`
precedent, so it never collapses to `∅`; the Seatbelt runtime closure declares
exactly that class per grant, so admission compares it as a `Subset` rather
than an undeclared widening. The projection is implemented and pinned by unit
test for the post-audit state, but **this build ships
`MACH_DEPUTY_AUDIT = Incomplete`**, under which every restricted net shape
still resolves `Unknown` and is refused (fail closed first, #405 D4). The
constant switches **only the authority projection** (the L3 scope bound). It
does not change the per-axis strength report (every restricted Seatbelt net
shape stays Advisory) or the L4 strength floor, so flipping it alone does not
admit `net:none` under a CONFINED contract. Report/floor integration, the
end-to-end admission tests, and the native deputy evidence that would justify
the flip all belong to a later, evidence-backed promotion PR. Loopback and
remote-host shapes stay `Unknown` in either state.

A `mach:` grant alongside a remote-host allow-list has no egress-proxy
semantics (the proxy's loopback fence installs no Mach floor, so the grant
would be erased rather than confined); the proxy planner refuses such a scope
on every backend.

**Denial report.** The kernel denies a Mach lookup silently, so bridle derives
the structured result from the installed policy: the envelope's
`disclosure.mach_services` lists `granted` (by name) and `withheld` (every
known candidate the profile denies). The host owns the prompt ("allow for this
session" vs. "allow permanently"); bridle owns the token, the resolution and the
report.

**Native evidence (macOS 26.6.2 / Darwin 25.6.0 arm64, `sandbox-exec`).**
Per-service deputy status: **unknown for every candidate** — no candidate has
been shown incapable of egress on the child's behalf, which is exactly why the
floor is zero. Breakage measurement under the zero floor, then per single
grant (evidence table in `docs/security/platform/macos-evidence.md`):

| tool / operation | zero floor | needs |
|---|---|---|
| `/bin/sh`, `/bin/echo`, `/usr/bin/xcrun --find` | runs | — |
| `git add/commit/log/status` with a configured identity | runs | — |
| `git commit` **without** a configured identity (`getpwuid`) | "Author identity unknown" | `com.apple.system.opendirectoryd.libinfo` |
| `id -un` (uid → name) | prints the numeric uid | `com.apple.system.opendirectoryd.libinfo` |
| `cargo --version` | runs | — |
| `python3` (`ssl.create_default_context()` loads 128 CA certs) | runs | — |
| `curl https://127.0.0.1:…` (TLS stack loads; socket denied as intended) | connect refused by `(deny network*)` | — |
| `getaddrinfo("example.com")` via the system resolver | fails (no `mDNSResponder` lookup) | *not a candidate* — DNS exfil via the resolver daemon is now closed under `net:none` |
| `security find-certificate` (keychain) | fails | `com.apple.SecurityServer` |

The `id -un` differential is encoded as the CI proof
`net_none_mach_floor_is_zero_and_a_named_grant_reopens_that_service`: a
validated numeric-uid control (success, non-empty ASCII decimal) and a name
control distinct from it; the zero floor yields the exact uid; a grant of
`libinfo` exits successfully with the name; an unrelated `SecurityServer`
grant yields the uid again; each confined profile has its own launch control.
This measures the `libinfo` grant and the literal rule it emits; it does not
characterize any other service's transitive authority.
The E4 A/B/A differential still passes under the zero floor (the production
leg exits via `callback_error`).

**Out of scope here.** Windows AppContainer (the brokered-RPC/COM/named-pipe
audit, #405 A/Windows) is a separate delegate on native Windows; host
allow-lists (#124 frontier) stay `Unknown`.

## Amendment E6 — the non-Mach-lookup ambient IPC audit (2026-09-29, agent-bridle#405)

E5 closed *named* Mach lookups. This amendment characterizes the other ambient
IPC paths ADR 0015/#405 named as candidates — everything a `net: none`,
zero-`mach:`-grant Seatbelt child might reach that is **not** gated by
`(deny mach-lookup)` at all — to determine whether the deny-all, zero-grant
shape can honestly promote to a `net → Kernel` witness.

**Method.** Each row is a differential (ADR 0015 / #361): the same probe
unconfined (positive control) vs. under exactly
`(version 1)(allow default)(deny network*)(deny mach-lookup)` with zero
grants — i.e. `net: none` used alone, independent of the (separately
governed) `fs`/`exec` axes. Every probe target was a loopback listener or
local resource this session owned; no external host was contacted.
Native evidence: macOS 15.7.3 (24G419), Darwin, arm64.

| Channel | Result | Evidence |
| --- | --- | --- |
| Unix-domain socket connect (`AF_UNIX`) | **CLOSED** | Unconfined `nc -U` to an owned `nc -lU` listener connects and delivers a byte. Confined (same profile): connect fails (exit 1), listener sees nothing. `(deny network*)` covers `AF_UNIX` connect, the same rule the `unix_sockets` grant mechanism re-allows exactly by path. |
| `open(1)` / LaunchServices (activate another app) | **CLOSED** | Unconfined `open -g -a Safari http://127.0.0.1:PORT/…` reaches an owned loopback HTTP listener. Confined: `open` fails immediately — `Unable to find application named 'Safari'` — listener sees nothing. Routes through `com.apple.coreservices.launchservicesd`, already denied by the E5 zero floor (`MACH_SERVICE_CANDIDATES`); closes for the same reason, not a new mechanism. |
| Darwin notifications (`notify_post`, e.g. `notifyutil -p`) | **CLOSED** | Unconfined `notifyutil -p` succeeds (exit 0). Confined: `Failed with code 9`. Requires a mach lookup to `com.apple.system.notification_center` (already in `MACH_SERVICE_CANDIDATES`); closed by the same zero floor. |
| Pasteboard (`pbcopy`/`pbpaste`) | **CLOSED** | Unconfined round-trips a probe string. Confined: `pbpaste` prints nothing, exit 1. Reached via `mach-lookup` to `com.apple.pasteboard.*` — not itself on `MACH_SERVICE_CANDIDATES`, which demonstrates the deny is a genuine blanket default (unlisted services are exactly as denied as listed ones; the candidate list is documentation of what a host may grant, never a baked-in partial allow). |
| Bootstrap lookup by any name outside `MACH_SERVICE_CANDIDATES` | **CLOSED (structural)** | `(deny mach-lookup)` has no default re-allow in the emitted profile; the only re-allow is the operator's `mach:` grants. An unlisted service name is denied identically to a listed one — the pasteboard row is itself an example, so this needed no separate probe. |
| `system-socket` (`PF_SYSTEM`/`AF_SYSTEM` kernel control sockets, e.g. `utun_control`) | **REACHABLE, no viable egress found** | A small C probe: `socket(PF_ROUTE, …)`, `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, `shm_open`, `sem_open` all **succeed identically confined and unconfined** — `system-socket` (and `ipc-posix-shm`/`ipc-posix-sem`) are not gated by this profile at all. Follow-up: actually creating a `utun` tunnel interface (`CTLIOCGINFO` + `connect()` to `com.apple.net.utun_control`) — the one PF_SYSTEM use that could carry raw IP traffic below the BSD socket layer `(deny network*)` governs — fails with `EPERM` **both confined and unconfined**: unprivileged utun creation is refused by the OS itself (entitlement/root-gated), independent of Seatbelt. No SBPL rule is needed for this shape; the residual is OS privilege separation, not something the profile has to add. |
| `AF_ROUTE` (routing-table socket) | **REACHABLE, read-only relevance** | Same probe: `socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)` succeeds confined and unconfined. This is a local routing-table read/notify channel (what `netstat -r`/`route get` use); it carries no egress by itself, and writing a route (`RTM_ADD`) is itself root-gated on macOS independent of Seatbelt. Not closed by this profile, but not a network-egress deputy either. |
| `ipc-posix-shm` / `ipc-posix-sem` (POSIX shared memory / semaphores) | **REACHABLE, no ambient relay found** | Same probe: `shm_open`/`sem_open` succeed confined and unconfined. Local, in-machine IPC only — a relay to egress would require ANOTHER process already reading the confined child's segment, which is a colluding-process scenario (like `mach-register`, below), not an ambient system-service deputy. Out of this audit's threat model; not independently pursued further. |
| `iokit-open` to a network-related user client | **NOT MEASURED — reasoned, not tested** | Not independently probed. The one concrete escalation this audit found worth checking (`utun` via `PF_SYSTEM`, above) turned out to be OS-privilege-gated regardless of Seatbelt; a network-capable IOKit user client (raw interface access below BSD sockets) would need the same class of entitlement/root gate Apple applies to `utun` and to most other IOKit user-client `IOServiceOpen` calls on a non-rootless-disabled system. This is a **believed**, not measured, claim — flagged here rather than silently assumed, and worth one probe (`IOServiceOpen` on a real network nub) before this row can move to CLOSED. |
| AppleEvents / `osascript` targeting another app | **BLOCKED — not measured, TCC-gated** | `osascript -e 'tell application "Finder" to get name of startup disk'` hung indefinitely, both unconfined and confined, when run over an interactive ssh session. Root cause, confirmed via the user TCC database: the `sshd` binary itself has an ambiguous/denied `kTCCServiceAppleEvents` entry, and with no one physically present to answer a consent dialog the AppleEvent send blocks rather than failing. A GUI-domain `launchctl bootstrap` LaunchAgent (run as the logged-in user, `gui/$(id -u)`) hit the same block — the window-server session exists (`who` shows an active console login, `Finder` has been running since the last login) but TCC consent still requires a live interactive approval this lane cannot grant over ssh, and no sudo/TCC-database edit is permitted. **A self-contained script is checked in** at `~/workspaces/.handoff/helper-jobs/mac-netnone/probe-appleevents.sh` for an operator to run once, interactively, from Terminal.app on the Mac mini (approving the automation prompt) — its output (`/tmp/appleevents-probe.out`) is the missing measurement. |
| Mach service *registration* (`mach-register`) by the confined child | **OUT OF THREAT MODEL** | #405's question is whether the confined child itself can cause egress. A child registering a service only matters if ANOTHER process — necessarily itself already unconfined and network-capable — chooses to call into it; the confined child gained no new authority by publishing. This is a colluding-process scenario, not an ambient system-service deputy, and is out of scope for the same reason `ipc-posix-shm`/`sem` relay is. |

**Residual declared, not closed, out of this axis's scope.** File-drop into a
directory a system daemon watches (a `LaunchAgents` plist, a Mail/CUPS spool)
is not gated by this profile at all — `net: none` alone leaves `fs_write` at
its own, independent default (`(allow default)` unless the caller separately
restricts `fs_write`). This is real but belongs to the `fs_write` axis's own
honesty, not a hidden `net` leak: a caller combining `net: none` with an
ambient `fs_write` scope has this residual today regardless of this
amendment, and will continue to after it, because the two axes are — and
should stay — independently scoped.

**Promotion condition.** `net: none` (or any `net_direct_denied` shape) with
**zero `mach:` grants** may resolve `Bounded(∅)` at `Kernel` strength once (a)
the AppleEvents row above closes (or is shown to need its own SBPL rule) and
(b) `MACH_DEPUTY_AUDIT` (`agent-bridle-core/src/sandbox.rs`) is flipped to
`Complete` — the flip is a separate, later commit, reviewable on its own,
per the design review for this amendment. `seatbelt_net_kernel_witness` and
the `enforcement_report` Seatbelt arm that consumes it are implemented and
tested ahead of that flip (this amendment's PR); the flip itself is
**not** included here. Named `mach:` grants, loopback shapes, and
remote-host allow-lists are unaffected by this amendment and stay
`Unknown`/`Advisory` — this audit covers only the deny-all, zero-grant
shape.

**Out of scope here.** Windows (a separate native delegate, #405 A/Windows);
per-`mach:`-grant service audits (`trustd.agent`, `opendirectoryd.*`, etc.,
each independently `Unknown` until characterized); the `fs_write`-mediated
file-drop residual (declared above, belongs to that axis).

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

### D1 — SUPERSEDED: kernel-confine a loopback-only allow-list; report `net → Kernel`

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

### D2 — SUPERSEDED: the kernel confines the *interface*; admission refines the *host*

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

### D3 — SUPERSEDED: a general remote-host allow-list stays `Advisory` (honesty)

Any `net: Only(set)` with a non-loopback member (e.g. `example.com`, `127.0.0.2`,
a public IP) is **not** loopback-only. SBPL cannot name it (Finding 1), so the
profile emits **no** network rule — the axis is left ambient and reported
`Advisory`, never silently dropped and never overclaimed. A single non-loopback
host taints an otherwise-loopback set (the whole allow-list falls to advisory)
rather than emit a rule that would silently drop the remote entry.

### D4 — SUPERSEDED: no change to the empty-net or the honesty oracle

`net: Only({})` (deny-all) keeps its `(deny network*)` / `net → Kernel` path,
mutually exclusive with D1. The `noop_host_never_reports_kernel` oracle and the
`effective ⊑ granted` law are undisturbed (the net rules only ever deny more).

## Bypass vectors and their disposition

> Historical direct-socket analysis. The table does not establish
> deputy-complete authority and must not be used to admit a restricted macOS net
> scope; the superseding E4 ruling above requires `Unknown → refuse`.

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

The consequences below describe the superseded 2026-06 support decision. The
direct-socket primitive remains available as defense in depth, but the current
admission outcome for every restricted Seatbelt net scope is refusal.

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
