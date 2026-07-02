# ADR 0009 — Cross-platform confinement strategy (the L3 boundary across Windows, Linux, macOS)

- Status: Accepted (2026-06-29)
- Date: 2026-06-29
- Context: ADR 0006 established per-OS L3 backends behind `best_available_sandbox()` /
  `SandboxKind`, with the Landlock backend as the template. agent-bridle ships as a unified
  Rust library (core + tool crates + the PyO3 bindings) meant to run natively on Windows,
  Linux, and macOS. The exec-axis frontier is open (#57: Landlock cannot soundly confine
  `exec`). The workload it confines is an **LLM command stream driving native toolchains**
  (`cargo`, `git`, `python`, `curl`) — heavy `fs`/`net`/`exec` I/O, not bytecode.
- **Extends ADR 0006** (the per-OS seam) by deciding the full cross-platform strategy and
  recording the options weighed and rejected.
- Related issues: **#78** (Tier 1 — the portable baseline), #50 (Seatbelt), #51 (Windows —
  re-scoped by D4), #57 (exec held), #35 (Linux netns/seccomp variant), #58 (command packs).

## Question

gVisor and Linux microVMs (Firecracker/Kata) are the obvious "strong sandbox" answers — but
both are bound to the Linux kernel (gVisor's Sentry emulates the Linux syscall surface;
Firecracker/Kata require KVM). A single Windows+Linux+macOS binary cannot use either off
Linux. **What confinement strategy gives a cross-platform L3 boundary for arbitrary native
subprocesses — without overclaiming, and without bloating the publishable default?**

## Decision

A **three-tier strategy**, every tier behind the ADR 0006 seam (one cargo feature, one
selector arm in `best_available_sandbox()`, one `SandboxKind` variant, a fail-closed
`apply()`, and an honest `None` fallback). The **Caveats are the config source** for every
tier (granted roots → mounts/rules; `net` scope → net policy; `exec` → the visible-binary
set). Tiers **compose with the in-process meet-attenuation**: each confined unit gets its own
jail derived from its already-attenuated caveats.

### D1 — Tier 1: native OS process sandboxing (the portable baseline)

Per-OS native primitives behind the one `Sandbox` trait:
- **Linux** — seccomp + namespaces + Landlock (fs landed; net/exec under #35/#57).
- **macOS** — Seatbelt (`sandbox_init`) — #50.
- **Windows** — **AppContainer (capability SIDs)** — #51, re-scoped (D4).

Lightweight, no external runtime, available on a stock host. This is the default confinement
tier. Tracked by **#78**.

### D2 — Tier 2: per-host micro-VM (the strong tier, opt-in)

A hardware-virtualized VM with a **uniform minimal Linux guest**, via a Rust-embeddable VMM
that swaps the host backend: **KVM (Linux), Hypervisor.framework (macOS), WHP/Hyper-V
(Windows)** — Cloud Hypervisor is the candidate. The guest is identical across hosts, so the
**Caveats→guest mapping is written once**; only the launcher differs. This is where `exec`
and `net` become **soundly** confined (the #57 frontier — un-granted binaries simply aren't
in the guest rootfs). Warm-pooled with an in-guest vsock broker (the airship model) to
amortize boot. Requires hardware virtualization → **honest `None` fallback** when
`/dev/kvm`/HVF/WHP is unavailable (common in CI / nested virt).

### D3 — Tier 3: Wasm plugin sandbox (orthogonal — for code we compile)

An embedded Wasm runtime (Wasmtime) for agent-bridle's **own tools/plugins authored as Wasm
modules**, with capability-passed I/O. This is the **OCAP-purest model** (the guest gets
nothing unless the host passes a handle) — but it confines **bytecode, not native
subprocesses**, so it is **not** the exec-axis answer (see Rejected). Adjacent to command
packs (#58).

### D4 — Windows targets AppContainer, not job objects

#51 is re-scoped from "job object / restricted token" to **AppContainer**: AppContainer is
itself capability-based (deny-by-default + explicit capability SIDs), which maps onto the OCAP
lattice far more cleanly than coarse job-object resource limits. Low-Integrity is the fallback
for older hosts; job objects may layer on as a resource backstop, but are not the
fs/net/exec boundary. (This is the Chromium-tab-sandbox model.)

### D5 — Honest `SandboxKind` per tier; never overclaim

Each backend adds a `SandboxKind` variant (`Seatbelt`, `AppContainer`, `MicroVm`, …); the
result envelope reports the boundary actually in force; `apply()` fails closed. (ADR 0006
D3/D4, extended across tiers, and surfaced at axis grain by ADR 0004 D1 / #30.)

### D6 — Windows AppContainer: axis coverage, kernel proofs, and accepted limitations (as implemented)

The Tier-1 Windows backend is complete. What it enforces, honestly reports, and deliberately
does **not** attempt:

**Kernel-enforced (reported `Kernel`), with real spawn proofs.** Proven by
`agent-bridle-aclaunch/tests/{kernel,net}_proofs.rs`, which launch a confined child and assert
the kernel — not the launcher logic — blocks out-of-scope operations (the Windows analog of
Linux `landlock_kernel_tests` / macOS `seatbelt_kernel_tests`):

- **`fs_read` / `fs_write`** — per-path DACL ACEs for the AppContainer SID over the
  container's default deny-of-user-directories (#51).
- **`exec` deny-all** — `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` blocks all child-process
  creation (#123).
- **`net` deny-all and loopback-only** — the capability-SID model (no `INTERNET_CLIENT`)
  kernel-denies off-box egress; `NetworkIsolationSetAppContainerConfig` grants the loopback
  exemption the egress proxy rides (#133, ADR 0016).

The proofs are hard-required in CI (`check-windows` + `nightly-windows`) via
`BRIDLE_REQUIRE_APPCONTAINER` — the Windows analog of #74's `BRIDLE_REQUIRE_LANDLOCK/SEATBELT`,
so a green build must have exercised the real boundary.

**Honestly reported weaker (no overclaim).**

- **`exec` allow-list → `Interceptor`.** A non-empty allow-list cannot be kernel-expressed
  without **WDAC** (Windows Defender Application Control) — a privileged, code-signed, policy-
  managed subsystem outside the scope of an in-process library. The in-process leash checks it;
  the report never claims `Kernel`.
- **general remote-host `net` allow-list → `Advisory`.** Enforced by the loopback egress proxy
  over the AppContainer no-internet floor (ADR 0016), which *over-delivers* above an advisory
  floor rather than raising the honest kernel claim.

**Accepted non-goals (intentional, not omissions).**

- **WDAC-based `exec` allow-list** — heavyweight infra; `Interceptor` is the honest fallback.
- **Registry / named-pipe isolation** — not among the four OS-confinement axes (fs_read/write,
  exec, net); AppContainer offers no kernel API to confine registry, and these channels are
  governed *indirectly* (fs_write confinement stops writing secrets to `%APPDATA%`; local IPC
  over sockets is gated by the net axis).
- **Job Objects (memory / CPU / process-count)** — resource limits, not a capability boundary
  (D4); may layer on later as an optional resource backstop, but orthogonal to the OCAP axes.
- **LPAC / named-object (Desktop, WindowStation) isolation** — optional hardening beyond the
  four axes; the DACL + capability-SID boundary already enforces the core contract.

## Consequences

- Tier 1 is the portable baseline; Tier 2 the strong opt-in (virt-gated); Tier 3 a separate
  plugin track. All are opt-in cargo features — the **default build stays lean and
  publishable**.
- Spawns: an **AppContainer** backend (#51 re-scoped), a **Cloud-Hypervisor micro-VM spike**
  (Tier 2), and a **Wasm-plugin track** (Tier 3, after the engine seam stabilizes).
- `exec`/`net` get a real cross-platform home (Tier 2) beyond Landlock's fs-only soundness.
- More backends = more CI matrix surface; each must assert that its reported `SandboxKind`
  matches the host's true capability (ADR 0004 D1 / #30).

## Options considered and rejected

### gVisor (runsc) as the cross-platform boundary — REJECTED (kept as an optional Linux tier)
A userspace kernel (Sentry) that traps and re-serves Linux syscalls (fs via gofer, net via
netstack). It *would* close the exec hole (a restricted mount makes un-granted binaries
invisible). Rejected as the **cross-platform** answer because it is **Linux-host only** —
Sentry emulates the *Linux* syscall surface and cannot intercept Windows (NTDLL) or macOS
(Mach) syscalls — and it is a Go binary (OCI shell-out), not Rust-embeddable. Not discarded
entirely: it remains a viable **stronger Linux backend** (an optional `linux-gvisor`
`SandboxKind`) if we want sound Linux `exec` without a full VM. It is simply not the
portability story.

### Firecracker / Kata Containers (Linux microVM) — REJECTED as portable
The canonical strong microVM. Rejected cross-platform because both bind directly to **Linux
KVM**, which does not exist on Windows or macOS. The microVM *pattern* survives in Tier 2 —
but via a host-swapping VMM (Cloud Hypervisor over KVM/HVF/WHP), not Firecracker specifically.

### WebAssembly + WASI as the exec-axis sandbox — REJECTED (wrong layer)
The most OCAP-pure model and tempting as "the ultimate cross-platform sandbox." Rejected for
the **core** job because agent-bridle confines arbitrary **native subprocesses**
(`cargo`/`git`/CPython/`curl`), not bytecode. You cannot run a native toolchain inside
Wasmtime; you would need the *entire toolchain* recompiled to Wasm plus a mature WASI
process/fs/net surface (which does not exist). The confined workloads are disk/net/exec-heavy
real tools — exactly what Wasm cannot host. Wasm is therefore demoted to **Tier 3** (confining
code *we* compile — plugins), never the exec axis.

### A single portable confinement primitive — REJECTED (does not exist)
The ideal would be one mechanism that confines native processes identically on all three OSes.
None exists: native isolation is irreducibly OS-specific (seccomp/Landlock vs Seatbelt vs
AppContainer/Hyper-V). The closest to "uniform" is Tier 2's micro-VM (uniform guest, per-host
VMM) — which is *why* it is the strong tier — yet even it needs a per-host VMM plus hardware
virt. We accept per-OS Tier-1 backends behind one trait rather than chase a non-existent
universal primitive.

### Windows job objects / restricted tokens (the original #51 scope) — REJECTED for AppContainer
Job objects cap resources (memory, CPU, process count) and restricted tokens are coarse;
neither is a capability boundary. AppContainer (capability SIDs, deny-by-default) is the
capability-shaped Windows primitive and the right OCAP target (D4).

### `gaol` (servo/gaol) as a dependency — REJECTED as a dep, kept as a reference
A Rust crate abstracting seccomp (Linux) + Seatbelt (macOS) behind one API — a useful
reference for the Tier-1 trait shape. Rejected as a dependency: **no Windows backend** and
largely **dormant**. We take the API lessons, not the crate.

### Always-on OS sandbox (no opt-in feature) — REJECTED
Same reason ADR 0006 rejected it: it forces every embedder to carry every backend's dependency
and removes the honest-advisory fallback. Confinement stays opt-in; the default build stays
lean and publishable.

### Drawbridge / Enarx-style TEE confinement — REJECTED (out of scope)
Hardware-TEE (SGX/SEV) confinement was considered for the strong tier. Rejected: it targets
*confidentiality from the host*, not *containing a workload's effects on the host* (our
threat model), needs specific CPU features, and has no uniform desktop story across Win/Lin/
mac. Tier 2's micro-VM gives the isolation we need without the TEE constraints.

## Threat-model note

The principal being confined is a **semi-trusted-to-untrusted agent's chosen command stream**
(an LLM selects the commands; prompt injection / confusion can make that stream hostile). The
goal is to **contain effects on the host** (least authority over fs/net/exec), not
confidentiality from the host. That framing is why native process sandboxing (Tier 1) and
micro-VMs (Tier 2) — both effect-containment boundaries — are the answer, and why TEEs
(confidentiality boundaries) are out of scope.

## Follow-ups (tracking issues)

- **#78** — Tier 1 native OS process sandboxing (the portable baseline; D1).
- **#35** — Linux Tier-1 `net`/`exec` (netns/seccomp) + the Linux-only publishable variant.
- **#57** — the held Linux `exec` frontier; soundly closed by Tier 2 (D2) or a namespace/seccomp broker.
- **#50** — macOS Seatbelt backend (D1).
- **#51** — Windows AppContainer backend (D1/D4).
