# ADR 0006 — Per-OS L3 sandbox backends, and engines as opt-in cargo features

- Status: Accepted (2026-06-25)
- Context: `agent-bridle-core` `Sandbox` trait + `best_available_sandbox()` +
  `SandboxKind` (the L3 seam); `agent-bridle-tool-shell` (the argv + safe-subset
  engine); the facade `agent-bridle` feature graph; `brush-bridle-core` (the
  deferred full-bash engine).
- **Extends ADR 0005** (which made L3 the boundary and L2 the convenience, and
  introduced the pluggable engine seam) by deciding *how* the L3 boundary is
  selected per operating system, and *how* an alternative engine (brush) is
  toggled — both as cargo features, with the choice resolved in code, not in the
  feature graph.
- Related issues: L3 axes/variant **#31** (net/exec backstops) and **#35**
  (Linux Landlock variant); macOS **#50** (Seatbelt) and Windows **#51**
  backends; optional brush engine **#20** / **#28**; honesty refinement **#30**.

## Question

ADR 0005 says "L3 is the boundary." But L3 is OS-specific — Landlock on Linux,
Seatbelt on macOS, job objects on Windows — and **cargo features cannot be
`cfg(target_os)`-conditional**. How do we let one codebase carry every backend,
build cleanly on every OS, pick the right one at runtime, and never overclaim
confinement it does not have? And how does the brush engine become an opt-in
alternative without making the default build depend on a fork?

## Decision

### D1 — One cargo feature per L3 backend, inert off its OS

The Landlock wiring is the template and generalizes:

- `linux-landlock` (exists), `macos-seatbelt` (#50), `windows-appcontainer` (#51),
  and a Linux `netns`/`seccomp` feature for the net/exec axes (#31).
- Each backend's OS-specific dependency lives under
  `[target.'cfg(target_os = "X")'.dependencies]` and is `optional = true`, gated
  by its feature. **Consequence:** enabling `macos-seatbelt` on Linux pulls and
  compiles *nothing* — the feature is a no-op off its target OS. (Landlock
  already does exactly this with the `landlock` crate.)

### D2 — Selection happens in code, not in the feature graph

Because a feature can't be made OS-conditional, **do not try to build one toggle
that "knows" the OS.** Instead:

- An embedder (or CI matrix) may safely enable **all** backend features in one
  build — `--features linux-landlock,macos-seatbelt,windows-appcontainer` — since
  each is inert except on its target. A facade meta-feature
  `os-sandbox = ["linux-landlock", "macos-seatbelt", "windows-appcontainer"]` is the
  one-knob convenience.
- `best_available_sandbox()` is the selector: one `cfg(all(target_os = "X",
  feature = "Y"))` arm per backend, each returning that backend's `Sandbox` (with
  a runtime capability probe — e.g. `landlock_is_supported()` — and falling back
  to `NoopSandbox`), and a final `NoopSandbox` default. A build only *compiles*
  the backends matching its OS+features, and a run always falls back to honest
  Noop.

### D3 — `SandboxKind` gains a variant per backend; never overclaim (I9)

`SandboxKind` carries a variant per real backend (`Landlock`, `Seatbelt`,
`JobObject`, …) plus `None`. The result envelope reports the variant actually in
force, so a macOS build with no Seatbelt yet honestly reports `None` rather than
implying confinement. This is ADR 0002 **I9** at backend granularity; ADR 0004
**D1 / #30** is the further refinement to per-*axis* honesty.

### D4 — `apply()` is fail-closed; the reported kind reflects reality

A backend's `apply()` MUST fail closed: if the kernel/OS does not actually
enforce the requested ruleset, it returns `Err` and the run fails rather than
proceeding unconfined. Combined with D3, this keeps the reported `SandboxKind`
honest: either the boundary is enforced (and reported) or the run errors — never
"reported confined but wasn't."

### D5 — Engines (incl. brush) are opt-in cargo features behind the ADR 0005 seam

- The **safe-subset engine is the default** (`shell` feature) — publishable, no
  git/fork dependency.
- **brush** is an opt-in `brush` feature on `agent-bridle-tool-shell` that depends
  on the published renamed fork `brush-bridle-core` and **swaps the engine** (both
  honor the same `Tool`/`Caveats`/result-envelope contract and the `Spawner`
  seam, so it is a swap, not a second tool). Default builds never pull it.
- Turn-on may be automatic via the capability handshake (#28): a `links`
  build-script / version probe flips the feature when the published brush carries
  the `CommandInterceptor` API — capability-thinking, not a version pin.
- **Orthogonality:** the engine runs *inside* whatever L3 backend
  `best_available_sandbox()` selected. Per-OS L3 (D1–D4) and engine choice (D5)
  are independent layers; the same jail confines either engine identically.
- **Additive and reversible** (ADR 0005 D4): default stays safe-subset; adopting
  brush is a feature flip, dropping it is removing the flag. No lock-in.

## Consequences

- **Apple Silicon / macOS:** until the Seatbelt backend (#50) lands, macOS builds
  cleanly and runs the engine *advisory* (`SandboxKind::None`, honest). The
  Seatbelt backend must be authored and verified **on a Mac** — it can't be
  compiled or tested from the Linux CI box; cfg-gating keeps it from affecting
  other targets.
- **No silent confinement holes across the matrix:** every OS×feature
  combination either compiles a real backend (with a fail-closed `apply` + honest
  `SandboxKind`) or falls back to honest `None`. The CI matrix should assert the
  reported `SandboxKind` matches the host's true capability (ADR 0004 D1 / #30).
- **Adding a backend** is local: a feature, a target-cfg dep, a `best_available_sandbox`
  arm, a `SandboxKind` variant, an `apply()` — no change to the engine or the Gate.
- **The default build stays lean and publishable** (no Landlock, no brush, no
  fork); confinement and full-bash are both opt-in.

## Alternatives considered

- **A single `cfg(target_os)`-aware feature.** Impossible — cargo features are
  not target-conditional. D2 (enable-all + code-side selection) is the idiom.
- **Always-on OS sandbox (no feature).** Rejected: forces every embedder to carry
  every backend's dep and removes the honest-advisory fallback; ADR 0002/0003's
  "never overclaim, embedder chooses" stance prefers opt-in.
- **brush as the default engine / a second always-registered tool.** Rejected
  (ADR 0005 D4): the default must be publishable without a fork, and a swap keeps
  one `shell` tool honoring one contract.
