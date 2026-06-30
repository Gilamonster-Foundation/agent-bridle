# ADR 0008 — External-consumer dependency strategy for agent-bridle-core

- Status: Accepted (2026-06-29)
- Date: 2026-06-29
- Context: the step-up surface (`Gate::evaluate` / `authorize_with_discharge` /
  `authorize_step_up`, `Presence`, `Decision`, `DischargeProvider`,
  `DischargeVerifier`, `Ed25519Verifier`, …) now lives in `agent-bridle-core`
  (ADR 0007; issues #60–#63). The workspace wires its crates by `path`
  (`Cargo.toml`), which only works *inside* this workspace; the one published
  external dep is `agent-mesh-protocol = "0.6"`. `agent-bridle-core` is already
  on crates.io at **0.1.0** — but that release predates the step-up surface.
  newt-agent (a separate repository) is the first out-of-tree consumer: its OCAP
  facade **P3 (step-up)** must depend on this surface.
- **Extends ADR 0007** (which defines the surface) by deciding *how* an
  out-of-tree crate depends on it. Changes no invariant.
- Related issues: #60–#63 (the surface this makes consumable); #28 / #20 (the
  brush git-dep that keeps the *shell* crate unpublishable — the reason newt
  depends on `core`, not the facade).

## Question

How does an out-of-tree repo (newt) take a real dependency on the step-up
surface? A `path` dependency only works inside this workspace. The crate is
published at 0.1.0 but that release is stale. And which crate should newt
depend on — `agent-bridle-core` or the `agent-bridle` facade?

## Decision

### D1 — newt depends on `agent-bridle-core` directly, NOT the facade

The entire step-up surface lives in `agent-bridle-core`. The `agent-bridle`
facade additionally pulls the leaf tool crates — `agent-bridle-tool-shell`,
which carries the **brush git dependency** under its `shell` feature (#20/#28)
and therefore cannot publish to crates.io until brush ships upstream. Depending
on the facade would drag that unpublishable edge (and tokio, reqwest, …) into
newt for no benefit. `agent-bridle-core` has **no git dependencies** — only
crates.io deps (`anyhow`, `serde`, `serde_json`, `async-trait`,
`agent-mesh-protocol`, and the optional `landlock` / `ed25519-dalek`) — so it is
always publishable and is the right, lean dependency for the step-up surface.

### D2 — git-pin now, publish a version bump at the step-up API freeze

- **Now:** newt git-pins a rev/tag of this repo and depends on
  `agent-bridle-core` from that pin, so P3 can build immediately — no publish, no
  version coordination. (crates.io rules forbid a git dep if *newt itself* is
  ever published; newt is an application, so this is acceptable interim.)
- **At the freeze:** once the step-up surface is stable (#60–#63 merged — done),
  bump the lock-step workspace version and publish `agent-bridle-core` to
  crates.io. The already-published 0.1.0 predates step-up, so the surface ships
  in the **next** published version. newt then switches its git pin to the
  crates.io version on a plain `cargo update`.
- Publishing is **outward-facing and irreversible** (DESIGN.md §release) → it
  requires the owner's explicit go-ahead and the version bump. **This ADR
  prepares and gates publishability; it does not publish.**

### D3 — feature flags external consumers enable

- `verifier-ed25519` — for the production `Ed25519Verifier` on the step-up path
  (ADR 0007 / #62). newt's P3 enables this.
- `linux-landlock` — only if the consumer wants the kernel L3 sandbox
  (orthogonal to step-up; ADR 0006). Off by default.
- The pure gate/policy/decision surface (`Gate`, `Presence`, `Decision`,
  `StepUpPolicy`, `DischargeProvider`, `DischargeVerifier`) needs **no** features.

A minimal consumer manifest:

```toml
[dependencies]
# interim (now):
agent-bridle-core = { git = "https://github.com/Gilamonster-Foundation/agent-bridle", tag = "<step-up-freeze-tag>", features = ["verifier-ed25519"] }
# at the freeze, switch to:
# agent-bridle-core = { version = "<next>", features = ["verifier-ed25519"] }
```

### D4 — a publishability gate guards the dependency boundary

`cargo publish --dry-run -p agent-bridle-core` runs in CI **and** the pre-push
hook (via the `just publish-check` recipe — HOOK/PIPELINE PARITY). A future
change that breaks core's publishability — re-introducing a git dependency, or a
path-only *required* dep with no version — fails the gate before it can merge and
silently strand newt. `agent-bridle-py` keeps `publish = false` (it is never
published from here; the justfile records why).

## Consequences

- newt's P3 is unblocked today (git pin) with a committed path to a stable
  crates.io dependency at the freeze.
- The publishability gate makes "core stays consumable out-of-tree" a *checked*
  property, not a hope — the regression that would break it now fails CI.
- Lean blast radius: newt pulls `agent-bridle-core` + `agent-mesh-protocol` and
  nothing from the shell/web/brush side.

## Alternatives considered

- **Depend on the `agent-bridle` facade.** Rejected (D1): drags the
  unpublishable brush git-dep edge and heavy leaf-tool deps into newt.
- **Path dependency.** Rejected: only works for crates *inside* this workspace;
  newt is a separate repo, so a path dep cannot resolve there.
- **Publish immediately (no git-pin interim).** Rejected: publishing is
  irreversible and the version isn't frozen until #60–#63 settle; git-pin lets
  newt proceed without prematurely freezing/publishing an API still in motion.

## Follow-ups

- At the freeze: bump the workspace version and run `just publish-crates`
  (owner go-ahead required); then update newt's pin to the crates.io version.
