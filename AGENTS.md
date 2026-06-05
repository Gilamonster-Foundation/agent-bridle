# AGENTS.md — agent-bridle

Operating rules for any agent (human or LLM) working in this repository.
The authoritative design is `docs/DESIGN.md`; read it first.

## What this is

`agent-bridle` is the shared **tool + capability-enforcement layer** for the
Gilamonster agent line. Tools declare the authority they need as
`agent_mesh_protocol::Caveats`; the `Gate` refuses dispatch unless
`required ⊑ granted` under the meet-semilattice, and hands the tool only the
*meet* of granted-and-required (least authority). The confused-deputy gap is
closed **structurally** (a `ToolContext` is a mint-token, constructible only
inside `Gate::authorize`), not by prompt hygiene.

## License & attribution

- **License: Apache-2.0** (see `LICENSE`). `brush` is MIT — its notice is
  carried in `NOTICE`. Keep `NOTICE` current when adding third-party deps.
- **Commit author:** `Shawn Hartsock <hartsock@users.noreply.github.com>`.
- **Trailer on every commit:**
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`

## Hard engineering rules

- **No wall-clock as a coordination primitive.** Caveats key on
  `valid_for_generation` (a `u64` generation counter), never on `SystemTime`.
  Timeouts may use timers (they bound work; they do not coordinate state), but
  never derive a *caveat* or a *decision about authority* from wall-clock.
- **Zero clippy warnings.** `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` AND `--no-default-features` must both be clean.
- **Least authority by construction.** `effective = granted.meet(required)`.
  Never widen authority anywhere; `meet` is property-tested as non-amplifying
  upstream in agent-mesh-protocol.
- **One mint site.** `ToolContext` may be constructed only inside
  `Gate::authorize`. Do not add public constructors or `pub` fields.
- **Path checks canonicalize, never string-prefix.** `check_path_*` resolves
  realpath and rejects symlink/`..` escapes *before* the membership test.
- **Heavy deps live in leaf tool crates only.** `agent-bridle-core` depends on
  `anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol` — and
  nothing else (no tokio, no brush).

## Workflow

- **Real PRs only.** Branch → TDD → `just check` green → push → `gh pr create`
  → CI gate → human merge. Agents do not merge to `main` (repo-init bootstrap
  was the one allowed direct push).
- **Push hooks are mandatory.** Run `just install-hooks` after cloning. Never
  `--no-verify`. The hook mirrors CI (HOOK/PIPELINE PARITY comments enforce
  this — when you edit one, audit the other).
- **Every bug fix ships a regression test** that fails before the fix.
- **Versioning:** lock-step workspace version; hold the 0.x line.

## Crate README Rule

Every crate in this workspace gets its own `README.md` — crates.io renders
it as the crate's front page, and `cargo package` fails if a declared
`readme` file is missing.

1. **Existence:** a new crate lands with a `README.md` in its crate root
   (short: what it is, what it does, license).
2. **Freshness:** every version bump of a crate includes a review of that
   crate's README. Update it to match the released behavior — new features,
   changed CLI flags, removed APIs. If a bump PR leaves the README
   untouched, the PR body must say why.

Treat a version bump without a README review as an incomplete change, the
same way a bug fix without a regression test is incomplete.
