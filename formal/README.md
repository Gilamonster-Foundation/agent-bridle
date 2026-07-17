# formal/ — mechanized models of the Ceremony Suite

Tier-3 (algebra + state machine) formal artifacts for `docs/spec/`. These are
the "solid and defensible" backbone: the spec's laws are not just prose, they
type-check / model-check.

## `lean/Authority.lean` — the authority algebra (P0 §2.0, laws L1/L4)

Mathlib-free Lean 4. The authority type `Effect × Assurance × Scope` is finite,
so axis laws are `decide`-checked and the product laws follow componentwise.

```sh
lean formal/lean/Authority.lean      # type-checks in seconds; exit 0 = proved
```

Proves (25 theorems, **0 `sorry`**):
- axis + product meet laws (commutative, associative, idempotent);
- **attenuation** `a ⊓ c ≤ a` and `≤ c` — authority never amplifies (L4 / PO-4);
- `attenuate_compose` — sequential ceilings collapse to one meet (order of
  independent ceilings is irrelevant);
- **no fail-open** `resolve [] = NeedsDecision`, never ⊤/approve (OB-9/OB-12);
- **order-independence** `resolve (x::y::xs) = resolve (y::x::xs)` — the
  generating step of any permutation (L1 / PO-1).

The Aeneas track (Phase 1c) extracts the Rust `resolve` kernel with Charon and
proves it *refines* this model — so the implementation inherits these theorems.

## `tla/CeremonyStore.tla` — the store state machine (P2, PO-2*)

TLA+ model of the CAS append + the anti-rollback trusted-state machine:
concurrent candidates and CAS-losers are benign; the externally-protected
checkpoint is monotone; no rollback past it; equivocation is two *committed*
records at one `(store,thread,sequence)`. Check with TLC:

```sh
# tlc CeremonyStore.tla   (TLA+ Toolbox / tla2tools.jar; add a model with small bounds)
```

Maps invariants to PO-2 / PO-2a / PO-2c and OB-15 / OB-16.

## Why two tools

The **algebra** (a pure function over a lattice) is Lean+Aeneas territory —
it refines to Rust. The **protocol/state machine** (concurrency, an attacker
transition, temporal invariants) is TLA+ territory. Confusing the two is the
"prose becomes authority-bearing protocol" failure the reviews punished; the
proof tiers keep them apart (see `docs/spec/README.md` → "The teeth").

Enrollment ceremonies (P3) get **Tier-2** symbolic proofs (Tamarin/ProVerif)
in Phase 2 — a third tool for a third kind of claim.
