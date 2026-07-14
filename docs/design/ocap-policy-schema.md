# OCAP durable-policy schema — the shared per-verdict contract

**Status:** contract shipped in `agent-bridle-core::policy` (#220). No
enforcement change; stores implement against it.
**Consumers:** newt-agent (first store: `~/.newt/ocap/`, newt#1131), gila, and
future fleet agents. Cross-agent trust-sharing over the mesh is explicitly
later work.

## Why

Prompted permissions are the day-1 default in the fleet's harnesses; what's
been missing is the **accumulation loop** — prompt → human decides → the
decision is stored **as durable, human-editable data** → fewer prompts next
session. Today durable *denies* exist in newt (`permission-denials.jsonl`)
but durable *allows* exist only for net hosts, and the shapes are ad-hoc.
This contract makes the whole verdict space symmetric, auditable, and shared.

## The shape

One TOML file per verdict, in a store directory the consuming agent owns
(newt: `~/.newt/ocap/`):

| file | verdict | meaning |
|---|---|---|
| `deny.toml` | Deny | never allowed; prompt not offered |
| `passkey.toml` | Passkey | allowed only after WebAuthn/presence step-up |
| `ask.toml` | Ask | always prompt (pins a target to interactive judgment) |
| `approve.toml` | Approve | durably allowed without prompting |

Each file holds entries per **capability class** — `[[exec]]` (command
targets), `[[fs]]` (path + `write` flag), `[[net]]` (hosts) — with optional
provenance (`note`, `granted`, `by`). Classes are a **closed enum** on
purpose: a permission surface must be enumerable to audit (unlike open knob
maps elsewhere in the fleet).

## The laws

1. **Precedence: deny > passkey > ask > approve.** A target matching several
   files takes the most restrictive verdict. A durable deny can never be
   shadowed by a durable approve.
2. **No match ⇒ fall through.** Evaluation returns nothing; the harness uses
   its interactive prompt / default-deny floor. Durable policy only ever
   *narrows or pre-answers* — it never widens the floor.
3. **High danger is never durably approvable.** Interpreter exec, broad fs
   roots (as judged by the consuming harness's danger table) must be refused
   at *write* time for `approve.toml`; the strongest offer for them is
   `passkey.toml`. The contract exposes `PolicySet::validate_approve` and the
   store MUST call it before persisting.
4. **Policy ≠ log.** These files are editable *policy*; the append-only audit
   trail (newt's `permission-log.jsonl`) stays separate and is never read for
   decisions.
5. **Matching is the harness's.** The contract evaluates exact strings; a
   harness with richer matching (basename rules, path prefixes, wildcards)
   normalizes before evaluating, or combines its own matches via
   `Verdict::precedence`.

## Seeded common settings

A shipped starter policy (e.g. in-workspace `git`/`cargo` under `approve`) is
just a `PolicyFile` document an installer offers to write — data, not code —
with `by = "seed"` provenance so it's distinguishable from human grants.

## Non-goals (now)

Wildcard/glob semantics in the schema itself; per-agent scoping inside one
store; mesh distribution of policy; revocation ceremonies beyond editing the
file. Each becomes its own contract rev when real.
