# ADR 0029 — A runtime is an engine, a fence and a tool source

- Status: Proposed
- Date: 2026-11-22
- Issue: #522 (epic #521)
- **Amends the vocabulary of ADR 0005 D2, ADR 0006 and ADR 0009.** It moves no
  invariant and changes no code.

## Question

Five words name parts of one thing: *engine* (ADR 0005), *backend* (ADR 0006),
*tier* (ADR 0009), *sandbox kind* and *mechanism*. No document says which
combinations a host can run, so a row can be offered without ever having run.

## Decision

### D1 — A runtime has three parts

A **runtime** is what runs one command under a grant:

| Part | Question | Type today |
|---|---|---|
| engine | who interprets the command | `ShellEngine`: `safe-subset`, `host`, `brush` |
| fence | what the kernel enforces on it | `SandboxKind`: `Landlock`, `Seatbelt`, `AppContainer`, `MinimalRootfs`, `MicroVm`, `None` |
| tool source | where its programs come from | no type: the host's `PATH`, or the carried utilities |

*Engine* keeps its meaning (L2, convenience, ADR 0005 D1). *Fence* is the word
for what ADR 0006 calls a backend and `SandboxKind` names; `sandbox_kind` in a
result stays the field name. *Tier* (ADR 0009) is a fence's strength, not a
fourth part.

### D2 — Valid rows, read from code at 86d6556

A row is valid when the code admits it and a result names it. "Tested" cites a
test that runs the row's engine against the row's fence; where none does, the
row says so.

| OS | Engine | Fence | Tool source | Admitted by | Tested by |
|---|---|---|---|---|---|
| Linux | `safe-subset` | Landlock | host `PATH` | `ShellEngine::build`, spawn funnel (`agent-bridle-core/src/spawn.rs`) | `real_spawn.rs` |
| Linux | `host` | Landlock | host `PATH` | `host_shell.rs`: serves only unrestricted `exec` and `net`, refuses the rest | `host_shell_real.rs` |
| Linux | `brush` | Landlock | carried utilities, else host `PATH` | `brush_shell.rs`; needs the `brush` feature | `brush_real.rs`, `carried_coreutils.rs` |
| Linux | any | none | as the engine | no backend compiled or kernel lacks Landlock: `sandbox_kind` is `none`, every restricted axis is advisory | `engine_conformance.rs` runs the host's default fence only |
| macOS | `safe-subset` | Seatbelt | host `PATH` | `macos-seatbelt` feature | `seatbelt_floor_evidence.rs`, `seatbelt_net_evidence.rs` |
| macOS | `host`, `brush` | Seatbelt | as the engine | `macos-seatbelt` feature | untested |
| macOS | any | none | as the engine | `macos-seatbelt` feature off | `engine_conformance.rs` in the sweep's no-Seatbelt subsets |
| Windows | `safe-subset` | AppContainer | host `PATH` | `windows-appcontainer` feature | `windows_appcontainer_contract.rs` |
| Windows | `host` | AppContainer | host `PATH` | `windows-appcontainer` feature | untested |
| Windows | `brush` | any | none | refused: `brush_private_control_supported()` is false off Linux and macOS | `shell_engine.rs` |

`MinimalRootfs` and `MicroVm` are not rows. They exist as `SandboxKind` values
with enforcement tables in `report.rs`, and `agent-bridle-jaild` and
`rootfs.rs` implement the jail, but no engine's build path selects them.
`vm.jaild_socket` is parsed by `agent-bridle-config` and read by nothing.
`require_landlock` and `require_seatbelt` are the only fence floors a host can
set. A row for either fence waits for a build path and a test (#525 for the
minimal rootfs).

### D3 — What each part may and may not do

- A result states the engine and fence it ran under. It will state the tool
  source (#524). A fence the host did not apply is reported as `none`, never as
  the fence it asked for (ADR 0004).
- A runtime that cannot be built is refused, never replaced by another
  (`ShellEngine::build`, #491). The fence follows the same rule.
- The tool source never widens authority. The carried utilities run under the
  same fence and the same `exec` check as a host program (ADR 0011).

## Consequences

- The conformance lane (#523) iterates D2's rows. A row no CI host can run
  fails the comparison; the rows marked untested above are the first.
- A host that selects a runtime from config (epic #521) names the three parts
  and gets a refusal for a row that is not here.
- No code moves. `ShellEngine` keeps its name; the tool source becomes one more
  `ShellOptions` field when #524 or #525 needs it.
