# Named host root with an inherited filesystem/network fence

Status: final source review and the checked-in six-command `just check` gate
are complete. The gate passed with `BRIDLE_REQUIRE_LANDLOCK=1` and
`BRIDLE_REQUIRE_FD_FIXTURES=1`. Native old-0.8 helper red, core and Brush greens,
and production application/operand mutation controls are measured. Focused
tests/lint and facade compilation pass. Publication, release and Newt Cargo
integration remain pending; optional strict rustdoc preflight reports unchanged
baseline link defects.

## Contract and proof domains

The existing admission scope obligation compares executable identities across
a process tree. It remains the default and continues to use
`AdmittedFence::admit` and the mesh `admit` relation on all four axes. This is
not a claim of complete native enforcement: Linux reports exec as Interceptor
and retains the documented loader/trampoline residual. Tests must preserve
that honest report rather than turn the scope obligation into a Kernel claim.

The proposed, explicitly selected **NamedRoot** contract authorizes one exact
absolute root invocation and permits its descendants to choose executable
identities inside the inherited filesystem/network fence. These are distinct
proof domains:

| Obligation | Evidence | Admission rule |
| --- | --- | --- |
| Root executable | Singleton containing the exact program passed to spawn | Exact absolute member of the unchanged effective `exec: Only` set; basename matching and parent traversal refuse |
| Descendant executable identities | The actual backend projection, explicitly `Unbounded` for this mechanism | Accepted only by the explicitly selected NamedRoot contract; never described as a subset of the bounded exec grant |
| Descendant filesystem and network | Actual backend projection and finite concrete closure checked against the trusted recorded protected-root inventory | Existing mesh `relate` must report Equal or Subset for each axis against delegated scope union declared closure |
| Enforcement strength | Actual mechanism with a root-scoped exec witness | Join the caller's floor with `EnforcementFloor::CONFINED`; root exec is Interceptor, so a caller requiring Kernel exec refuses |

This is an explicit change of the exec obligation's domain, not proof of the
old process-tree exec obligation. The trusted host selects the new operation;
model arguments cannot select it. The operation requires an exact absolute
grant and records the changed domain in its admission evidence. The effective
`Caveats` remain byte-for-byte unchanged; no `exec: All` replacement, unbounded
runtime closure, or `from_delegated` substitution is permitted. A host needing
the old process-tree scope obligation must use the default operation, with its
existing reported enforcement and residuals.

## Existing machinery and the minimal gap

Reuse `ToolContext` minted by `Gate`, `ResolvedScope`/`relate` from
`agent-mesh-protocol`, `AdmittedFence`, `ConfinementMechanism`, `FenceEvidence`,
`ExitEvidence`, and the existing local execution handle/tree supervisor.
`ContentId` already addresses the canonical fence body; this change needs no
new identifier, journal, outcome vocabulary, or execution supervisor.

The missing datum is exec's proof domain. Add `ExecBoundary` to the existing
mechanism: default `ProcessTree`, opt-in `NamedRoot`. Extend the existing private
fence body into an owned, inspectable `AdmittedFenceBody` for NamedRoot. Its body
contains the effective and mechanism caveats, exact root, selected mechanism
and boundary, and full `BackendProjection` (all resolved axes and the declared
runtime closure), plus the canonical trusted protected-root inventory. The descendant exec axis stays visibly Unbounded. Derive its
CID through `content-addressable`; do not invent another encoding or identity.
Default-mode encoding remains unchanged where the new optional body is absent.

At apply time, `spawn_authorized` rederives a **fresh** projection from the
actual backend instance, selected mode, actual application caveats, and the
same root-set derivation routines that build its native rules. It does not read
the cached admitted projection. Verification rebuilds the complete canonical
body using this fresh projection and compares its CID with admission. Root
identity comes from the actual prepared launch's program operand, from `Command::get_program()` on the fully prepared native command, and must
equal the admitted root immediately before application/spawn. Wrapper backends
are unsupported for NamedRoot in this change. A separately supplied verification string is not sufficient. Tests must
substitute both the applied projection and the actual launch operand while
leaving the earlier admitted claim unchanged. This binds the prepared inputs;
it does not claim to solve remaining path-to-inode races or native fidelity.

Implemented entry points under review:

- `LocalExecutionBackend::start_named_root(cx, request) -> ExecutionHandle`:
  the same result shape and lifecycle as `start`, including Accepted/Denied,
  Started only after a live child exists, and one quiescent terminal.
- `AdmittedFence::admit_named_root(delegated, root, protected_roots, mechanism, floor, project)`:
  performs the two explicit exec-domain obligations and the three inherited
  scope comparisons above. It does not call ordinary admission with a forged
  projection or relaxed caveats. Reuse mesh `relate`; do not copy its algebra.
- `ConfinementMechanism::for_named_root(kind, child_network)` and an accessor
  for the explicit boundary; ordinary constructors retain ProcessTree.
- `verify_named_root_applied(caveats, actual_launch_root, protected_roots, mechanism, fresh_projection)`
  checks the complete applied identity against the admitted CID. The production
  caller must derive both the launch root and projection at the actual spawn
  boundary as described above. Existing default verification remains unchanged.
- `BrushShellTool::with_named_host_roots()` enables the trusted-parent routing
  described below. The builder defaults off; this is not a tool argument.

`core/spawn.rs` keeps the single spawn funnel, with an internal named-root
case reached by the managed entry point. `core/admitted.rs` owns admission and
identity; `core/report.rs` owns the explicit domain and honest strength.
`core/sandbox.rs` owns mode-specific backend projection/application.
`core/execution/local.rs` reuses its existing group cancellation, draining,
reaping and proxy finalization.

## Evidence transport and verification

The baseline `FenceEvidence` contained only `fence_id`, `sandbox_kind`, and
`egress_proxied`; it could not reconstruct the root, domain, or axis body. The
implementation extends that existing type because the opaque CID is insufficient:

1. The verified `AdmittedFenceBody` and existing `AdmittedFenceId` leave the
   actual spawn funnel together through `ConfinedChild` and `ManagedSpawn`.
2. Add `admitted: Option<Box<AdmittedFenceBody>>` to `FenceEvidence`. NamedRoot
   requires `Some`; default-mode evidence can retain its existing shape.
   `LocalExecutionBackend::attach` copies this producer evidence into Started
   only after successful native spawn, then carries the same body/CID into
   terminal `ExitEvidence.fence` after tree/proxy quiescence.
3. Add `execution_started: Option<ExecutionEvent>` and
   `execution: Option<ExecutionEvent>` to the existing `ToolEnvelope`: exactly
   the actual Started event (if acquired) and actual terminal event, with existing
   IDs/sequences. This bounded pair preserves Started even when finalization
   returns Failed. The adapter never reconstructs a requested-caveat body.
   The verifier rejects wrong kinds, mismatched IDs/order or changed terminal
   fence, and checks root/grant/body/CID/backend/report. Exited requires Started;
   Denied prohibits Started; Failed may have or lack it. A verified pair returns
   Some(body) only when an actual Started exists, otherwise None. No-start
   terminals carry no backend proof. Local IDs do not authenticate replay.
4. Add verification on the existing `FenceEvidence`: checked canonical body
   encoding must recompute its fence CID; body backend must match
   `sandbox_kind`; root/boundary/axis evidence must be available to the consumer.
   The consumer also compares the body root and effective caveats to the
   invocation/grant it is recording. A CID/body match is integrity evidence,
   not authentication of an arbitrary sender or a native confinement proof.

The required producer/consumer test starts a real managed root, observes its
Started and terminal evidence, serializes the real shell envelope, then uses
the consumer verifier to recover the same root/domain/all-axis body. Mutating
the transported root, domain, axis projection, or effective caveats without
updating the CID must fail. Replacing a body and CID with evidence for a
different root or effective authority must fail the root/grant-binding check.
Equal fence bodies may share a CID across executions: it identifies fence
content, not a unique run. Started and terminal correlation uses the existing
ExecutionId and trusted execution handle, with no new identity. Core and
production Brush producer/consumer tests have passed. Removing only the body-CID
comparison makes coherent Started/Exited CID corruption pass incorrectly;
removing only the apply-CID comparison accepts a valid narrower fresh projection
under the cached CID. Each focused negative fails under its isolated mutation
and passes after source restoration.

## Recorded protected roots

`SandboxPolicy.named_root_protected_roots: Option<BTreeSet<String>>` is the
trusted inventory channel. It is required and nonempty only for NamedRoot;
None is omitted in default serialization. The parent/config supplies its actual
state-store locations; model arguments do not choose them. Admission records
the canonical set in the existing fence body/CID. Apply rederives it from the
same trusted policy, and the consumer supplies and normalizes its own expected
inventory. The guarantee is relative to these recorded roots: this operation
does not discover every private store, infer a complete inventory from names,
or revoke explicit delegated access.

For the supported Landlock cell, exec and net runtime closures are exactly
empty. Filesystem runtime closures must be finite concrete paths; named classes,
unknown/unbounded axes and relative paths refuse. Canonical component overlap
catches ancestors, descendants and aliases of a recorded private root, rather
than relying on private marker substrings. Reuse the existing missing-tail
canonicalizer with an explicit finite-ancestor check for dangling/ambiguous
symlinks. Missing ordinary tail components are allowed; ambiguous resolution
refuses. This records a path snapshot and does not solve native path-to-inode
races. Only closure additions are checked: overlap already covered by an
explicit delegated filesystem grant is allowed. NamedRoot uses this recorded
inventory, so a concrete addition named `.newt` or `.ssh` outside it is not
private merely because of its spelling. Ordinary admission retains its legacy
private-marker refusals. No filesystem walk or extra grant/identity protocol
is introduced.

## Backend restriction

For Landlock, separate whether Execute is handled from whether the exec grant
is restricted. NamedRoot omits the inherited Execute restriction while read
root derivation still uses the exact restricted grant. Do not add
`bin_read_paths`, compiler names, or directories to loader allowances. Existing
explicit toolchain read grants must cover compiler/linker data; the operation
does not discover or grant them automatically.

NamedRoot native support is Landlock-only in this change. Seatbelt currently
lifts filesystem authority from delegated caveats and explicitly lacks the
required ruleset-grain projection. All NamedRoot Seatbelt/other backend requests
therefore refuse before a root side effect; no dormant process-exec weakening
is added. Ordinary Seatbelt behavior remains unchanged. A truthful native
Seatbelt projection is separate scope; no platform support is promoted here.

## Trusted-parent Brush routing

Selection occurs in `BrushShellTool::invoke`, after cwd/env validation and
before `SandboxedWorker::brush().spawn`. Parse using the already-pinned Brush
parser's original AST. Accept one synchronous simple command, with no extra
list item, conditional, pipeline stage, negation, timing modifier, prefix
assignment, redirect, or runtime expansion. Reuse `static_shell_word` and its
word-parser helpers for literal lowering. Do not use the flattened inspection
inventory or the safe-subset parser's newline-as-whitespace interpretation.

For a single absolute literal command with an exact effective grant, call the
managed named-root operation with argv/cwd/explicit env. Existing output
observation and timeout behavior must be preserved, forwarding the managed
terminal and evidence into the ordinary shell envelope. Compound/dynamic
commands retain the existing Brush mechanism and gain no new execution promise.
The lowering helper returns `Ok(None)` for valid noncandidate syntax; it must
not convert valid compound/dynamic commands into `Err` refusals. Malformed
syntax may return the normal parse error. Explicitly granted absolute
interpreters/launchers are roots under this generic contract; there is no
basename blacklist. A bare `sh` or `env` fails the absolute-root criterion.
An ungranted command retains the existing denial/permission retry path; after
an exact grant, the same parent dispatch can select NamedRoot.

The target Cargo example is one absolute Cargo command plus structured env.
The diagnostic `export ...; cargo ...` prefix was an environment-export
workaround, not proposed accepted grammar.

## Regression source and acceptance

The core synthetic admission matrix and native helper tests are now wired.
Existing 0.8 starts the exact root but its child image gets EACCES/exit42;
the candidate starts root/child/grandchild and exits0 with identical explicit
read grants and request. The direct unfenced controls pass as fixture positives. The actual production
OS-apply-disabled mutation also reaches the identical outside sentinel and
exits0; restoring the fence returns PermissionDenied/exit43. A mutation of
the prepared Command operand is refused before Started. Both temporary
source mutations were restored. The frozen ordinary body/CID also passes. Missing API compile
failures are not counted as behavioral red. Brush parser, real envelope,
observer/output-cap, unsupported-backend and process-tree cleanup tests have
also passed. The current-thread cancellation regression measured about two
seconds of reactor blocking before moving handle acquisition/collection/drop
into one blocking owner; its corrected timer control passes below 500 ms.
These focused receipts do not replace final review or the full gate. The
preserved Newt 0.7 Cargo red is evidence for 0.7 only.

Before acceptance, measure the reviewed regressions against the old behavior:

1. Same-name sibling cannot mint root admission; ordinary admission still
   rejects an unbounded descendant exec projection.
2. NamedRoot admits the explicit two-domain evidence. Test fs_read, fs_write
   and net widening independently; Unknown on each inherited axis and exec;
   private or unbounded runtime closure on every authority-bearing axis;
   ungranted, bare, relative, ParentDir and empty roots; wrong mode, unsupported
   backend, and a Kernel exec floor. Each refusal must be attributable to its
   intended condition, with an admitted control where applicable.
3. Different roots under the same grant have different fence CIDs; mode/root/
   caveat substitution fails apply-time verification. A changed **fresh**
   backend projection and a changed actual spawned root operand must also
   refuse while the cached admission remains unchanged.
4. Native copied helper executables form root/child/grandchild identities.
   They run under NamedRoot but fail the old inherited exec restriction;
   known outside-read/write and socket probes fail while inside controls pass.
   Include the explicit fence-disabled mutation: the identical child/program,
   arguments, environment and known outside sentinel must read that sentinel
   and exit 0 when the OS fence alone is disabled. Under the fence it must
   fail the same read; the real envelope must have the literal `denied` field
   **absent**, identify the actual backend, and report each restricted fs/net
   axis as Kernel and named-root exec as Interceptor. These assertions
   distinguish native denial from parser refusal, ENOENT, or a broken fixture.
   The disabled-fence run is a test control, never a production fallback.
   A normal no-backend invocation must still refuse. The readable control
   therefore uses an explicit test-only fence-application mutation/control;
   do not weaken production admission to make that control execute.
5. Unsupported backends, including every NamedRoot macOS invocation, refuse before any
   root sentinel. A real opt-in-off/default runtime twin preserves ordinary
   Brush behavior and its Interceptor report. With opt-in enabled, valid
   compound/dynamic input executes through that same ordinary route, with
   equal observable results and no NamedRoot body.
6. Compound/newline/substitution input never selects NamedRoot. Quoted literal
   argv round-trips, and explicit environment reaches the root without an
   `export` prefix.
7. Cancellation/timeout of a root with a live grandchild finishes through the
   existing managed lifecycle, with no descendant, pipe, proxy, or blocking
   worker retained after terminal evidence.
8. Newt's actual production Cargo fixture succeeds with explicitly granted
   toolchain reads; the existing outside-access and ungranted-root twins hold.
   The old-0.8 and NamedRoot Cargo runs must use the **same explicit read
   grants**, argv, cwd and environment; only the reviewed exec operation
   changes. Grant additions or environment fixes cannot account for the green.

Measured receipts include the native old-0.8 descendant refusal, the frozen
ordinary body/CID, core admission/inventory/native tests, and the Brush leaf's
12 unit, seven native and one no-backend cases. The production apply-disabled
and prepared-operand mutations have exact source diffs and restored-source
controls. Missing-bool decoding has a separate old-attributes real-envelope
round-trip red: only the five omitted-false boolean fields gain serde defaults;
explicit malformed values still refuse and `sandbox_kind` remains required.

Final focused verification passes: 34 core tests, 12 Brush unit tests, seven
native Brush cases, one real backend-disabled refusal, zero-warning core/leaf
clippy and facade compilation with Brush/Landlock. Formatting and the stock
security preflight pass. Optional strict rustdoc in that feature cell fails on
pre-existing private/broken links; every located diagnostic quotes a line
unchanged from the base, with no new NamedRoot link diagnostic. No warning is
suppressed and no baseline docs rewrite is included.

The six-command `just check` gate passed with both required native fixture
flags enabled, and final source review is complete. Publication, release and
Newt's production Cargo old/new twin with identical explicit read grants remain
pending; no upstream helper substitutes for that integration. A native macOS
refusal has not been run on this Linux host. Landlock-only selection refuses
all other backends, with a real feature-disabled refusal control here.

Native proofs must identify the actual backend and positive controls. A
nonzero exit or absence of structured denial is not by itself a confinement
proof. Cargo's current EACCES result remains a preserved dependency red.
Model: gpt-6-astra | Harness: Codex 0.153.4 | Operator: Shawn Hartsock | Time: 22:49 UTC | Date: 2026-09-12
