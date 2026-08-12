# The Bridle POSIX Authority Model

> POSIX is an interface/projection of Bridle authority. POSIX is **not** the
> security model. Bridle's authority algebra remains sovereign; a POSIX-shaped
> namespace is one *projection* of it, exactly as Landlock, Seatbelt, and
> AppContainer are projections today.

Status: **Design (architecture-before-implementation).** No enforcement
mechanism described here is built. Companion artifacts: the decision in
[ADR 0026](../adr/0026-posix-authority-projection.md); the machine-checked model
in [`formal/Ceremony/Posix/Machine.lean`](../../formal/Ceremony/Posix/Machine.lean)
and [`formal/tla/PosixAuthority.tla`](../../formal/tla/PosixAuthority.tla); the
threat model in [posix-threat-model.md](posix-threat-model.md); the authority
matrix in [posix-authority-matrix.md](posix-authority-matrix.md); the Linux
mapping in [posix-linux-projection.md](posix-linux-projection.md).

This document extends the algebra of [ADR 0002](../adr/0002-ocap-design-contract-and-hard-invariants.md)
and [ADR 0020](../adr/0020-authority-product-lattice.md); it does **not** open a
parallel authority universe. It is the formalization of the target already named
in [legibility-and-the-opaque-box.md](legibility-and-the-opaque-box.md): *a
confined child obtains a resource only by inheriting a handle (fd, or a preopened
directory) — never by pathname resolution against an ambient root.*

---

## 1. What is preserved (the sovereign algebra)

The POSIX model adds no new authority carrier. It reuses, unchanged:

- **Authority = `Caveats`** — four allowlist axes `fs_read`, `fs_write`, `exec`,
  `net`, each a `Scope = All | Only(BTreeSet)`, from `agent-mesh-protocol`,
  re-exported at `agent-bridle-core/src/lib.rs:28`. The order `⊑` is
  `Caveats::leq`; the meet `⊓` is `Caveats::meet`; `effective = granted.meet(required)`
  is minted once at `agent-bridle-core/src/gate.rs:207` and attenuation is
  structural via the `ToolContext` mint monopoly (`context.rs:42`, compile-fail
  doctests at `lib.rs:159-176`).
- **`EnforcementFloor`** — required strength per axis, `{Kernel, Interceptor,
  Advisory}` (`report.rs:92`), joined monotonically (`report.rs:526`), never
  lowered.
- **`ResolvedAuthority`** — the projection's honest bound per axis: `Bounded |
  Unbounded | Unknown`, with the fail-closed law **`Unknown ⇒ refuse`**
  (`sandbox.rs:132`, `provenance.rs`).
- **`AdmittedFence`** — the sole adjudicator (`admitted.rs:245`), content-addressed
  by `AdmittedFenceId` (BLAKE3 CIDv1/dag-cbor via `content-addressable`),
  verified admit→apply at `admitted.rs:346` / `spawn.rs:605`.

The POSIX model is a **new object grain** over this algebra, not a new algebra.
Where today `Caveats` axes name *path/host allowlists*, the POSIX model names the
*objects and operations* those allowlists authorize, and proves that the
object-and-descriptor layer cannot manufacture authority the `Caveats` did not
already grant.

### The fork we take deliberately

`agent-mesh-protocol` also ships an **unused** content-addressed
`Grant`/`Derivation`/`verify_chain` half (`authority.rs:202,406,530`,
`DenyAllElevations` fail-closed) that bridle does not wire in. Descendant
attenuation (§7) is the place that machinery belongs. This model **reuses** the
chain-attenuation discipline (`child ⊑ parent`) rather than inventing a second
one; whether to wire the mesh `Derivation` type itself, or model attenuation at
the POSIX grain, is the open decision recorded in ADR 0026 §Consequences.

---

## 2. The abstract machine (OS-independent)

An application under Bridle experiences a **projected namespace**: a POSIX-like
tree of objects and operations containing *exactly* the objects and operations
its delegated authority represents. The machine below is defined without any
kernel mechanism, so it can be projected independently onto Linux, macOS, and
Windows.

### 2.1 Object classes (minimum semantically correct set)

The prompt's candidate list is pruned to what carries **distinct authority**:

| Object | Kept? | Rationale |
|---|---|---|
| **File** | yes | the `fs_read`/`fs_write` bearer |
| **Directory** | yes | distinct: traversal + enumeration is not file content (§3 metadata) |
| **Executable** | yes | the `exec` axis; distinct from File-read (a file may be readable but not executable, and vice versa) |
| **SocketEndpoint** | yes | the `net` bearer |
| **Process** | yes | signal/inspect targets; not reducible to fs |
| **IPCChannel** | yes | AF_UNIX / pipe / shared-memory; carries *descriptor delegation*, irreducible to `net` (§4) |
| **Device** | **provisional** | `ioctl` is an untyped authority multiplexer — modeled as `Unknown ⇒ refuse`, not a first-class grantable object (§3) |
| ~~Namespace~~ | **folded** | not an object; it is the *resolution context* (§5) — modeling it as an object invites the amplification bug |
| ~~Credential~~ | **folded** | a Credential is a File object plus a projected name (§5); env/identity is authority-bearing *state*, handled in §3 |

### 2.2 Operations (minimum set)

`Lookup, Inspect, Read, Write, Create, Delete, Execute, Connect, Listen, Accept,
Delegate, Signal`. Pruned from the candidate list: **Rename** = Create+Delete on
a Directory (no new authority); **Map** (`mmap`) = an operation *on an already-held
descriptor* (§4), not a namespace op; **Control** = the `ioctl` multiplexer,
kept only as the `Device`-refuse case. **Inspect** is kept **distinct from Read**
— this is the load-bearing split of §3.

### 2.3 The central transition law

For a process in state `S` performing operation `op` on object `obj`:

```
transition(S, op, obj) is permitted
    iff
required_authority(op, obj)  ⊑  effective_authority(S)
```

This is `Ceremony.Posix.transitionOp` in the Lean model; the guard is
**definitional** — an unauthorized transition does not exist as a value, so
`complete_mediation` is a projection of the guard, not a runtime check. Every
object/operation must map `required_authority` onto the four `Caveats` axes or be
justified as a new authority class (§3). **No operation may fall into a generic
"syscall allowed" bucket** — that is the acceptance-gate line the matrix
(posix-authority-matrix.md) enforces per row.

---

## 3. Is the four-axis floor sufficient?

We do **not** auto-expand the axes. For each POSIX authority class we decide
sufficient / insufficient / uncertain against `{fs_read, fs_write, exec, net}`.
The full grid is [posix-authority-matrix.md](posix-authority-matrix.md); the
load-bearing findings:

- **Metadata vs content (Inspect ≠ Read).** `stat`, existence, size, ownership,
  timestamps, and directory topology are observable even when content is denied.
  This is already a *registered residual*: **ASM-MACOS-METADATA** (the Seatbelt
  profile emits `(allow file-read-metadata)` at `sandbox.rs:1981`; content stays
  confined, metadata stays ambient). **Decision:** metadata is modeled as a
  distinct `Inspect` authority that today resolves to `Unknown` on every backend
  (no backend confines it), and is therefore *reported*, never silently folded
  into `fs_read`. This is the single most honest candidate for a fifth axis; we
  do not add it yet, we surface it (matrix row `inspect.*` = `Unknown`).
- **IPC / descriptor passing.** AF_UNIX + `SCM_RIGHTS` transfers a *descriptor*,
  i.e. an object capability, between processes. This is **not** reducible to
  `net` (it is not egress) nor to `fs` (no pathname). It is **Delegate** (§4).
  Abstract-namespace unix sockets are already flagged a bounded residual
  (`config.rs:159`). Modeled as first-class `Delegate` on an `IPCChannel`.
- **Process control.** Signals, `/proc` discovery, ptrace, scheduling. Today only
  process-group kill exists (`spawn.rs:666`, `shell_tool.rs:1516`); discovery and
  signalling across the process boundary are **unmodeled** → `Unknown ⇒ refuse`
  for cross-process `Signal`/`Inspect`, `Faithful` for a process signalling its
  own group.
- **Devices / `ioctl`.** `ioctl` multiplexes unbounded, driver-defined authority
  behind one syscall number. It cannot be honestly bounded by an allowlist axis,
  so `Device` operations resolve to `Unknown ⇒ refuse` (never a grantable
  object). This is a *feature*: refusing beats a broad allowlist masquerading as
  mediation.
- **Identity / environment.** Environment variables are already boundary state
  (`env_clear` at `spawn.rs:650` + the loader denylist `config.rs:487`); `cwd`,
  `umask`, supplementary groups, and namespaces are authority-bearing *process
  state*, modeled as part of `effective_authority(S)` rather than as objects.

**Conclusion:** the four axes are *sufficient for the file/exec/net core* and
*insufficient for Inspect, Delegate, and cross-process Signal*, which the model
carries as explicit classes that resolve to `Unknown ⇒ refuse` until a faithful
projection exists — never as a silent fold into an existing axis.

---

## 4. Descriptors as capabilities (and where the analogy breaks)

**Hypothesis:** a POSIX file descriptor is already approximately a capability —
an unforgeable handle carrying rights to a specific object. The ambient-authority
problem is not the fd; it is the *manufacture of new fds by pathname resolution
against an ambient root*.

The model takes the hypothesis as the design target and then attacks it. A
descriptor is faithful-capability **only if** every way to obtain or derive one
is authority-bounded. The derivation surface, adversarially enumerated:

| Vector | Capability analogy holds? | Model treatment |
|---|---|---|
| `dup`/`dup2`/`fcntl(F_DUPFD)` | yes — same rights | `derive`, rights ⊆ source (Lean `descriptor_non_amplification`) |
| inheritance across `exec` | **only if ambient fds are closed** | the #319 gap — see below |
| `SCM_RIGHTS` receipt | yes, but crosses processes | `Delegate` on `IPCChannel`; received rights ⊆ sender's |
| `/proc/self/fd/N` reopen | **breaks it** — can *widen* mode | reopen is a namespace `Lookup`, bounded by `effective`, not by the fd |
| `O_PATH` upgrade | **breaks it** — `O_PATH` fd re-resolved to full | treated as `Lookup`, re-mediated against `effective` |
| `openat(dirfd, "..")` / `AT_EMPTY_PATH` | breaks it if dirfd escapes | require `openat2(RESOLVE_BENEATH|NO_SYMLINKS)` (Linux projection) |
| symlink / hardlink / bind-mount / rename TOCTOU | breaks object identity | §5 object-stability; E1 residual (`sandbox.rs:1139`) |
| `mmap(PROT_EXEC)` after read | breaks `exec` confinement | the ld.so trampoline; exec is honestly `Interceptor`, never `Kernel` |
| `io_uring` | **breaks everything** — async syscalls dodge the fd table | E3 residual; seccomp denies `io_uring_*` (`sandbox.rs:1462`) |

The through-line, proved in the Lean model: **`fds ⊑ effective` is preserved by
every `resolve`/`derive` step** (`reach_preserves_wf`). A descriptor is a
capability *because the reachable set never grows past the grant* — which is true
only when reopen/`O_PATH`/`openat` are re-mediated against `effective` (not
trusted as fd-derived) and ambient fds are closed on spawn. That last clause is
**issue #319** (`spawn.rs:342-358`): `ConfinedCommand` closes env but relies on
the CLOEXEC convention and does not `close_range` ambient fds. Until #319 lands,
the descriptor-as-capability claim is *aspirational on the real path* — which is
exactly why §15 of the plan recommends #319 as the first executable slice.

---

## 5. Object identity vs pathname identity

Authority attaches to a **delegated object capability**, not to a host pathname
string. The projected namespace need not mirror host paths:

```
host:      ~/.ssh/id_work        (+ id_ed25519, config, the whole ~/.ssh)
projected: /credentials/git-key  (ONLY id_work; ~/.ssh is not in the namespace)
```

The security claim is about the delegated object, not the string `~/.ssh`. This
requires a **stable object identity** per class, and it must be separated from
**content identity**:

- **Content identity** = the CID of the bytes (`content-addressable::ContentId`).
  Correct for *immutable* objects (an executable image, a config snapshot).
- **Object identity** = a stable handle to a possibly-*mutable* object. A mutable
  file **cannot** be named by its content CID — the CID changes on every write.

Stable-identity semantics per class:

| Class | Stable identity | Mechanism |
|---|---|---|
| File (immutable) | content CID | `content-addressable` |
| File (mutable) | canonical object handle | `openat2` + object-stability (E1); *not* content CID |
| Directory | canonical path root, symlink-resolved | `grant_roots_are_object_stable` (`sandbox.rs:1139`) |
| Executable | content CID of the image | rootfs cache key (`rootfs.rs:360`) |
| SocketEndpoint | (host, port) tuple or loopback-fenced proxy | `net_proxy.rs` |
| Process | pidfd (not pid — pid reuse breaks identity) | Linux `pidfd` |
| IPCChannel | the descriptor itself | §4 |

E1 (a symlinked/non-canonical grant root ⇒ `Unknown`) is the existing enforcement
of "pathname is resolution, object is authority": if the path does not resolve to
a stable object, the axis is `Unknown` and admission refuses.

---

## 6. The CID provenance chain — which links must exist

Content-addressing binds security-relevant state so an attacker cannot substitute
one artifact for another between analysis and application
(analyze-one/apply-another). We decide which of the candidate hops must
*cryptographically exist*, not which would be nice to log:

```
GrantCID → RuntimeClosureCID → PosixNamespaceCID → EnforcementPlanCID
        → AppliedFenceCID → ExecutionEvidenceCID → ResultCID
```

Grounded on what exists: `AdmittedFenceId` already binds
`FenceBody{mechanism_caveats, mechanism}` and `verify_applied` refuses on
mismatch (`admitted.rs:346`). `ASM-CID` is `partial` — the fence CID is real; the
plan/evidence/result CIDs are not yet Rust (`assumptions.md`).

**Minimum binding set** (the rest are logging until proven load-bearing):

1. **AppliedFenceCID** — exists today; the anchor.
2. **PosixNamespaceCID** — *required and new*. Because §5 makes "namespace ≠
   authority" the crux, the resolved namespace (the map from projected names to
   object capabilities) must be content-addressed and bound into the fence, or an
   attacker who controls resolution can present namespace `N` for analysis and
   `N'` at use. This is the one genuinely new CID the POSIX model demands.
3. **ExecutionEvidenceCID** — bind evidence to the applied fence (already modeled
   as T7 in `AuthorityLifecycle.tla`; grounds the non-equivocation obligation).

`GrantCID`/`RuntimeClosureCID`/`EnforcementPlanCID`/`ResultCID` are **deferred**:
they carry no substitution attack the above three do not already close, so adding
them now would be CID-for-aesthetics. All bindings extend the *existing*
`content_addressable::ContentId` machinery (BLAKE3/CIDv1/dag-cbor, a distinct
newtype per hop, fail-closed verify) — never a parallel hash format, and never
the local `step_up::ContentId([u8;32])`.

---

## 7. Security theorems (kernel-independent)

Stated here, mechanized in `formal/Ceremony/Posix/Machine.lean` (model half) and
`formal/tla/PosixAuthority.tla` (state-machine half):

- **Complete mediation.** For every permitted transition `T` by a process in
  runtime closure `R`: `authority(T) ⊑ delegated_authority(R)`.
  *(Lean `complete_mediation`; TLA+ `NoAuthorityAmplification`.)*
- **Descendant attenuation.** `authority(child) ⊑ authority(parent)`, absent an
  explicit authorized delegation. *(Lean `spawnChild_attenuates` +
  `spawnChild_wf`; TLA+ `DescendantAttenuation`.)*
- **Namespace non-amplification.** Resolving a name confers no authority beyond
  the grant. *(Lean `namespace_non_amplification`; TLA+
  `NamespaceNonAmplification`.)*
- **Descriptor non-amplification.** A capability derived from a descriptor cannot
  exceed the descriptor it derives from. *(Lean `descriptor_non_amplification`;
  TLA+ `DescriptorNonAmplification`.)*
- **Projection soundness.** For an enforcement projection `P`,
  `enforced(P(A)) ⊆ A`; where the platform cannot faithfully enforce `A`, the
  result is `Unknown / Unsupported / Refused` — **never** a silent widening.
  *(Lean obligation `ProjectionSoundnessObligation`; discharged by native
  evidence, not the model.)*
- **Non-equivocation.** The analyzed authority is cryptographically bound to the
  applied authority. *(Lean obligation `NonEquivocationObligation`; TLA+ T7 in
  `AuthorityLifecycle.tla`; grounded by ASM-CID.)*

The capstone `reach_preserves_wf` ties complete-mediation, namespace-, and
descriptor-non-amplification into one statement: **from a well-formed start,
every reachable state keeps `fds ⊑ effective`** — no sequence of
resolve/derive/operate steps amplifies a process's authority beyond its grant.

---

## 8. What the model deliberately does not claim

Per the assurance doctrine (`formal/assurance/assumptions.md`: *formal methods
prove our model; native evidence proves the OS refines our model*), this model
does **not** claim any OS enforces the projection. Projection soundness and
non-equivocation are stated as obligation `Prop`s with no proof term, discharged
by the hostile-child tests and the `ASM-POSIX-*` ledger, never by the algebra.
The adversarial case against the entire abstraction is argued in
[ADR 0026 §"Why bridle-POSIX may be the wrong abstraction"](../adr/0026-posix-authority-projection.md).
