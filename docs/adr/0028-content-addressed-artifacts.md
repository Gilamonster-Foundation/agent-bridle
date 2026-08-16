# ADR 0028 — Content-addressed artifacts: read by CID, write by append + bind

- Status: **Proposed — sketch** (2026-08-16). Architecture-before-implementation;
  a GO here authorizes proposing an implementation phase, not writing one.
- Date: 2026-08-16
- Context: Bridle's filesystem authority is path-shaped end to end — `Caveats`
  carries `fs_read`/`fs_write` as sets of path strings, `Scope::meet` is exact
  set intersection, and containment (prefix, symlink, `..`) is deliberately
  *outside* the lattice, done at use time by `ToolContext::check_path_*`. That
  is honest, but it means (a) the meet is semantically empty for any two path
  scopes that are not byte-identical, (b) a grant names a *location*, so what
  the human approved and what the child later reads can differ, and (c) a path
  means nothing across hosts. Meanwhile the workspace already has a real
  content-identity substrate — the `content-addressable` crate's CIDv1
  (`dag-cbor 0x71`, BLAKE3 `0x1e`), used today for `AdmittedFenceId` and for
  agent-mesh `AuthorityId`/`GrantId` — and Bridle's own evidence chain
  (`assumptions.md` ASM-CID, *partial*) is waiting on exactly the input/output
  identities this ADR supplies. The motivating consumer is newt-agent's Jupyter
  tool (PR #1730): a notebook is a *value*, its execution is an *action*, and
  its result is a *new value* — the shape a content-addressed store fits and a
  mutable working tree does not.
- Governed by / harmonizes with: **ADR 0002** (`Caveats` meet-semilattice,
  one mint site, no widen; new axes land upstream, never in Bridle), **ADR
  0013** (program identity by presence in a constructed rootfs), **ADR 0022 /
  0024** (signed-object grammar, canonical dag-cbor, CIDv1 links), **ADR 0023**
  (a claim with no proof tier is prose), **ADR 0026 / 0027** (projection
  template: no new authority carrier; `Unknown ⇒ refuse`; native evidence
  before merge), and P5 OB-10 (seal a `file` by identity, never by mutable
  handle). Identity contract: the `content-addressable` crate is the *single*
  home of content identity for the whole line; codec/text/algorithm policy for
  raw artifacts is decided there
  ([content-addressable#84](https://github.com/hartsock/content-addressable/issues/84)),
  not here.
- Scope: how content identity enters *fs authority* and *evidence*. It does
  **not** add a `Caveats` axis, does not replace path authority for working
  trees, and does not decide the store's on-disk format.

## Question

Should Bridle let grants and evidence name files by **content identifier
(CID)** rather than by path — and if so, for which operations, enforced by
what, and with what residuals?

## Findings the decision rests on (verified 2026-08-16 on the reference Linux dev host, kernel 6.8 / Landlock ABI 4)

1. **A CID is an exact token.** `Scope::meet` (BTreeSet intersection) and the
   mesh's "membership is exact set inclusion" are *correct* for CIDs with no
   canonicalization at all. Containment over a **tree** CID is DAG reachability
   — a decidable, exact set (the leaf closure) — not a string prefix.
2. **A CID names a value, never a slot.** There is no such thing as write
   authority "to a CID"; the content changes, the name changes.
3. **A CID identifies; it never authorizes.** Anyone can compute the CID of
   `/etc/passwd`. A CID is a scope token *inside* a signed grant; the grant
   authorizes. (This is P5 OB-10's sealing rule and OB-18's no-secrets rule
   read together.)
4. **Landlock rules are inode-keyed, not path-keyed.** A rule on `allowed/f`
   survives `mv allowed/f allowed/f2` and a cross-directory move, and *denies* a
   fresh object created at the old name (tmp+rename). Rules on a single regular
   file work. Symlinks are resolved before the check. The kernel layer is
   already object-shaped; Bridle's string layer above it is the name-shaped one.
5. **No kernel mechanism on this box enforces "may read only content == X".**
   fs-verity is compiled in but `FS_IOC_ENABLE_VERITY` → `ENOTSUP` (ext4
   without the `verity` feature); IMA appraisal has no policy loaded; the BPF LSM
   is not in the active LSM list.
6. **Hash-after-open is racy on mutable files.** No mandatory locking; a writer
   can change what a later `read`/`mmap`/`exec` through the *same fd* observes.
   Verifying the **buffer you actually consume** is always sound; verifying an
   object and then re-reading it is sound only if the object is immutable.
7. **Existing drift worth naming.** `rootfs.rs` keys the ADR 0013 rootfs cache
   by `(path, ro/rw, len, mtime)`, not by content, contra ADR 0013 D7.

## Decision

### D1 — CIDs are scope tokens and evidence, not a new authority carrier

No new `Caveats` axis. A CID enters authority only as a member of an existing
scope set (D2, D4) and enters evidence as a link in a signed record (D5). Any
notion of "the model holds a CID, therefore it may read it" is rejected
(finding 3).

### D2 — Read authority over immutable artifacts is `fs_read` on a harness-owned store

- The harness owns an **artifact store**: a directory of immutable objects
  laid out `<store>/<cid>` (single object) with materialized trees for tree
  CIDs. Objects are `0444`, written only by the harness at ingest, verified at
  ingest (content == name), and never rewritten (grow-only; the
  `content-addressable` `NodeStore` laws PO-STORE-1..3).
- A grant to read an artifact is the ordinary token
  `fs_read: Only({"<store>/<cid>"})` (or the materialized tree root). It is
  enforced by the **existing fs fence** — Landlock rules on single files or on
  the tree root — at its existing `Kernel` grade (finding 4). Because the child
  holds no `fs_write` on the store, integrity of what it reads is guaranteed
  *by authority*, and content == name is guaranteed by ingest. **The path rule
  is the CID rule.** Zero protocol change; zero new enforcement mechanism.
- Cross-host: the same CID token materializes to a store path on any host; the
  grant is portable, the path is derived.

### D3 — Trees are the crate's DAG shapes; containment is DAG closure

A tree CID is the root of the `content-addressable` chunked-file/directory DAG
(`DirNode`/`FileNode`/`ChunkLeaf`, content-addressable#53). Materialization
writes the closure under `<store>/<cid>/`; the granted read set *is* the leaf
closure. Bridle defines no tree object of its own (no NAR, no bespoke tree
encoding); artifact identity — including whether raw byte leaves carry a raw
codec or stay dag-cbor-wrapped — is decided in content-addressable#84 and
consumed here.

### D4 — Writes are `append(store) + bind(ref → CID)`; `fs_write` never targets a CID

- A confined child writes into a **private staging directory** it holds
  `fs_write` on. After the action, the **harness** ingests staging outputs
  into the store (hash → CID, verify, place `0444`). Append is
  unforgeable-by-derivation: the only way to add content is to add content, and
  its name follows.
- Names live in a **ref namespace** owned by the store
  (`<store>/refs/<name>` → CID). Bind authority is the ordinary token
  `fs_write: Only({"<store>/refs/notebooks/a.ipynb"})`, checked through
  `ToolContext::check_path_write` — but the *write is performed by the harness*
  on the grant's behalf, after validating the CID exists in the store. Ref
  names are flat, symlink-free, exact tokens; meets over them are exact.
- The child never holds authority over the store or the ref namespace. Working
  trees stay path-authority (this ADR does not touch them); a "read latest of
  `notebooks/a.ipynb`" grant is a ref grant, and it is a *location* grant by
  design.

### D5 — Evidence binds input CIDs, action, fence, and output CIDs

`ExecutionResult`/`FenceEvidence` gain (as CIDv1 links, `content-addressable`
typed ids, domain-tagged per ADR 0022): the granted input CIDs, the staging
outputs' CIDs after ingest, the `AdmittedFenceId`, and an **action id** =
CID over `(inputs, fence id, argv, env-grant)`. This closes the *inputs* and
*results* hops of ASM-CID and gives a deterministic key for a future result
cache (same inputs + same fence + same command ⇒ same result) without
promising one now.

### D6 — Content verification is over consumed bytes, or by immutability — never hash-then-reread

Inside the harness, `open_scoped` may verify a store object by hashing the
buffer it hands to the tool. Verifying an fd and then letting a tool `mmap`,
re-`read`, or `exec` it is permitted **only** for store objects (immutable by
D2). Exec-by-content is *not* adopted: `fexecve` of a hashed sealed memfd is
sound but fights the inode-keyed exec fence (Landlock EXECUTE checks the
inode's ancestry; ADR 0011 seccomp-denies `execveat` at `exec:none`); ADR 0013's
"presence in a constructed rootfs" remains the exec-identity mechanism, with
its cache re-keyed by content (finding 7) as a follow-up.

### D7 — Residuals, named honestly

- **ASM-STORE (host trust).** The store's integrity against the *host user*
  (not the child) is DAC only on this box; fs-verity / IMA would be a stronger
  witness where available and are `Unknown` here. Reported, not claimed.
- **Metadata / Inspect.** A store path leaks existence and size like any path
  (posix-authority-model's `Inspect` residual); unchanged by this ADR.
- **Ref-bind is Interceptor-grade.** The harness performs the bind; the fs
  fence bounds *which* refs, the harness bounds *what* may be bound.

## Worked example — Jupyter as a hermetic action

`jupyter.execute(notebook: CID) → CID`: the grant carries
`fs_read ⊇ {<store>/<nb-cid>, <store>/<kernel-env-tree-cid>}`,
`fs_write = {<staging>}`, `exec = {jupyter}`, `net = none` (kernels on
`transport: ipc` in staging; see the #1730 review), and optionally
`fs_write ∋ <store>/refs/notebooks/a.ipynb` for bind. nbconvert runs with
`--output` into staging (no `--inplace`); the harness ingests the result,
records `(inputs, action, fence, outputs)` per D5, and binds the ref if
authorized. The model never names a host path.

## Consequences

**Positive.** Meets over artifact reads and ref binds are exact and mean what
they say; approve-what-you-saw becomes the strong form (bytes, not names);
grants are host-portable; the ASM-CID inputs/results hops close; result
caching becomes possible; nothing new for the kernel to enforce; no `Caveats`
change, no mesh bump.

**Negative / cost.** A harness-owned store and ref namespace to build and
back up; ingest cost (hash once, at ingest — never per open); every edit of a
live artifact is a new CID (working trees deliberately stay path-shaped); one
more place (`refs/`) where a name is a location; identity policy for raw
artifacts is blocked on content-addressable#84.

## Alternatives considered

- **A `cid` axis in `Caveats`.** Rejected: ADR 0002 sends new axes upstream,
  the fixed-field struct makes it a lockstep major with old-reader fail-open,
  and D2 gets the same enforcement with a path token.
- **CIDs as bearer capabilities (Tahoe read-caps).** Rejected: a content hash
  is guessable for low-entropy content and public for shared content; it is a
  name (finding 3).
- **A Bridle-local artifact digest / tree format** (e.g. nessie `Digest`/`Tree`,
  kyln raw-codec ids). Rejected: the line standardizes on the
  `content-addressable` crate; foreign conventions are subsumed there (#84),
  not accommodated here.
- **Kernel content enforcement (fs-verity + BPF LSM, IMA appraisal).**
  Deferred: unavailable on the reference host; belongs as a per-platform
  witness under ADR 0026's honesty matrix if/when present.
- **Exec by content (sealed memfd + `fexecve`).** Deferred: see D6.

## Proof obligations (ADR 0023 tiers)

- **Tier 1 (property):** granted read set for a tree CID == DAG leaf closure;
  `Scope::meet` over CID tokens is exact (already covered upstream; add a CID
  vector).
- **Tier 2 (native, hostile child):** under Landlock, a child with
  `fs_read = {<store>/<cid>}` reads that object, is denied a sibling object,
  is denied `bind`/`link`/`write` in the store; a same-name replacement of a
  granted object is denied (finding 4).
- **Tier 2 (harness):** ingest rejects any object whose bytes ≠ its CID;
  `bind` rejects a CID absent from the store and a ref outside `fs_write`.
- **Assurance ledger:** ASM-STORE row (host trust, `Unknown` witness); ASM-CID
  updated from *partial* to name the two hops this closes.

## Notes

- Consistent with the "a CID identifies, never authorizes" law stated on the
  unmerged `adr/0025` branch, but this ADR does not depend on that document;
  the identity contract is the crate.
- Companion review that motivated this: the #1730 / Capability-IR assessment
  (2026-08-16) — the exact-token meet problem and the "Jupyter needs no TCP"
  finding.
