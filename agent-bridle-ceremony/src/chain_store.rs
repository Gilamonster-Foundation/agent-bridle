//! The P2 chain-store kernel — a Rust mirror of `formal/tla/CeremonyStore.tla`.
//!
//! This is the executable image of the TLC-model-checked (547 states green)
//! append + anti-rollback **state machine** of the Chain-Store profile
//! (`docs/spec/chain-store-profile.md` §1, §1.1, §4). It models **one** authority
//! thread — a fixed `(store_id, thread_id)` — as a *linear authority spine*
//! (§1: "conversation is a jungle; authority is a railway") plus an
//! externally-protected checkpoint. There is no wire format here: `StoreId`,
//! `ThreadId`, and `LineCid` are **abstract opaque handles**, not hashes or
//! encodings — those stay HELD until the Phase-1d conformance vectors
//! (`docs/spec/ROADMAP.md`, "HELD until its conformance vectors exist").
//!
//! ## Faithful image of the TLA+ variables
//!
//! | TLA+ variable | here |
//! |---|---|
//! | `spine` (`[1..len -> RecordIds]`) | [`ChainStore::spine`], `spine[i]` = sequence `i+1` |
//! | `len` (committed length; head = `spine[len]`) | [`ChainStore::len`] |
//! | `checkpoint` (externally-protected length) | [`ChainStore::checkpoint`] |
//!
//! `RecordIds` is a finite set of **model values** — symbols observable only by
//! equality, never hashed/ordered/serialized. [`LineCid`] mirrors that exactly:
//! it derives `Eq`/`Hash` but **no `Ord`** and exposes no bytes. The state
//! machine's only question about record ids is "same or different?" (a fork is
//! two *different* committed ids at one sequence), so equality is all it needs.
//!
//! ## Faithful image of the TLA+ actions
//!
//! * [`ChainStore::append_cas`] ⇔ `Append(expected, r)` — a compare-and-swap
//!   (OB-15, FROZEN §1.1). Commits **iff** the presented `expected` head is the
//!   current head (`expected = len`); a proposer that read an *earlier* head
//!   LOST the race and retries with **no state change** (§1.1 "a loser retries";
//!   the benign `expected < len` case). A proposer that names a head this spine
//!   *never had* (`expected > len`, an impossible read) is rejected outright.
//! * [`ChainStore::advance_checkpoint`] ⇔ `AdvanceCheckpoint` — the checkpoint
//!   may only rise, to the current committed length.
//! * [`ChainStore::accept_head`] ⇔ the §4 external monotonic anchor generalizing
//!   `AdvanceCheckpoint`: a presented head is accepted **only** if it is a
//!   forward extension of the *same spine* at strictly greater sequence — never
//!   a lower sequence, a different store, or a sibling.
//! * `UntrustedStep == UNCHANGED vars` is modelled by *absence of API*: no method
//!   can remove/rewrite a committed record or lower the checkpoint. An attacker
//!   with disk/network but no keys therefore cannot move the authority state —
//!   `untrusted_step_safe` holds by construction (§5).
//!
//! ## Invariants / properties this module upholds (⇔ TLA+ names)
//!
//! | TLA+ | statement | discharged by |
//! |---|---|---|
//! | `SpineFunctional` (OB-15) | one committed record per sequence — never overwritten | append only ever *extends* (prefix-preserving) |
//! | `NoRollback` (PO-2c) | `len >= checkpoint` always | checkpoint only rises to a length `<= len` |
//! | `CheckpointMono` (PO-2/2a) | the checkpoint never regresses | [`advance_checkpoint`]/[`accept_head`] only raise it |
//! | `LenMono` (OB-15) | committed length is monotone | nothing removes a committed record |
//! | `CASLoserBenign` (OB-15) | a lost/rejected CAS changes nothing | [`append_cas`] mutates only on `Committed` |
//!
//! As with [`super::authority`] and [`super::boundary`], the laws are discharged
//! in `#[cfg(test)]` by **exhaustive enumeration** over a small bounded domain —
//! here a breadth-first exploration of every reachable state with `len <= 4`
//! (the `StateBound` / `CeremonyStore.cfg` bound), the Rust analogue of TLC's
//! model check and of the Lean proofs' `by cases <;> decide`.

/// A content-addressed identifier of a store's genesis (`chain-store-profile.md`
/// §1, OB-6). **Opaque and abstract**: the inner token is a purely in-memory
/// model handle standing in for the real `store_id` — the concrete content-CID
/// byte layout is HELD until the P1/P2 conformance vectors freeze it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StoreId(u64);

/// The identifier of one authority thread within a store (`chain-store-profile.md`
/// §1). **Opaque and abstract**, exactly as [`StoreId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThreadId(u64);

/// A line-CID: the hash of a full at-rest record *including its signature*
/// (`chain-store-profile.md` §2 — what parents reference). **Opaque and
/// abstract**: it derives `Eq`/`Hash` but deliberately **no `Ord`** and exposes
/// no bytes, because the state machine observes only equality of record ids
/// (the Rust analogue of a TLC `RecordIds` model value). The real hash and its
/// byte layout are HELD (P1 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LineCid(u64);

impl StoreId {
    /// Wrap an **opaque, in-memory** model handle. The `u64` is NOT a wire
    /// encoding — it is a distinguishable-by-equality token, the analogue of a
    /// TLC model value. Provided so bounded tests can enumerate a finite pool of
    /// distinct ids the way TLC enumerates a model-value set.
    pub const fn from_model(token: u64) -> Self {
        StoreId(token)
    }
}

impl ThreadId {
    /// See [`StoreId::from_model`]. Opaque model handle, not a wire encoding.
    pub const fn from_model(token: u64) -> Self {
        ThreadId(token)
    }
}

impl LineCid {
    /// See [`StoreId::from_model`]. Opaque model handle, not a hash or encoding —
    /// the real line-CID (P1 §2) is HELD.
    pub const fn from_model(token: u64) -> Self {
        LineCid(token)
    }
}

/// The externally-protected anchor state (`chain-store-profile.md` §4·1). This
/// is the "highest `AuthorityCheckpoint` accepted per thread" a participant
/// carries *outside* the store — never "on disk beside the log" (§4). Fields
/// mirror the profile's struct exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorityCheckpoint {
    /// normative, cryptographically bound store identity (OB-6).
    pub store_id: StoreId,
    /// one causal authority thread within the store.
    pub thread_id: ThreadId,
    /// dense per-`(store_id, thread_id)` sequence (the head's position, = TLA `len`).
    pub sequence: u64,
    /// the accepted head at `sequence`.
    pub head: LineCid,
}

/// Outcome of [`ChainStore::append_cas`] — the three faithful readings of the
/// TLA+ `Append(expected, r)` transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppendOutcome {
    /// CAS **won** (`expected = len`): `next` is now the committed head at
    /// `sequence`. The spine grew by one; the checkpoint is UNCHANGED (mirrors
    /// `Append`'s `UNCHANGED checkpoint`).
    Committed { sequence: u64, head: LineCid },
    /// CAS **lost** a benign race: `expected` named a genuine *earlier* head of
    /// this spine (a shorter prefix) — a stale read (TLA `expected < len`).
    /// **No state change.** Retry against `current`. (§1.1: "an honest device
    /// that reads a head, proposes a successor, and loses the CAS is retrying,
    /// not attacking" — `CASLoserBenign`.)
    CasLost { current: Option<LineCid> },
    /// The proposal is **malformed** independent of any race: `expected` names a
    /// head this spine NEVER had (a foreign / longer-than-reality head, TLA
    /// `expected > len` — an impossible read). **No state change.** Do NOT retry;
    /// this is not a lost race.
    Rejected { current: Option<LineCid> },
}

/// Outcome of [`ChainStore::accept_head`] — the §4 forward-extension decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AcceptOutcome {
    /// The presented head forward-extends the same spine at a strictly greater
    /// sequence; the protected checkpoint advanced to `sequence`.
    Accepted { sequence: u64 },
    /// The presented head was refused; see [`Rejection`] for which §4 clause.
    Rejected(Rejection),
}

/// Why [`ChainStore::accept_head`] refused a presented head (`chain-store-profile.md`
/// §4·1: "never a lower `sequence`, a different store, or a sibling").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// "a different store" — `store_id` mismatch (a record cannot be replayed
    /// into a different store, P1 §4·5).
    DifferentStore,
    /// a sibling *thread* — `thread_id` mismatch.
    DifferentThread,
    /// "never a lower `sequence`" — the presented sequence is not strictly
    /// greater than the protected checkpoint (a stale or equal head = rollback).
    NotForward,
    /// "a sibling" — a genuine fork: a *different* head at a sequence this spine
    /// has already committed differently.
    Sibling,
    /// the presented sequence is beyond this store's committed spine, so the
    /// anchor cannot verify it as a forward extension (fail-closed: the P1
    /// segment verification needed to adopt a longer peer spine is HELD).
    BeyondSpine,
}

/// One authority thread's committed spine + externally-protected checkpoint —
/// the faithful executable image of `CeremonyStore.tla` (`store_id`/`thread_id`
/// fixed). Every mutator is grow-only or rise-only; there is deliberately **no**
/// operation that removes a committed record or lowers the checkpoint
/// (`untrusted_step_safe`, §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStore {
    store_id: StoreId,
    thread_id: ThreadId,
    /// the committed authority spine; `spine[i]` is the record at `sequence i+1`
    /// (TLA `spine`, a function `1..len -> RecordIds`).
    spine: Vec<LineCid>,
    /// the externally-protected highest accepted length (TLA `checkpoint`);
    /// `0` = genesis / nothing anchored yet.
    checkpoint: u64,
}

impl ChainStore {
    /// A fresh, empty thread (TLA `Init`: `len = 0`, `checkpoint = 0`,
    /// `spine = <<>>`).
    pub fn new(store_id: StoreId, thread_id: ThreadId) -> Self {
        ChainStore {
            store_id,
            thread_id,
            spine: Vec::new(),
            checkpoint: 0,
        }
    }

    /// this thread's store identity.
    pub fn store_id(&self) -> StoreId {
        self.store_id
    }

    /// this thread's identifier.
    pub fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    /// committed length (TLA `len`); `sequence` of the head.
    pub fn len(&self) -> u64 {
        self.spine.len() as u64
    }

    /// genesis / empty-thread predicate (`len() == 0`).
    pub fn is_empty(&self) -> bool {
        self.spine.is_empty()
    }

    /// the current committed head (`Some(spine[len])`, or `None` at genesis).
    pub fn head(&self) -> Option<LineCid> {
        self.spine.last().copied()
    }

    /// the externally-protected checkpoint length (TLA `checkpoint`).
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    /// the protected anchor as a full [`AuthorityCheckpoint`], or `None` if
    /// nothing is anchored yet (`checkpoint == 0`).
    pub fn protected_checkpoint(&self) -> Option<AuthorityCheckpoint> {
        let head = self.committed_head_at(self.checkpoint)?;
        Some(AuthorityCheckpoint {
            store_id: self.store_id,
            thread_id: self.thread_id,
            sequence: self.checkpoint,
            head,
        })
    }

    /// the committed head at a 1-based `sequence`, or `None` if out of range
    /// (`sequence == 0` or beyond the spine). Total and panic-free.
    fn committed_head_at(&self, sequence: u64) -> Option<LineCid> {
        if sequence == 0 {
            return None;
        }
        self.spine.get((sequence - 1) as usize).copied()
    }

    /// was `expected` a genuine *earlier* head of this spine (a shorter prefix)?
    /// The current head is handled by the caller before this is consulted, so a
    /// hit here means a benign stale read; a miss means a head this spine never
    /// had. (Line-CIDs are unique by P1 construction, so each spine entry was the
    /// head of exactly one prefix — the analogue of TLC's distinct `RecordIds`.)
    fn is_prior_head(&self, expected: Option<LineCid>) -> bool {
        match expected {
            // the empty head is a prior head iff we have since grown past it.
            None => !self.spine.is_empty(),
            Some(cid) => self.spine.contains(&cid),
        }
    }

    /// Compare-and-swap append (TLA `Append(expected, r)`, OB-15 FROZEN §1.1).
    ///
    /// `expected` is the head the proposer read (CAS on the head CID, which on a
    /// linear spine is equivalent to TLA's CAS on `len`). Commits `next` **iff**
    /// `expected` is still the current head. Otherwise the state is left
    /// **identical** and the outcome tells the caller how to react:
    /// [`AppendOutcome::CasLost`] (benign stale read — retry) vs
    /// [`AppendOutcome::Rejected`] (an impossible read — do not retry). Both
    /// non-committing arms uphold `CASLoserBenign`.
    pub fn append_cas(&mut self, expected: Option<LineCid>, next: LineCid) -> AppendOutcome {
        let current = self.head();
        if expected == current {
            // CAS success (`expected = len`): extend the spine by one. Only this
            // arm mutates — `LenMono` and `SpineFunctional` (prefix-preserving).
            self.spine.push(next);
            return AppendOutcome::Committed {
                sequence: self.len(),
                head: next,
            };
        }
        if self.is_prior_head(expected) {
            // `expected < len`: a real earlier head — the proposer lost the race.
            AppendOutcome::CasLost { current }
        } else {
            // `expected > len` / foreign: a head this spine never produced.
            AppendOutcome::Rejected { current }
        }
    }

    /// Advance the protected checkpoint to the current committed length (TLA
    /// `AdvanceCheckpoint`: enabled iff `checkpoint < len`, then
    /// `checkpoint' = len`). Returns whether it moved. The checkpoint can only
    /// **rise** and never exceeds `len`, so this preserves `CheckpointMono` and
    /// `NoRollback`.
    pub fn advance_checkpoint(&mut self) -> bool {
        if self.checkpoint < self.len() {
            self.checkpoint = self.len();
            true
        } else {
            false
        }
    }

    /// The §4 external monotonic anchor: accept a *presented* head only if it is
    /// a forward extension of the **same spine** at strictly greater sequence.
    ///
    /// This generalizes `AdvanceCheckpoint` with the profile's three refusals
    /// (§4·1): never a lower sequence, a different store, or a sibling. On accept
    /// the protected checkpoint advances to `presented.sequence`; every reject
    /// leaves state unchanged. Because acceptance requires the presented head to
    /// match this store's committed head at that sequence, the new checkpoint is
    /// always `<= len` — `NoRollback` is preserved.
    pub fn accept_head(&mut self, presented: &AuthorityCheckpoint) -> AcceptOutcome {
        if presented.store_id != self.store_id {
            return AcceptOutcome::Rejected(Rejection::DifferentStore);
        }
        if presented.thread_id != self.thread_id {
            return AcceptOutcome::Rejected(Rejection::DifferentThread);
        }
        // "never a lower `sequence`": must be strictly greater than the anchor.
        if presented.sequence <= self.checkpoint {
            return AcceptOutcome::Rejected(Rejection::NotForward);
        }
        match self.committed_head_at(presented.sequence) {
            // beyond what we hold — cannot verify as a forward extension.
            None => AcceptOutcome::Rejected(Rejection::BeyondSpine),
            // same spine, strictly greater sequence: a genuine forward extension.
            Some(cid) if cid == presented.head => {
                self.checkpoint = presented.sequence;
                AcceptOutcome::Accepted {
                    sequence: presented.sequence,
                }
            }
            // a different head at a sequence we committed differently — a fork.
            Some(_) => AcceptOutcome::Rejected(Rejection::Sibling),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Distinct model values — the Rust analogue of a small TLC `RecordIds` set.
    const S0: StoreId = StoreId::from_model(0);
    const S1: StoreId = StoreId::from_model(1);
    const T0: ThreadId = ThreadId::from_model(0);
    const T1: ThreadId = ThreadId::from_model(1);
    const A: LineCid = LineCid::from_model(1);
    const B: LineCid = LineCid::from_model(2);
    const C: LineCid = LineCid::from_model(3);
    const D: LineCid = LineCid::from_model(4);
    // A cid that is never committed on any test spine — a "foreign" head.
    const FOREIGN: LineCid = LineCid::from_model(99);

    /// Build a store at `(S0, T0)` with a preset committed spine + checkpoint.
    /// (Same-module test can touch private fields — the fixture the explorer
    /// materializes reachable states from.)
    fn store_with(spine: &[LineCid], checkpoint: u64) -> ChainStore {
        ChainStore {
            store_id: S0,
            thread_id: T0,
            spine: spine.to_vec(),
            checkpoint,
        }
    }

    /// A reachable state of the machine (TLA `<< spine, len, checkpoint >>`;
    /// `len` is `spine.len()`).
    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    struct St {
        spine: Vec<LineCid>,
        checkpoint: u64,
    }

    fn snapshot(cs: &ChainStore) -> St {
        St {
            spine: cs.spine.clone(),
            checkpoint: cs.checkpoint,
        }
    }

    fn is_prefix(a: &[LineCid], b: &[LineCid]) -> bool {
        a.len() <= b.len() && b[..a.len()] == *a
    }

    /// Breadth-first (here: depth-first over a work stack) exploration of EVERY
    /// reachable state with `len <= max_len`, driving the real `ChainStore` ops —
    /// the Rust analogue of TLC exploring `Spec` under `StateBound` (len =< 4).
    /// Returns the reachable states and every committing/advancing edge.
    fn reachable(pool: &[LineCid], max_len: u64) -> (HashSet<St>, Vec<(St, St)>) {
        let mut seen: HashSet<St> = HashSet::new();
        let mut edges: Vec<(St, St)> = Vec::new();
        let init = St {
            spine: Vec::new(),
            checkpoint: 0,
        };
        seen.insert(init.clone());
        let mut stack = vec![init];
        while let Some(s) = stack.pop() {
            // Append: for `expected = current head` (the CAS winner) and each r.
            if s.spine.len() as u64 > max_len {
                continue;
            }
            if (s.spine.len() as u64) < max_len {
                for &r in pool {
                    // Line-CIDs are unique by P1 construction (§2: the hash binds
                    // the parent link, so no committed record repeats) — the Rust
                    // analogue of TLC's *distinct* `RecordIds`. Only enumerate
                    // fresh cids, keeping the head-CID CAS unambiguous.
                    if s.spine.contains(&r) {
                        continue;
                    }
                    let mut cs = store_with(&s.spine, s.checkpoint);
                    let head = cs.head();
                    let out = cs.append_cas(head, r);
                    assert!(
                        matches!(out, AppendOutcome::Committed { .. }),
                        "expected == head must be a CAS winner"
                    );
                    let ns = snapshot(&cs);
                    edges.push((s.clone(), ns.clone()));
                    if seen.insert(ns.clone()) {
                        stack.push(ns);
                    }
                }
            }
            // AdvanceCheckpoint.
            {
                let mut cs = store_with(&s.spine, s.checkpoint);
                if cs.advance_checkpoint() {
                    let ns = snapshot(&cs);
                    edges.push((s.clone(), ns.clone()));
                    if seen.insert(ns.clone()) {
                        stack.push(ns);
                    }
                }
            }
            // accept_head (§4 anchor): present each of THIS spine's own committed
            // heads at a sequence strictly above the checkpoint — a genuine
            // forward extension is accepted and moves the checkpoint to that
            // sequence. This composes accept_head's checkpoint moves into the
            // reachable set (AdvanceCheckpoint only jumps to `len`), so the
            // invariant/monotonicity checks below cover all THREE transitions,
            // and exercises accept_head's ACCEPT path inside the reachability
            // proof (the isolated reject paths are covered by a separate test).
            {
                let probe = store_with(&s.spine, s.checkpoint);
                for seq in (s.checkpoint + 1)..=(s.spine.len() as u64) {
                    let Some(head) = probe.committed_head_at(seq) else {
                        continue;
                    };
                    let presented = AuthorityCheckpoint {
                        store_id: S0,
                        thread_id: T0,
                        sequence: seq,
                        head,
                    };
                    let mut cs = store_with(&s.spine, s.checkpoint);
                    if matches!(cs.accept_head(&presented), AcceptOutcome::Accepted { .. }) {
                        let ns = snapshot(&cs);
                        edges.push((s.clone(), ns.clone()));
                        if seen.insert(ns.clone()) {
                            stack.push(ns);
                        }
                    }
                }
            }
        }
        (seen, edges)
    }

    /// `SpineFunctional` (OB-15) + `NoRollback` (PO-2c) + `LenMono`/`CheckpointMono`
    /// over EVERY reachable state (`len <= 4`). Mirrors `THEOREM Spec => []Inv`
    /// and `Spec => (CheckpointMono /\ LenMono)`.
    ///
    /// Guards: were `append_cas` ever to overwrite a committed sequence, the
    /// prefix check would FAIL (`SpineFunctional`); were the checkpoint ever set
    /// above `len` the NoRollback check would FAIL; were any edge to shrink `len`
    /// or lower the checkpoint the mono checks would FAIL.
    #[test]
    fn reachable_states_uphold_invariants_and_monotonicity() {
        let (states, edges) = reachable(&[A, B, C, D], 4);
        for s in &states {
            // NoRollback (PO-2c): len >= checkpoint.
            assert!(
                s.spine.len() as u64 >= s.checkpoint,
                "NoRollback violated: checkpoint {} > len {}",
                s.checkpoint,
                s.spine.len()
            );
            // SpineFunctional (OB-15): the spine is a total function on
            // 1..=len and undefined outside — one committed record per sequence.
            let cs = store_with(&s.spine, s.checkpoint);
            for seq in 1..=s.spine.len() as u64 {
                assert!(
                    cs.committed_head_at(seq).is_some(),
                    "seq in range is defined"
                );
            }
            assert!(cs.committed_head_at(0).is_none(), "seq 0 is undefined");
            assert!(
                cs.committed_head_at(s.spine.len() as u64 + 1).is_none(),
                "seq beyond len is undefined"
            );
        }
        for (from, to) in &edges {
            // LenMono (OB-15): committed length never shrinks.
            assert!(to.spine.len() >= from.spine.len(), "LenMono violated");
            // CheckpointMono (PO-2/2a): the checkpoint never regresses.
            assert!(to.checkpoint >= from.checkpoint, "CheckpointMono violated");
            // SpineFunctional (OB-15): no committed record is ever rewritten —
            // the predecessor spine is a prefix of the successor spine.
            assert!(
                is_prefix(&from.spine, &to.spine),
                "SpineFunctional violated: a committed record was overwritten"
            );
        }
        // sanity: the exploration actually reached non-trivial states.
        assert!(states.len() > 1);
    }

    /// `CASLoserBenign` (OB-15): a lost CAS (stale-but-real head) and a rejected
    /// CAS (foreign head) both leave the state **byte-identical**. Exhaustive
    /// over every reachable state.
    ///
    /// Guards: if either non-committing arm mutated the spine or checkpoint, the
    /// `assert_eq!(before, after)` would FAIL — the exact bug §1.1 warns against
    /// (treating a benign CAS-loser as if it changed committed history).
    #[test]
    fn cas_loser_and_reject_leave_state_identical() {
        let (states, _) = reachable(&[A, B, C, D], 4);
        for s in &states {
            // stale reads that name a REAL earlier head -> CasLost, no change.
            let mut stale: Vec<Option<LineCid>> = Vec::new();
            if !s.spine.is_empty() {
                stale.push(None); // read the empty head after we grew.
                for &cid in &s.spine[..s.spine.len() - 1] {
                    stale.push(Some(cid)); // any earlier (non-head) committed head.
                }
            }
            for &expected in &stale {
                let mut cs = store_with(&s.spine, s.checkpoint);
                let before = snapshot(&cs);
                let out = cs.append_cas(expected, A);
                assert!(
                    matches!(out, AppendOutcome::CasLost { .. }),
                    "a real earlier head must lose the CAS, not commit/reject"
                );
                assert_eq!(
                    before,
                    snapshot(&cs),
                    "CASLoserBenign: CasLost mutated state"
                );
            }

            // a head this spine NEVER had -> Rejected, no change.
            let foreign = if s.spine.is_empty() {
                Some(A) // claims a head while at genesis: impossible read.
            } else {
                Some(FOREIGN)
            };
            let mut cs = store_with(&s.spine, s.checkpoint);
            let before = snapshot(&cs);
            let out = cs.append_cas(foreign, A);
            assert!(
                matches!(out, AppendOutcome::Rejected { .. }),
                "a foreign head must be Rejected"
            );
            assert_eq!(
                before,
                snapshot(&cs),
                "CASLoserBenign: Rejected mutated state"
            );
        }
    }

    /// The CAS winner (TLA `Append`, `expected = len`): commits, grows `len` by
    /// exactly one, preserves the prefix (`SpineFunctional`), and leaves the
    /// checkpoint UNCHANGED (`Append`'s `UNCHANGED checkpoint`).
    ///
    /// Guards: a commit that jumped `len` by !=1, dropped the prefix, or touched
    /// the checkpoint would FAIL here.
    #[test]
    fn committed_cas_extends_by_exactly_one() {
        let (states, _) = reachable(&[A, B, C, D], 4);
        for s in &states {
            if s.spine.len() as u64 >= 4 {
                continue;
            }
            for &next in &[A, B, C, D] {
                // fresh line-CID (P1 §2 uniqueness), as in the explorer.
                if s.spine.contains(&next) {
                    continue;
                }
                let mut cs = store_with(&s.spine, s.checkpoint);
                let head = cs.head();
                let out = cs.append_cas(head, next);
                assert_eq!(
                    out,
                    AppendOutcome::Committed {
                        sequence: s.spine.len() as u64 + 1,
                        head: next,
                    }
                );
                assert_eq!(cs.len(), s.spine.len() as u64 + 1, "len grows by one");
                assert!(is_prefix(&s.spine, &cs.spine), "prefix preserved");
                assert_eq!(cs.head(), Some(next));
                assert_eq!(
                    cs.checkpoint(),
                    s.checkpoint,
                    "Append leaves checkpoint UNCHANGED"
                );
            }
        }
    }

    /// `AdvanceCheckpoint` + `CheckpointMono` + `NoRollback`: the checkpoint rises
    /// to `len`, never regresses, never exceeds `len`, and re-advancing is a
    /// no-op. Exhaustive over spines of length 0..=3 and every legal checkpoint.
    ///
    /// Guards: a checkpoint set above `len`, or a second advance that moved it,
    /// or a regression, would FAIL.
    #[test]
    fn advance_checkpoint_rises_to_len_and_is_idempotent() {
        let spines: [&[LineCid]; 4] = [&[], &[A], &[A, B], &[A, B, C]];
        for spine in spines {
            let len = spine.len() as u64;
            for cp in 0..=len {
                let mut cs = store_with(spine, cp);
                let moved = cs.advance_checkpoint();
                assert_eq!(moved, cp < len, "advance enabled iff checkpoint < len");
                assert_eq!(cs.checkpoint(), len, "checkpoint rises to len");
                assert!(cs.checkpoint() >= cp, "CheckpointMono");
                assert!(cs.checkpoint() <= cs.len(), "NoRollback: checkpoint <= len");
                // idempotent: a second advance cannot move it further.
                let again = cs.advance_checkpoint();
                assert!(!again, "re-advancing at the head is a no-op");
                assert_eq!(cs.checkpoint(), len);
            }
        }
    }

    /// The §4 forward-extension rule (`accept_head`): a presented head is accepted
    /// iff it is a forward extension of the SAME spine at strictly greater
    /// sequence — and rejected for a lower/equal sequence, a sibling head, a
    /// different store, a different thread, or a sequence beyond the spine.
    /// Exhaustive over store × thread × sequence × head, for every checkpoint.
    ///
    /// Guards: accepting a rollback (lower/equal seq), a fork (sibling head), a
    /// replay into another store, or a head we cannot anchor would each FAIL —
    /// the compared oracle re-derives the §4 verdict independently.
    #[test]
    fn accept_head_is_forward_extension_only() {
        let spine = [A, B, C]; // committed heads: A@1, B@2, C@3.
        for cp in 0..=spine.len() as u64 {
            for &store in &[S0, S1] {
                for &thread in &[T0, T1] {
                    for seq in 0..=4u64 {
                        for &head in &[A, B, C, FOREIGN] {
                            let presented = AuthorityCheckpoint {
                                store_id: store,
                                thread_id: thread,
                                sequence: seq,
                                head,
                            };
                            let mut cs = store_with(&spine, cp);
                            let got = cs.accept_head(&presented);

                            // Independent oracle for the §4 verdict.
                            let matching_at_seq = match seq {
                                1 => Some(A),
                                2 => Some(B),
                                3 => Some(C),
                                _ => None, // 0 or beyond the length-3 spine.
                            };
                            let want = if store != S0 {
                                AcceptOutcome::Rejected(Rejection::DifferentStore)
                            } else if thread != T0 {
                                AcceptOutcome::Rejected(Rejection::DifferentThread)
                            } else if seq <= cp {
                                AcceptOutcome::Rejected(Rejection::NotForward)
                            } else {
                                match matching_at_seq {
                                    None => AcceptOutcome::Rejected(Rejection::BeyondSpine),
                                    Some(expected) if expected == head => {
                                        AcceptOutcome::Accepted { sequence: seq }
                                    }
                                    Some(_) => AcceptOutcome::Rejected(Rejection::Sibling),
                                }
                            };
                            assert_eq!(
                                got, want,
                                "accept_head verdict for {presented:?} at cp={cp}"
                            );

                            // On accept the checkpoint advanced to seq; else unchanged.
                            match got {
                                AcceptOutcome::Accepted { sequence } => {
                                    assert_eq!(cs.checkpoint(), sequence);
                                    assert!(sequence > cp, "accepted head is strictly forward");
                                }
                                AcceptOutcome::Rejected(_) => {
                                    assert_eq!(cs.checkpoint(), cp, "reject leaves checkpoint put");
                                }
                            }
                            // NoRollback + CheckpointMono hold across accept_head.
                            assert!(cs.checkpoint() <= cs.len(), "NoRollback");
                            assert!(cs.checkpoint() >= cp, "CheckpointMono");
                        }
                    }
                }
            }
        }
    }

    /// A concrete end-to-end trace tying it together: genesis grows by CAS, a
    /// stale proposer loses benignly, the checkpoint anchors forward, and a
    /// sibling / rollback head is refused. (A narrative complement to the
    /// exhaustive laws above.)
    #[test]
    fn end_to_end_append_anchor_and_refuse() {
        let mut cs = ChainStore::new(S0, T0);
        assert_eq!(cs.head(), None);

        // genesis append (expected empty head).
        assert_eq!(
            cs.append_cas(None, A),
            AppendOutcome::Committed {
                sequence: 1,
                head: A
            }
        );
        assert_eq!(
            cs.append_cas(Some(A), B),
            AppendOutcome::Committed {
                sequence: 2,
                head: B
            }
        );

        // a proposer that still thinks the head is A loses the race, benignly.
        let before = snapshot(&cs);
        assert_eq!(
            cs.append_cas(Some(A), C),
            AppendOutcome::CasLost { current: Some(B) }
        );
        assert_eq!(before, snapshot(&cs), "CAS-loser changed nothing");

        // anchor the head forward via the external rule.
        let anchor = AuthorityCheckpoint {
            store_id: S0,
            thread_id: T0,
            sequence: 2,
            head: B,
        };
        assert_eq!(
            cs.accept_head(&anchor),
            AcceptOutcome::Accepted { sequence: 2 }
        );
        assert_eq!(cs.protected_checkpoint(), Some(anchor));

        // a rollback to an older head is refused (NotForward).
        let rollback = AuthorityCheckpoint {
            store_id: S0,
            thread_id: T0,
            sequence: 1,
            head: A,
        };
        assert_eq!(
            cs.accept_head(&rollback),
            AcceptOutcome::Rejected(Rejection::NotForward)
        );
        // a sibling (fork) at a fresh sequence is refused (Sibling).
        let sibling = AuthorityCheckpoint {
            store_id: S0,
            thread_id: T0,
            sequence: 2,
            head: C, // we committed B@2, not C.
        };
        // seq 2 == checkpoint now, so this is NotForward first; push checkpoint back
        // by testing a store whose checkpoint is lower to isolate the Sibling arm.
        let mut cs2 = store_with(&[A, B], 0);
        assert_eq!(
            cs2.accept_head(&sibling),
            AcceptOutcome::Rejected(Rejection::Sibling)
        );
        // NoRollback held throughout.
        assert!(cs.checkpoint() <= cs.len());
    }
}
