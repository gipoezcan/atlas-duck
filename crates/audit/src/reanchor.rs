//! "Re-anchor" (§8.7, PD-170, M2 handoff T15): a keychain anchor entry was lost (deleted by a
//! user, a keychain cleanup) while the KEK still opens the store, so neither recovery nor `open`
//! repairs it and every start reports `anchor_missing`. After the native confirmation the anchors
//! are rewritten from the store, but only from a store that verifies, and never silently: the
//! rewrite is its own integrity incident (`VERIFY {result: re_anchored}`, acknowledged like any
//! other). Offered only while `StoreHealth.anchors_missing` is `Some`, which an interrupted
//! restore never is (its missing or foreign head anchor is the restore's to reset).

use crate::anchors::{self, Barrier, BarrierGuard, FirstRetainedAnchor, HeadAnchor};
use crate::encoding::ZERO_HASH;
use crate::error::AuditError;
use crate::store::Store;
use crate::types::{Committed, Confirmed};
use crate::verify::{self, FindingKind, VerifyFinding};

const NOTHING_MISSING: &str = "no keychain anchor is missing: there is nothing to re-anchor";
const ANCHORS_HELD: &str =
    "an anchor update of a prune or restore is pending: re-anchor is not possible now";
const DOES_NOT_VERIFY: &str =
    "the store does not verify, so it is not re-anchored (the verification is logged)";
const RESTORED: &str = "the store was restored meanwhile: nothing was re-anchored";

/// `Store::re_anchor`.
pub(crate) fn re_anchor(store: &Store, confirmed: Confirmed) -> Result<Committed, AuditError> {
    store.ensure_open()?;
    let health = store.health();
    if health.anchors_missing.is_none() {
        return Err(AuditError::Invalid(NOTHING_MISSING));
    }
    if health.anchors_blocked.is_some() {
        return Err(AuditError::Invalid(ANCHORS_HELD));
    }
    let generation = store.generation();
    // From here the anchors are held still: no head write, and no prune (the one barrier slot is
    // taken), so the verified store and the keychain stay as the verification saw them.
    let (seq, _, _) = store.head();
    let guard = store.install_barrier(Barrier::Restore { seq, reset: None })?;
    match verified_rewrite(store, &confirmed, generation) {
        // The anchor thread lifted the barrier with the write.
        Ok(c) => {
            guard.complete();
            Ok(c)
        }
        Err(e) => {
            release(guard, store, generation);
            Err(e)
        }
    }
}

/// Lifts the barrier, unless a restore replaced the store since: its own barrier then holds the
/// slot (it swapped ours out) and is not ours to lift.
fn release(guard: BarrierGuard, store: &Store, generation: u64) {
    if store.generation() == generation {
        drop(guard);
    } else {
        guard.complete();
    }
}

/// The full verification, the `re_anchored` incident, then both anchors from the store.
fn verified_rewrite(
    store: &Store,
    confirmed: &Confirmed,
    generation: u64,
) -> Result<Committed, AuditError> {
    let (findings, verified) = store.run_full_verify()?;
    if verified != generation {
        return Err(AuditError::Invalid(RESTORED));
    }
    // Rewriting the anchors of a store with any other incident would launder it: the run is
    // logged as the full verification it is, and nothing is rewritten.
    if findings
        .iter()
        .any(|f| f.kind.is_incident() && f.kind != FindingKind::AnchorMissing)
    {
        store.append_full_verify(&findings, generation)?;
        return Err(AuditError::Invalid(DOES_NOT_VERIFY));
    }
    if !findings
        .iter()
        .any(|f| f.kind == FindingKind::AnchorMissing)
    {
        // Both entries are back (restored from a keychain backup, say).
        store.note_anchors_present();
        return Err(AuditError::Invalid(NOTHING_MISSING));
    }
    // `re_anchored` first: it is the record's `result` (F.11).
    let mut out = vec![VerifyFinding::new(
        FindingKind::ReAnchored,
        "the keychain anchors were rewritten from the verified store",
    )];
    out.extend(findings);
    let verify = store.verify_event("re_anchor", &out, None, Some(confirmed))?;
    let c = store.append_for_generation(verify, generation)?;

    // As "Recover this log" rebuilds them (`recover.rs`): the latest `prune_log` row's values,
    // the retained `GENESIS`, else a surviving first-retained entry of this chain (verified
    // above), else zero (informational once `GENESIS` is pruned).
    let (_, _, chain_id) = store.head();
    let (first_retained_seq, first_retained_prev_hash, genesis) = store.with_reader(|conn| {
        let io = |e: rusqlite::Error| AuditError::Io(e.to_string());
        let (frs, last) = verify::latest_prune_values(conn).map_err(io)?;
        Ok((frs, last, verify::retained_genesis_hash(conn).map_err(io)?))
    })?;
    let genesis_hash = match genesis {
        Some(g) => g,
        None => anchors::load_first_retained(store.keystore())
            .ok()
            .flatten()
            .filter(|f| f.chain_id == chain_id)
            .map_or(ZERO_HASH, |f| f.genesis_hash),
    };
    let (seq, record_hash, chain_id) = store.head();
    store.complete_restore_anchors(
        HeadAnchor {
            chain_id: chain_id.clone(),
            seq,
            record_hash,
        },
        FirstRetainedAnchor {
            chain_id,
            genesis_hash,
            first_retained_seq,
            first_retained_prev_hash,
        },
    )?;
    Ok(c)
}
