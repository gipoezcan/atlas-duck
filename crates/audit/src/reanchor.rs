//! "Re-anchor" (§8.7, PD-170, M2 handoff T15): a keychain anchor entry was lost (deleted by a
//! user, a keychain cleanup) while the KEK still opens the store, so neither recovery nor `open`
//! repairs it and every start reports `anchor_missing`. After the native confirmation the anchors
//! are rewritten from the store, but only from a store that verifies, and never silently: the
//! rewrite is its own integrity incident (`VERIFY {result: re_anchored}`, acknowledged like any
//! other). Offered only while `StoreHealth.anchors_missing` is `Some`, which an interrupted
//! restore never is (its missing or foreign head anchor is the restore's to reset).

use crate::anchors::{self, AnchorLoadError, BarrierGuard, FirstRetainedAnchor, HeadAnchor};
use crate::encoding::ZERO_HASH;
use crate::error::AuditError;
use crate::store::Store;
use crate::types::{Committed, Confirmed};
use crate::verify::{self, FindingKind, VerifyFinding};

/// `Invalid` text of `Store::re_anchor`: no keychain anchor entry is missing.
pub const RE_ANCHOR_NOTHING_MISSING: &str =
    "no keychain anchor is missing: there is nothing to re-anchor";
/// `Invalid` text of `Store::re_anchor`: a prune's or restore's anchor update holds the anchors.
pub const RE_ANCHOR_HELD: &str =
    "an anchor update of a prune or restore is pending: re-anchor is not possible now";
/// `Invalid` text of `Store::re_anchor`: the store has another incident (the run is logged).
pub const RE_ANCHOR_DOES_NOT_VERIFY: &str =
    "the store does not verify, so it is not re-anchored (the verification is logged)";
/// `Invalid` text of `Store::re_anchor`: a restore replaced the store while it ran.
pub const RE_ANCHOR_RESTORED: &str = "the store was restored meanwhile: nothing was re-anchored";

/// `Store::re_anchor`.
pub(crate) fn re_anchor(store: &Store, confirmed: Confirmed) -> Result<Committed, AuditError> {
    store.ensure_open()?;
    let health = store.health();
    if health.anchors_missing.is_none() {
        return Err(AuditError::Invalid(RE_ANCHOR_NOTHING_MISSING));
    }
    if health.anchors_blocked.is_some() {
        return Err(AuditError::Invalid(RE_ANCHOR_HELD));
    }
    let generation = store.generation();
    // From here the anchors are held still: no head write, and no prune (the one barrier slot is
    // taken), so the verified store and the keychain stay as the verification saw them. The
    // barrier is this call's own: only its completion or its guard (dropped on every path) lift
    // it, and a restore that takes the slot meanwhile keeps its own barrier.
    let (seq, _, _) = store.head();
    let guard = store.install_rewrite_barrier(seq)?;
    verified_rewrite(store, &guard, &confirmed, generation)
}

/// The full verification, the `re_anchored` incident, then both anchors from the store.
fn verified_rewrite(
    store: &Store,
    guard: &BarrierGuard,
    confirmed: &Confirmed,
    generation: u64,
) -> Result<Committed, AuditError> {
    let (findings, verified) = store.run_full_verify()?;
    if verified != generation {
        return Err(AuditError::Invalid(RE_ANCHOR_RESTORED));
    }
    #[cfg(any(test, feature = "testing"))]
    store.fault(crate::testing::FaultPoint::ReAnchorVerified)?;
    // Rewriting the anchors of a store with any other incident would launder it: the run is
    // logged as the full verification it is, and nothing is rewritten.
    if findings
        .iter()
        .any(|f| f.kind.is_incident() && f.kind != FindingKind::AnchorMissing)
    {
        store.append_full_verify(&findings, generation)?;
        return Err(AuditError::Invalid(RE_ANCHOR_DOES_NOT_VERIFY));
    }
    if !findings
        .iter()
        .any(|f| f.kind == FindingKind::AnchorMissing)
    {
        // Both entries are back (restored from a keychain backup, say).
        store.note_anchors_present();
        return Err(AuditError::Invalid(RE_ANCHOR_NOTHING_MISSING));
    }
    // The first-retained values, read before anything is logged: an error here refuses with
    // nothing logged or written.
    let first_retained = first_retained_values(store)?;
    // `re_anchored` first: it is the record's `result` (F.11).
    let mut out = vec![VerifyFinding::new(
        FindingKind::ReAnchored,
        "the keychain anchors were rewritten from the verified store",
    )];
    out.extend(findings);
    let verify = store.verify_event("re_anchor", &out, None, Some(confirmed))?;
    let c = store.append_for_generation(verify, generation)?;

    let (seq, record_hash, chain_id) = store.head();
    #[cfg(any(test, feature = "testing"))]
    store.fault(crate::testing::FaultPoint::ReAnchorBeforeComplete)?;
    // A restore that committed since the incident replaced the store these anchors describe.
    // This narrows the window; the completion's owner check closes it (a restore takes the
    // barrier before its commit, and the completion then refuses).
    if store.generation() != generation || chain_id != first_retained.chain_id {
        return Err(AuditError::Invalid(RE_ANCHOR_RESTORED));
    }
    store.complete_restore_anchors(
        guard,
        HeadAnchor {
            chain_id,
            seq,
            record_hash,
        },
        first_retained,
    )?;
    Ok(c)
}

/// The first-retained entry to write, as "Recover this log" rebuilds it (`recover.rs`): the
/// latest `prune_log` row's values; the genesis hash of the retained `GENESIS`, else of a
/// surviving first-retained entry of this chain (verified with the store above), else zero
/// (informational once `GENESIS` is pruned and every entry naming it is lost). A failed read
/// of that entry is an error, never zero: a present entry must not lose its genesis hash.
fn first_retained_values(store: &Store) -> Result<FirstRetainedAnchor, AuditError> {
    let (_, _, chain_id) = store.head();
    let (first_retained_seq, first_retained_prev_hash, genesis) = store.with_reader(|conn| {
        let io = |e: rusqlite::Error| AuditError::Io(e.to_string());
        let (frs, last) = verify::latest_prune_values(conn).map_err(io)?;
        Ok((frs, last, verify::retained_genesis_hash(conn).map_err(io)?))
    })?;
    let genesis_hash = match genesis {
        Some(g) => g,
        None => match anchors::load_first_retained(store.keystore()) {
            Ok(entry) => entry
                .filter(|f| f.chain_id == chain_id)
                .map_or(ZERO_HASH, |f| f.genesis_hash),
            Err(AnchorLoadError::KeyStore(e)) => return Err(AuditError::KeyStore(e)),
            Err(AnchorLoadError::Newer(n)) => {
                return Err(AuditError::Io(format!(
                    "the keychain first-retained anchor has the newer layout {n}"
                )));
            }
        },
    };
    Ok(FirstRetainedAnchor {
        chain_id,
        genesis_hash,
        first_retained_seq,
        first_retained_prev_hash,
    })
}
