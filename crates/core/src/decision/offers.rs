//! PD-70: a write preview's deny offers. Whether a kind is offered is decided by the function that
//! builds the hint a deny attaches (`hint_for`), so the UI offers exactly the details
//! `decide(Deny, details)` accepts for this revision and nothing else. Core still checks every
//! decision (unchanged path).

use atlas_duck_preview::{DenyOffer, DenyOfferKind};

use super::{DenyDetails, hint_for};
use crate::engine::write::WriteState;
use crate::lifecycle::model::Hold;

/// The kinds in the order the UI lists them, each as the `DenyDetails` it stands for.
const KINDS: [(DenyOfferKind, DenyDetails); 4] = [
    (
        DenyOfferKind::UpstreamHttp,
        DenyDetails::UpstreamHttp {
            include_messages: false,
        },
    ),
    (DenyOfferKind::OutcomeHint, DenyDetails::OutcomeHint),
    (
        DenyOfferKind::ResolutionFailed,
        DenyDetails::ResolutionFailed {
            include_candidates: false,
        },
    ),
    (
        DenyOfferKind::MissingFields,
        DenyDetails::MissingFields {
            include_allowed_values: false,
        },
    ),
];

/// The kinds `hint_for` accepts for `w` in `hold`, each with whether its optional part (the
/// upstream messages, the candidates, the allowed values) has anything to include.
pub(super) fn deny_offers(op_id: &str, w: &WriteState, hold: Option<Hold>) -> Vec<DenyOffer> {
    KINDS
        .iter()
        .filter(|(_, details)| hint_for(op_id, w, hold, *details).is_ok())
        .map(|&(kind, _)| DenyOffer {
            kind,
            has_optional_detail: optional_detail(kind, w),
        })
        .collect()
}

fn optional_detail(kind: DenyOfferKind, w: &WriteState) -> bool {
    match kind {
        DenyOfferKind::UpstreamHttp => w.failure.as_ref().is_some_and(|f| !f.card.text.is_empty()),
        DenyOfferKind::OutcomeHint => false,
        DenyOfferKind::ResolutionFailed => w
            .verdict
            .unresolved
            .as_ref()
            .is_some_and(|(_, _, _, candidates)| !candidates.is_empty()),
        DenyOfferKind::MissingFields => w
            .verdict
            .missing_fields
            .iter()
            .any(|f| !f.allowed_values.is_empty()),
    }
}
