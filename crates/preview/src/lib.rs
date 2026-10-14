//! Preview model builders per operation (§2.2).

pub mod diff;
pub mod form;
pub mod invisible;
mod json_tree;
pub mod mixed_script;
mod model;
pub mod render;
mod sanitize;
pub mod warning;

pub use json_tree::{JSON_STRING_COLLAPSE_BYTES, JsonNode, json_tree};
pub use model::{
    BodyView, CandidateRev, CommentView, ConstructList, DenyOffer, DenyOfferKind,
    ERROR_TEXT_CAP_BYTES, FieldRow, IssueCard, ItemCount, OutcomeKind, PREVIEW_BUILDER_VERSION,
    Preview, PreviewBody, PreviewHeader, RAW_PAGE_BYTES, RENDER_VERSIONS, RawPager, RequestView,
    cap_error_text,
};
pub use sanitize::{Platform, app_origin, iframe_document, sanitize_html};
pub use warning::{Level, Warning, WarningId};
