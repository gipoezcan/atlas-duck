//! Preview model builders per operation (§2.2).

mod json_tree;
mod model;
mod sanitize;
pub mod warning;

pub use json_tree::{JSON_STRING_COLLAPSE_BYTES, JsonNode, json_tree};
pub use model::{
    BodyView, CandidateRev, ERROR_TEXT_CAP_BYTES, ItemCount, OutcomeKind, PREVIEW_BUILDER_VERSION,
    Preview, PreviewBody, PreviewHeader, RAW_PAGE_BYTES, RawPager, RequestView, cap_error_text,
};
pub use sanitize::{Platform, app_origin, iframe_document, sanitize_html};
pub use warning::{Level, Warning, WarningId};
