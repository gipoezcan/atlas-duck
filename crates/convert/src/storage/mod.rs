//! Confluence storage format (spec §7.6, plan PD-94..PD-97).
//!
//! One parser ([`parse`]) is the ground truth for everything that reads storage: the construct
//! inventory a write preview lists, the user references core resolves, the static check of an
//! agent-supplied storage body, the conversion to Markdown ([`storage_to_markdown`]) and (later
//! tasks) the hard check and the lossy count. Sibling modules reach the lexical fallback scan as
//! `parse::lexical_constructs`.

mod parse;
mod to_md;

pub use parse::{
    Element, MAX_DEPTH, Node, Ns, StorageDoc, StorageReject, StorageUsers, check_storage_body,
    construct_spans, parse, storage_constructs, storage_user_refs,
};
pub use to_md::{ConversionReport, KNOWN_MACROS, LostCounts, UserResolutions, storage_to_markdown};
