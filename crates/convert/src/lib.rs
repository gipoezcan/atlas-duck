//! storage→markdown, markdown→wiki, markdown→storage, wiki→preview-html (§2.2).
//!
//! Pure functions over strings; depends on no workspace crate and does no I/O.
//! `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod escape;
mod hard_check;
mod md_to_storage;
mod md_to_wiki;
mod placeholders;
pub mod storage;
pub mod wiki;
mod wiki_html;
mod wiki_text;
mod xml_escape;

pub use hard_check::{Unrecorded, hard_check_wiki};
pub use md_to_storage::markdown_to_storage;
pub use md_to_wiki::{ContainerKind, EmittedCode, EmittedConstructs, markdown_to_wiki};
pub use placeholders::{PlaceholderHit, PlaceholderKind, check_markdown_placeholders};
pub use storage::{
    ConversionReport, LostCounts, StorageReject, StorageUsers, UserResolutions, check_storage_body,
    hard_check_storage, storage_constructs, storage_to_markdown, storage_user_refs,
};
pub use wiki::{CodeKind, ConstructKind, WikiConstructs, wiki_constructs};
pub use wiki_html::wiki_to_preview_html;
pub use wiki_text::wiki_to_text;
