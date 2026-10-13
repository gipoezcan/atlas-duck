//! storage→markdown, markdown→wiki, markdown→storage, wiki→preview-html (§2.2).
//!
//! Pure functions over strings; depends on no workspace crate and does no I/O.
//! `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod escape;
mod hard_check;
mod md_to_wiki;
pub mod wiki;
mod wiki_html;
mod wiki_text;

pub use hard_check::{Unrecorded, hard_check_wiki};
pub use md_to_wiki::{ContainerKind, EmittedCode, EmittedConstructs, markdown_to_wiki};
pub use wiki::{CodeKind, ConstructKind, WikiConstructs, wiki_constructs};
pub use wiki_html::wiki_to_preview_html;
pub use wiki_text::wiki_to_text;
