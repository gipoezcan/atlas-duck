//! storage→markdown, markdown→wiki, markdown→storage, wiki→preview-html (§2.2).
//!
//! Pure functions over strings; depends on no workspace crate and does no I/O.
//! `clippy::unwrap_used` and `clippy::expect_used` are errors here (§7.7).

#![deny(clippy::unwrap_used, clippy::expect_used)]
