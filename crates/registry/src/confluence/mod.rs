//! Confluence operation specs (§7.4), one `pub(crate) const` per op, listed once in `lib.rs`.

use crate::model::OperationSpec;

#[allow(dead_code)] // the catalog (Task 4) replaces this empty table with one const per op
pub(crate) const SPECS: &[OperationSpec] = &[];
