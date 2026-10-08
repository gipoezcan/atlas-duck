//! Confluence operation specs (§7.4), one `pub(crate) const` per op, listed once in `lib.rs`.

use crate::RELEASE_CAP_BYTES;
use crate::model::{Caps, RedactionRules, StatusSet, SuccessBody, SuccessShape};

pub(crate) mod reads;
mod schemas;
pub(crate) mod writes;

pub(crate) const NO_CAPS: Caps = Caps {
    max: None,
    move_limit: None,
    comments_cap: None,
    upload_max_bytes: None,
    static_result_cap_bytes: RELEASE_CAP_BYTES,
};

pub(crate) const NO_REDACTION: RedactionRules = RedactionRules {
    copies: &[],
    mirrors: &[],
    url_fields: &[],
};

pub(crate) const DEFAULT_SUCCESS: SuccessShape = SuccessShape {
    statuses: StatusSet::Any2xx,
    body: SuccessBody::Json,
};

/// §7.2: declared empty success of `confluence.label.remove`.
pub(crate) const EMPTY_204: SuccessShape = SuccessShape {
    statuses: StatusSet::Exactly(&[204]),
    body: SuccessBody::Empty,
};

/// §4.2: the Confluence write receipt.
pub(crate) const RECEIPT_FIELDS: &[&str] =
    &["id", "type", "status", "version.number", "_links.webui"];
