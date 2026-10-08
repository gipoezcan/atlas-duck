//! The preview base model (C.6): what core hands to the approvals UI (§6.1, §6.3).

use serde::{Deserialize, Serialize};

use crate::json_tree::JsonNode;
use crate::warning::Warning;

/// Size of one Raw page; the bytes themselves stay in core (C.7 `RawPage`).
pub const RAW_PAGE_BYTES: u64 = 256 * 1024;

/// Task 6 replaces this with the value that includes the Unicode/emoji table versions (§6.4, §8.3).
pub const PREVIEW_BUILDER_VERSION: &str = "pb1+unicode-pending";

/// `UpstreamError.error_messages_text` cap (bytes, including the trailing ellipsis).
pub const ERROR_TEXT_CAP_BYTES: usize = 2048;

/// Revision of a candidate: `counter` increments on every change; the hash is SHA-256 over the
/// candidate (computed in core, which re-exports this type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateRev {
    pub counter: u64,
    #[serde(with = "hex32")]
    pub candidate_hash: [u8; 32],
}

/// Lowercase hex of exactly 32 bytes; anything else (uppercase, wrong length) is rejected.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(D::Error::custom("hash must be lowercase hex"));
        }
        hex::decode(&s)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("hash must be 32 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preview {
    pub candidate_rev: CandidateRev,
    pub approvable: bool,
    pub header: PreviewHeader,
    pub warnings: Vec<Warning>,
    pub body: PreviewBody,
    pub raw: RawPager,
    pub also_appears_in: Vec<String>,
    pub preview_builder_version: String,
}

/// §6.1 item 3 plus the classifier counts (§6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewHeader {
    pub instance_alias: String,
    pub op_id: String,
    pub class: String,
    pub item_count: Option<ItemCount>,
    pub byte_size: u64,
    pub fields_included: Vec<String>,
    pub hidden_in_preview_bytes: u64,
    pub bidi_controls: u64,
    pub other_invisible: u64,
    pub executes_as: Option<String>,
    pub receipt_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ItemCount {
    pub shown: u64,
    /// `None` when the server reports no total ("N shown, more available").
    pub total: Option<u64>,
    pub more_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    ReleaseCap16,
    ResponseCap32,
    FetchCap50,
    ReadBudget120,
    PerCallTimeout30,
    NetworkAfterSend,
    JsonBodyUnreadable,
}

/// A request body as shown in the Request tab: text, or base64 for binary/multipart (§5.4 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum BodyView {
    None,
    Text(String),
    Base64(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestView {
    pub index: u32,
    pub method: String,
    pub resolved_url: String,
    pub content_type: Option<String>,
    pub body: BodyView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PreviewBody {
    /// §6.3 Fallback.
    JsonTree {
        tree: JsonNode,
    },
    WriteRequests {
        requests: Vec<RequestView>,
    },
    UpstreamError {
        status: u16,
        /// Capped to [`ERROR_TEXT_CAP_BYTES`]; build with [`PreviewBody::upstream_error`].
        error_messages_text: String,
    },
    Outcome {
        outcome: OutcomeKind,
        size_or_pages: String,
        query: String,
    },
    EnrichmentError {
        status: Option<u16>,
        text: String,
        outcome: Option<OutcomeKind>,
    },
    UnresolvedName {
        param: String,
        value: String,
        matches: u64,
        candidates: Vec<String>,
    },
    Conflict {
        summary: String,
        diff_text: String,
    },
    CouldNotRecheck {
        class: String,
        requests: Vec<RequestView>,
    },
}

impl PreviewBody {
    /// `UpstreamError` with the message text capped (2 KiB, char boundary, trailing `…`).
    pub fn upstream_error(status: u16, error_messages: &str) -> PreviewBody {
        PreviewBody::UpstreamError {
            status,
            error_messages_text: cap_error_text(error_messages),
        }
    }
}

impl PreviewBody {
    /// `EnrichmentError` with the text capped like `UpstreamError` (§6.3).
    pub fn enrichment_error(
        status: Option<u16>,
        text: &str,
        outcome: Option<OutcomeKind>,
    ) -> PreviewBody {
        PreviewBody::EnrichmentError {
            status,
            text: cap_error_text(text),
            outcome,
        }
    }
}

/// Cuts `s` to at most [`ERROR_TEXT_CAP_BYTES`] bytes at a char boundary; a cut text ends in `…`.
pub fn cap_error_text(s: &str) -> String {
    if s.len() <= ERROR_TEXT_CAP_BYTES {
        return s.to_owned();
    }
    let mut end = ERROR_TEXT_CAP_BYTES - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Raw view paging; the bytes stay in core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RawPager {
    pub total_bytes: u64,
    pub page_bytes: u64,
    pub page_count: u64,
}

impl RawPager {
    /// Pages of [`RAW_PAGE_BYTES`]; an empty Raw still has one (empty) page.
    pub fn for_total(total_bytes: u64) -> RawPager {
        RawPager {
            total_bytes,
            page_bytes: RAW_PAGE_BYTES,
            page_count: total_bytes.div_ceil(RAW_PAGE_BYTES).max(1),
        }
    }
}
