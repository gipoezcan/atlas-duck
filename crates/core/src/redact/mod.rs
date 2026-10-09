//! Redaction of a structured release candidate (§5.3): drops with their registry copies and
//! item-level mirrors, masks in every canonical match form, the release-blocking checks, and the
//! two one-click presets (§5.2 step 6 "Release status only", §9.5 "Keep error class only").
//!
//! Fail closed: whatever cannot be removed for certain ends up in [`RedactionOutcome::blocked`],
//! and a non-empty `blocked` means the release must not happen. Drops remove keys and elements
//! and never write `null`, `""` or `[]`; masking is the only redaction that leaves a placeholder.
//!
//! Order inside [`apply`]: drops (`DropItem`, `DropField`, presets) in the order given, then every
//! every-occurrence mask, then the single-occurrence masks, then the mirror check, then the final
//! every-occurrence pass. "Also appears in" is computed after the drops, before any mask.

mod apply;
mod entities;
mod mirror;
mod path;
pub mod views;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use apply::{also_appears_in, apply};

/// §5.3: the placeholder a mask leaves.
pub const REDACTED: &str = "[REDACTED]";

/// C.7: a field drop for one item or across all items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropScope {
    /// The path as given.
    PerItem,
    /// Every `[3]`/`[key=value]` selector before the last segment widened to `[]` (the last keeps
    /// its own: `issues[key=A]` is still one issue); also removes the document-root copies
    /// (`CopyRule::RootPath`).
    AllItems,
}

/// C.7: what a mask hit does to a declared URL-valued field (§5.3 rule 2, the user's choice).
/// Without a `UrlField` op such a hit stays and blocks the release; with several, the last wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMode {
    ReplaceWhole,
    /// The key is removed and named in `fields_dropped`.
    Drop,
}

/// C.7 one-click presets, both allowlists (anything unexpected in the candidate goes too). They
/// expect the candidate shapes named below at the root; a candidate without them blocks
/// (`OpTargetMissing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPreset {
    /// §5.2 step 6: of the upstream-error candidate `{status, error_messages}` keep `status`.
    StatusOnly,
    /// §9.5: of `{script_error: {class, message, stack, logs, elapsed, stderr}}` keep
    /// `script_error.class` (and nothing else at the root).
    ErrorClassOnly,
}

/// C.7 (+ PD-20 `at`). Paths use the redaction path grammar (see `path.rs`): `name`, `name[]`,
/// `name[key=value]`, `name[3]`, dot-separated.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionOp {
    /// Removes the elements of the arrays at `array_path` whose field `key` equals `value`.
    DropItem {
        array_path: String,
        key: String,
        value: serde_json::Value,
    },
    DropField {
        path: String,
        scope: DropScope,
    },
    /// `every_occurrence: false` masks one occurrence: the first at `at` (a `name[3]` location,
    /// as `also_appears_in` reports it), or the first in document order when `at` is `None`.
    MaskText {
        text: String,
        every_occurrence: bool,
        at: Option<String>,
    },
    UrlField {
        mode: UrlMode,
    },
    Preset(RedactionPreset),
}

/// Redacting `Debug` (§7.7): lengths, never the text, path or value.
impl fmt::Debug for RedactionOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DropItem {
                array_path, key, ..
            } => write!(
                f,
                "DropItem {{ array_path: <{} bytes>, key: <{} bytes>, value: .. }}",
                array_path.len(),
                key.len()
            ),
            Self::DropField { path, scope } => write!(
                f,
                "DropField {{ path: <{} bytes>, scope: {scope:?} }}",
                path.len()
            ),
            Self::MaskText {
                text,
                every_occurrence,
                at,
            } => write!(
                f,
                "MaskText {{ text: <{} bytes>, every_occurrence: {every_occurrence}, at: {} }}",
                text.len(),
                if at.is_some() { "Some(..)" } else { "None" }
            ),
            Self::UrlField { mode } => write!(f, "UrlField {{ mode: {mode:?} }}"),
            Self::Preset(p) => write!(f, "Preset({p:?})"),
        }
    }
}

/// §4.2 `meta.redactions`: counts and field names only, never positions or values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedactionMeta {
    /// Elements removed from the op's `items_key` array (§7.5: `returned + items_dropped` =
    /// items fetched); for an op without one, elements removed by `DropItem` (and element
    /// `DropField`s) themselves. Mirrored entries and emptied changelog histories never count.
    pub items_dropped: u64,
    /// Last key of every dropped location that existed, first occurrence first. A name that
    /// holds an every-occurrence mask string (or cannot be inspected) is `[REDACTED]` instead:
    /// this list reaches the agent.
    pub fields_dropped: Vec<String>,
    /// Masked spans (a URL value replaced whole counts one, so does a dropped name withheld as
    /// `[REDACTED]`).
    pub spans_masked: u64,
}

/// Why a release must not happen. Paths are `name[3]` locations.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum BlockReason {
    /// An every-occurrence mask's string still has a canonical hit here (a value, a number's
    /// text or an object key; keys are never rewritten), or a single-occurrence selection in a
    /// URL field without a `UrlField` choice.
    MaskStillOccurs { path: String },
    /// Still changing after 3 decode rounds while an every-occurrence mask is active, or (any
    /// mask active) over the work budget of the canonical match form.
    UnstableEncoding { path: String },
    /// A hit no view could mask and re-encode cleanly.
    ReencodeAmbiguous { path: String },
    /// A mirror entry without a source counterpart, or a key dropped from a source entry that is
    /// still on its mirror entry.
    MirrorOrphan { path: String },
    /// A keyless mirror entry in arrays of different lengths.
    MirrorUnmatchable { path: String },
    /// Plan addition: an op that names nothing in the candidate. A drop path that does not
    /// parse or matches nothing (a key holding `.`, `[` or `]` cannot be addressed), a preset
    /// whose container is missing, or a single-occurrence `at` without an occurrence.
    OpTargetMissing { path: String },
}

impl BlockReason {
    pub fn path(&self) -> &str {
        match self {
            Self::MaskStillOccurs { path }
            | Self::UnstableEncoding { path }
            | Self::ReencodeAmbiguous { path }
            | Self::MirrorOrphan { path }
            | Self::MirrorUnmatchable { path }
            | Self::OpTargetMissing { path } => path,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::MaskStillOccurs { .. } => "MaskStillOccurs",
            Self::UnstableEncoding { .. } => "UnstableEncoding",
            Self::ReencodeAmbiguous { .. } => "ReencodeAmbiguous",
            Self::MirrorOrphan { .. } => "MirrorOrphan",
            Self::MirrorUnmatchable { .. } => "MirrorUnmatchable",
            Self::OpTargetMissing { .. } => "OpTargetMissing",
        }
    }
}

/// Redacting `Debug`: a path can be an object key that holds the masked string.
impl fmt::Debug for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {{ path: <{} bytes> }}",
            self.name(),
            self.path().len()
        )
    }
}

#[derive(Clone, PartialEq)]
pub struct RedactionOutcome {
    /// The candidate after the ops.
    pub released: serde_json::Value,
    pub meta: RedactionMeta,
    /// Empty ⇒ release allowed (after `needs_confirmation` was confirmed).
    pub blocked: Vec<BlockReason>,
    /// Single-occurrence masks: "N other occurrences remain" (§5.3), one per such mask.
    pub needs_confirmation: Vec<String>,
    /// Locations with a canonical hit for a masked/selected string (after the drops, before
    /// any mask, per mask in document order), then the locations of blocked values; no
    /// duplicates.
    pub also_appears_in: Vec<String>,
}

/// Redacting `Debug` (§7.7): counts only.
impl fmt::Debug for RedactionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactionOutcome")
            .field("meta", &self.meta)
            .field("blocked", &self.blocked.len())
            .field("needs_confirmation", &self.needs_confirmation.len())
            .field("also_appears_in", &self.also_appears_in.len())
            .finish_non_exhaustive()
    }
}

/// The `url_fields`, copy and mirror paths of `rules` that do not parse in the redaction path
/// grammar (a malformed one would be ignored silently by [`apply`]).
pub fn invalid_rule_paths(rules: &atlas_duck_registry::RedactionRules) -> Vec<&'static str> {
    use atlas_duck_registry::CopyRule;
    let mut paths: Vec<&'static str> = rules.url_fields.to_vec();
    for c in rules.copies {
        paths.push(match c {
            CopyRule::Path(p) | CopyRule::RootPath(p) => p,
            CopyRule::ChangelogItems { items_path, .. } => items_path,
        });
    }
    for m in rules.mirrors {
        paths.extend([m.src, m.dst, m.key]);
    }
    paths
        .into_iter()
        .filter(|p| path::parse(p).is_none())
        .collect()
}
