//! The one error type every command answers with (PD-66, §2.4, §10.3).

use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::{AdminError, DecisionError, RELEASE_BLOCKED_INTERNAL, SettingsError};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::cli_install::InstallError;
use crate::removal::RemovalError;

/// No free text from Atlassian: every variant is a fixed kind, a static field name or a core error
/// (`DecisionError`, `AdminError`) that serializes a kind and fixed data. One exception:
/// `DecisionError::EditRejected` carries the validator's app-generated message, which can echo
/// values of the user's edit or of the agent's request, bounded and display-escaped by the validator;
/// no secret or path can appear in it. The UI shows it only for an edit, cut to a bounded length and
/// inside `AgentText` after a fixed prefix; every other error it maps from `kind` to fixed strings.
///
/// Wire shape: `{"kind": "invalid_argument", "field": "<name>"}`, `{"kind": "not_found"}`,
/// `{"kind": "not_ready"}`, `{"kind": "internal"}`, and the wrapped core errors nested under
/// `error` (`{"kind": "decision", "error": {"kind": "stale", ..}}`, `{"kind": "admin", "error":
/// {..}}`): the core errors carry their own `kind`, so flattening them would repeat the key.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandError {
    /// A value the DTO layer refused before any core call; `field` names the argument.
    InvalidArgument {
        field: &'static str,
    },
    NotFound,
    /// No `Core` serves yet (before first run, locked, starting, or the store failed).
    NotReady,
    Decision(DecisionError),
    Admin(AdminError),
    /// `SettingsAdmin` refused or failed (M6 T25): nested like `Admin`, `{"kind": "settings",
    /// "error": {"kind": "invalid", "key": ..}}`. Fixed kinds, keys and the config banner; no text.
    Settings(SettingsError),
    /// M6 T25: the credential window is open for something else (`WindowError::Busy`); close it
    /// first. M10: also another job holding the serving state's slot (an export, a backup, a
    /// restore, a recovery-tier flow). Nothing was changed. A removal call's own claim is
    /// `removal {running}` (T28 m-8).
    Busy,
    /// M6 T27 (§12.3): "Install CLI to PATH" or its removal could not be done; the kind says why
    /// (`no_stable_path`, `unsafe_path`, `occupied`, `registry`, ...). Nested like `Admin`: `{"kind":
    /// "cli_install", "error": {"kind": "occupied"}}`. No path and no OS text.
    CliInstall(InstallError),
    /// M6 T28 (§12.5): "Prepare for removal" refused or failed (`no_procedure`, `unticked`,
    /// `token_stored`, `autostart`, `recorded`; M10 T16: `running`, another removal call runs).
    /// Nested like `Admin`: `{"kind": "removal", "error": {"kind": "unticked"}}`. No text.
    Removal(RemovalError),
    /// M5 M-11 (T7 review H1): the candidate could not be built, so a preview or a Raw page has
    /// nothing to show. The text is the core constant, chosen here so the UI never maps an error
    /// kind to it; wire `{"kind": "release_blocked", "text": ..}`.
    ReleaseBlocked,
    /// M10 T12 (PD-180, PD-181): a native confirmation or a folder dialog Rust drew was cancelled
    /// (or the export's cancel flag was set): nothing was appended, nothing is left on disk.
    Cancelled,
    /// M10 T12 (PD-159..PD-161): the compliance export did not end as a plain success. Nested like
    /// `Admin`: `{"kind": "export", "error": {"kind": "not_renamed", ..}}`. No path, no OS text.
    Export(ExportFailure),
    /// M10 T12: `Store::backup` failed (nothing is logged for a failed backup; retry it whole).
    Backup,
    /// M10 T12: an Audit-window read failed. Nested: `{"kind": "audit", "error": {"kind":
    /// "unreadable", "seq": n}}` for a record that does not decrypt or verify, `{"kind": "failed"}`
    /// otherwise. No error text.
    Audit(AuditReadFailure),
    /// M10 T13 (PD-168): a restore was refused or failed. Nested like `Admin`: `{"kind":
    /// "restore", "error": {"kind": "wrong_passphrase"}}`. No path, no text.
    Restore(RestoreFailure),
    /// M10 T14 (PD-166): the anchor directory was not changed. Nested: `{"kind": "anchor_dir",
    /// "error": {"kind": "not_writable"}}`. No path, no text.
    AnchorDir(AnchorDirFailure),
    /// M10 T14 (PD-170): "Re-anchor" did nothing (the store's refusal, by kind). Nested like
    /// `AnchorDir`. No text.
    ReAnchor(ReAnchorFailure),
    /// M10 T14 (PD-170): "Forget old install" stopped. Nested like `AnchorDir`; a keychain error
    /// names what was and was not deleted (account names, display-escaped).
    Forget(ForgetFailure),
    /// A blocking task died, or a state the command layer cannot explain.
    Internal,
}

/// Why the anchor directory was not changed (M10 T14, PD-166). Nothing was committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorDirFailure {
    /// The chosen folder's chain file could not be created or opened for append: "This folder
    /// cannot be written" (plan text, the UI's).
    NotWritable,
    /// The anchor-dir writer is stuck on the current directory (a hung share): try again.
    WriterBusy,
    /// The chosen folder is the anchor directory already.
    Unchanged,
    /// "Remove" with no anchor directory set.
    NotSet,
    /// Anything else (a path that is not absolute or not UTF-8, an unreadable settings row, a
    /// closed store).
    Failed,
}

impl AnchorDirFailure {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NotWritable => "not_writable",
            Self::WriterBusy => "writer_busy",
            Self::Unchanged => "unchanged",
            Self::NotSet => "not_set",
            Self::Failed => "failed",
        }
    }
}

impl Serialize for AnchorDirFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("kind", self.kind())?;
        m.end()
    }
}

/// Why "Re-anchor" did nothing (M10 T14, PD-170): the store's refusals by kind
/// (`RE_ANCHOR_*`, `anchors::BARRIER_TAKEN`), the keychain, the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReAnchorFailure {
    /// No keychain anchor entry is missing (also the check before the dialog).
    NothingMissing,
    /// A prune's, restore's or re-anchor's barrier holds the anchors (also the check before the
    /// dialog).
    Held,
    /// The store has another integrity incident: it is not re-anchored (that verification is
    /// logged).
    DoesNotVerify,
    /// A restore replaced the store while it ran, or took its barrier: nothing was written.
    Restored,
    /// The keychain could not be read or written (after the `re_anchored` incident: it stands,
    /// the anchors stay missing).
    Keychain,
    Failed,
}

impl ReAnchorFailure {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NothingMissing => "nothing_missing",
            Self::Held => "held",
            Self::DoesNotVerify => "does_not_verify",
            Self::Restored => "restored",
            Self::Keychain => "keychain",
            Self::Failed => "failed",
        }
    }
}

impl Serialize for ReAnchorFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("kind", self.kind())?;
        m.end()
    }
}

/// Why "Forget old install" stopped (M10 T14, PD-170).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgetFailure {
    /// The keychain or an archived store could not be read for the list: nothing was deleted.
    Unreadable,
    /// A keychain delete failed: `deleted` went, `not_deleted` (the failed one first) stay; a
    /// retry deletes the rest. Account names (`pat/<instance_id>`, `canary`, `kek`, ...),
    /// display-escaped.
    Keychain {
        deleted: Vec<String>,
        not_deleted: Vec<String>,
    },
    /// Anything else (nothing was deleted).
    Failed,
}

impl ForgetFailure {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Keychain { .. } => "keychain",
            Self::Failed => "failed",
        }
    }
}

impl Serialize for ForgetFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        if let Self::Keychain {
            deleted,
            not_deleted,
        } = self
        {
            m.serialize_entry("deleted", deleted)?;
            m.serialize_entry("not_deleted", not_deleted)?;
        }
        m.end()
    }
}

/// How a compliance export ended when it did not simply succeed (Δ-M10-3, PD-159, PD-181).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFailure {
    /// The time range holds no record; nothing was written.
    EmptyRange,
    /// The chosen folder already holds an export directory of this name (the same range exported
    /// in the same second); nothing was written. A later attempt gets a new name.
    Exists,
    /// The failed or cancelled export's staging directory `dir_name` (a `….partial` subdirectory
    /// of the folder the user chose; its name only, never a path) could not be removed: it may
    /// hold decrypted records, no `EXPORT` was logged, and the user must delete it.
    Leftover { dir_name: String },
    /// The export is complete and logged, but its directory is still named `dir_name` (ending in
    /// `.partial`): rename it (drop the suffix) before giving it to a recipient, since
    /// `verify-export` refuses `.partial` names. Never retried: a retry logs another `EXPORT`.
    NotRenamed {
        /// Lowercase hex SHA-256 of `manifest.json` (the recipient's trust root, PD-161).
        manifest_sha256: String,
        dir_name: String,
        rows: u64,
    },
    /// Anything else: nothing was logged and nothing is left.
    Failed,
}

impl ExportFailure {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EmptyRange => "empty_range",
            Self::Exists => "exists",
            Self::Leftover { .. } => "leftover",
            Self::NotRenamed { .. } => "not_renamed",
            Self::Failed => "failed",
        }
    }
}

impl Serialize for ExportFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        match self {
            Self::Leftover { dir_name } => m.serialize_entry("dir_name", dir_name)?,
            Self::NotRenamed {
                manifest_sha256,
                dir_name,
                rows,
            } => {
                m.serialize_entry("manifest_sha256", manifest_sha256)?;
                m.serialize_entry("dir_name", dir_name)?;
                m.serialize_entry("rows", rows)?;
            }
            Self::EmptyRange | Self::Exists | Self::Failed => {}
        }
        m.end()
    }
}

/// Why a restore did not complete (M10 T13, PD-168; `restore_flow::restore_failure`). Every kind
/// but `committed_incomplete` means nothing changed and the restore can be tried again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreFailure {
    /// The backup's recovery passphrase does not open it.
    WrongPassphrase,
    /// The chosen file or folder is not a backup (no bundle, or its files do not match its
    /// manifest).
    NotABackup,
    /// The backup was written by a newer atlas-duck.
    Newer,
    /// The backup's chain or schema does not verify.
    Broken,
    /// The backup does not match the anchor directory's lines.
    AnchorDirMismatch,
    /// The restore committed but a later step failed: the store is closed and the next start
    /// completes the restore (the windows show `COMMITTED_INCOMPLETE_TEXT`, owned by the UI in
    /// `app/ui/src/shared/strings.ts`, with a restart prompt).
    CommittedIncomplete,
    /// The keychain could not be read or written.
    Keychain,
    /// Anything else.
    Failed,
}

impl RestoreFailure {
    pub fn kind(self) -> &'static str {
        match self {
            Self::WrongPassphrase => "wrong_passphrase",
            Self::NotABackup => "not_a_backup",
            Self::Newer => "newer",
            Self::Broken => "broken",
            Self::AnchorDirMismatch => "anchor_dir_mismatch",
            Self::CommittedIncomplete => "committed_incomplete",
            Self::Keychain => "keychain",
            Self::Failed => "failed",
        }
    }
}

impl Serialize for RestoreFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("kind", self.kind())?;
        m.end()
    }
}

/// Why an Audit-window read failed (M10 T12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditReadFailure {
    /// Record `seq` does not decrypt, does not match its digest or has an unexpected shape.
    Unreadable { seq: u64 },
    /// Anything else.
    Failed,
}

impl Serialize for AuditReadFailure {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        match self {
            Self::Unreadable { seq } => {
                m.serialize_entry("kind", "unreadable")?;
                m.serialize_entry("seq", seq)?;
            }
            Self::Failed => m.serialize_entry("kind", "failed")?,
        }
        m.end()
    }
}

impl CommandError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => "invalid_argument",
            Self::NotFound => "not_found",
            Self::NotReady => "not_ready",
            Self::Decision(_) => "decision",
            Self::Admin(_) => "admin",
            Self::Settings(_) => "settings",
            Self::Busy => "busy",
            Self::CliInstall(_) => "cli_install",
            Self::Removal(_) => "removal",
            Self::ReleaseBlocked => "release_blocked",
            Self::Cancelled => "cancelled",
            Self::Export(_) => "export",
            Self::Backup => "backup",
            Self::Audit(_) => "audit",
            Self::Restore(_) => "restore",
            Self::AnchorDir(_) => "anchor_dir",
            Self::ReAnchor(_) => "re_anchor",
            Self::Forget(_) => "forget",
            Self::Internal => "internal",
        }
    }

    /// A refusal of core on a read of the candidate (`preview_fetch`, `raw_page`): `NotApprovable`
    /// there is the rebuild failure of §5.2, shown as the `internal` banner; the rest is as is.
    pub fn from_candidate_read(e: DecisionError) -> Self {
        match e {
            DecisionError::Invalid(InvalidReason::NotApprovable) => Self::ReleaseBlocked,
            other => Self::Decision(other),
        }
    }
}

impl Serialize for CommandError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("kind", self.kind())?;
        match self {
            Self::InvalidArgument { field } => m.serialize_entry("field", field)?,
            Self::Decision(e) => m.serialize_entry("error", e)?,
            Self::Admin(e) => m.serialize_entry("error", e)?,
            Self::Settings(e) => m.serialize_entry("error", e)?,
            Self::CliInstall(e) => m.serialize_entry("error", e)?,
            Self::Removal(e) => m.serialize_entry("error", e)?,
            Self::Export(e) => m.serialize_entry("error", e)?,
            Self::Audit(e) => m.serialize_entry("error", e)?,
            Self::Restore(e) => m.serialize_entry("error", e)?,
            Self::AnchorDir(e) => m.serialize_entry("error", e)?,
            Self::ReAnchor(e) => m.serialize_entry("error", e)?,
            Self::Forget(e) => m.serialize_entry("error", e)?,
            Self::ReleaseBlocked => m.serialize_entry("text", RELEASE_BLOCKED_INTERNAL)?,
            Self::NotFound
            | Self::NotReady
            | Self::Busy
            | Self::Cancelled
            | Self::Backup
            | Self::Internal => {}
        }
        m.end()
    }
}

/// The kind (and the refused field) only, like the core errors' `Display`.
impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { field } => write!(f, "invalid_argument ({field})"),
            other => f.write_str(other.kind()),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<DecisionError> for CommandError {
    fn from(e: DecisionError) -> Self {
        Self::Decision(e)
    }
}

impl From<AdminError> for CommandError {
    fn from(e: AdminError) -> Self {
        Self::Admin(e)
    }
}

impl From<SettingsError> for CommandError {
    fn from(e: SettingsError) -> Self {
        Self::Settings(e)
    }
}

impl From<InstallError> for CommandError {
    fn from(e: InstallError) -> Self {
        Self::CliInstall(e)
    }
}

impl From<RemovalError> for CommandError {
    fn from(e: RemovalError) -> Self {
        Self::Removal(e)
    }
}

#[cfg(test)]
mod tests {
    use atlas_duck_core::CandidateRev;
    use serde_json::json;

    use super::*;

    #[test]
    fn wire_shape_has_one_kind_and_nests_core_errors() {
        let e = CommandError::InvalidArgument { field: "reason" };
        assert_eq!(
            serde_json::to_value(&e).ok(),
            Some(json!({"kind": "invalid_argument", "field": "reason"}))
        );
        for (e, kind) in [
            (CommandError::NotFound, "not_found"),
            (CommandError::NotReady, "not_ready"),
            (CommandError::Busy, "busy"),
            (CommandError::Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_value(&e).ok(), Some(json!({ "kind": kind })));
        }
        let stale = CommandError::from(DecisionError::Stale {
            current: CandidateRev {
                counter: 2,
                candidate_hash: [0xab; 32],
            },
        });
        // The text form, not a `Value`: a repeated key would survive only there.
        let text = serde_json::to_string(&stale).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert!(
            text.starts_with(r#"{"kind":"decision","error":{"kind":"stale""#),
            "{text}"
        );
        assert_eq!(
            serde_json::to_value(CommandError::ReleaseBlocked).ok(),
            Some(json!({"kind": "release_blocked", "text": RELEASE_BLOCKED_INTERNAL}))
        );
        // Only a refused read of the candidate becomes the banner; every other refusal is as it was.
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::Invalid(InvalidReason::NotApprovable)),
            CommandError::ReleaseBlocked
        );
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::NotDecidable),
            CommandError::Decision(DecisionError::NotDecidable)
        );
        assert_eq!(
            CommandError::from_candidate_read(DecisionError::Invalid(InvalidReason::NotOpened)),
            CommandError::Decision(DecisionError::Invalid(InvalidReason::NotOpened))
        );
        let admin = CommandError::from(AdminError::NotFound);
        assert_eq!(
            serde_json::to_value(&admin).ok(),
            Some(json!({"kind": "admin", "error": {"kind": "not_found"}}))
        );
        // M10 T36 (L217): the kinds `add` used to report as `audit`, nested under `admin` with
        // their fixed data (the product, a closed reason) and no text.
        for (e, want) in [
            (
                AdminError::DuplicateAlias,
                json!({"kind": "admin", "error": {"kind": "duplicate_alias"}}),
            ),
            (
                AdminError::SecondDefault {
                    product: atlas_duck_core::Product::Confluence,
                },
                json!({"kind": "admin",
                       "error": {"kind": "second_default", "product": "confluence"}}),
            ),
            (
                AdminError::UnusableCaBundle {
                    reason: atlas_duck_core::CaBundleReason::NoCertificate,
                },
                json!({"kind": "admin",
                       "error": {"kind": "unusable_ca_bundle", "reason": "no_certificate"}}),
            ),
        ] {
            let e = CommandError::from(e);
            assert_eq!(serde_json::to_value(&e).ok(), Some(want));
        }
        let invalid = CommandError::from(SettingsError::Invalid {
            key: "jira_comments_cap",
        });
        let text = serde_json::to_string(&invalid).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert_eq!(
            serde_json::to_value(&invalid).ok(),
            Some(json!({"kind": "settings",
                        "error": {"kind": "invalid", "key": "jira_comments_cap"}}))
        );
        assert_eq!(
            CommandError::from(SettingsError::Cancelled).to_string(),
            "settings"
        );
        let cli = CommandError::from(InstallError::Occupied);
        let text = serde_json::to_string(&cli).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert_eq!(
            serde_json::to_value(&cli).ok(),
            Some(json!({"kind": "cli_install", "error": {"kind": "occupied"}}))
        );
        assert_eq!(cli.to_string(), "cli_install");
        let removal = CommandError::from(RemovalError::Unticked);
        let text = serde_json::to_string(&removal).unwrap_or_default();
        assert_eq!(text.matches("\"kind\"").count(), 2, "{text}");
        assert_eq!(
            serde_json::to_value(&removal).ok(),
            Some(json!({"kind": "removal", "error": {"kind": "unticked"}}))
        );
        assert_eq!(removal.to_string(), "removal");
    }

    /// M10 T12: the Audit window's kinds. A leftover or unrenamed export names its directory by
    /// its name only; nothing carries a path or an error text.
    #[test]
    fn audit_window_kinds_wire_shape() {
        for (e, kind) in [
            (CommandError::Cancelled, "cancelled"),
            (CommandError::Backup, "backup"),
        ] {
            assert_eq!(serde_json::to_value(&e).ok(), Some(json!({ "kind": kind })));
        }
        let leftover = CommandError::Export(ExportFailure::Leftover {
            dir_name: "atlas-duck-export-c-1-2-x.partial".into(),
        });
        assert_eq!(
            serde_json::to_value(&leftover).ok(),
            Some(json!({"kind": "export", "error": {"kind": "leftover",
                        "dir_name": "atlas-duck-export-c-1-2-x.partial"}}))
        );
        let renamed = CommandError::Export(ExportFailure::NotRenamed {
            manifest_sha256: "ab".repeat(32),
            dir_name: "d.partial".into(),
            rows: 3,
        });
        assert_eq!(
            serde_json::to_value(&renamed).ok(),
            Some(json!({"kind": "export", "error": {"kind": "not_renamed",
                        "manifest_sha256": "ab".repeat(32), "dir_name": "d.partial", "rows": 3}}))
        );
        for (f, kind) in [
            (ExportFailure::EmptyRange, "empty_range"),
            (ExportFailure::Exists, "exists"),
            (ExportFailure::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_value(CommandError::Export(f)).ok(),
                Some(json!({"kind": "export", "error": {"kind": kind}}))
            );
        }
        assert_eq!(
            serde_json::to_value(CommandError::Audit(AuditReadFailure::Unreadable { seq: 9 })).ok(),
            Some(json!({"kind": "audit", "error": {"kind": "unreadable", "seq": 9}}))
        );
        assert_eq!(
            serde_json::to_value(CommandError::Audit(AuditReadFailure::Failed)).ok(),
            Some(json!({"kind": "audit", "error": {"kind": "failed"}}))
        );
        assert_eq!(leftover.to_string(), "export");
    }

    /// M10 T13 (PD-168): a refused or failed restore is one fixed kind, nested; no path, no text.
    #[test]
    fn restore_kinds_wire_shape() {
        for (f, kind) in [
            (RestoreFailure::WrongPassphrase, "wrong_passphrase"),
            (RestoreFailure::NotABackup, "not_a_backup"),
            (RestoreFailure::Newer, "newer"),
            (RestoreFailure::Broken, "broken"),
            (RestoreFailure::AnchorDirMismatch, "anchor_dir_mismatch"),
            (RestoreFailure::CommittedIncomplete, "committed_incomplete"),
            (RestoreFailure::Keychain, "keychain"),
            (RestoreFailure::Failed, "failed"),
        ] {
            let e = CommandError::Restore(f);
            assert_eq!(
                serde_json::to_value(&e).ok(),
                Some(json!({"kind": "restore", "error": {"kind": kind}}))
            );
            assert_eq!(e.to_string(), "restore");
        }
    }

    /// M10 T14 (PD-166, PD-170): the recovery-tier refusals are one fixed kind each, nested; only a
    /// partial forget names the account names it did and did not delete.
    #[test]
    fn recovery_tier_kinds_wire_shape() {
        for (f, kind) in [
            (AnchorDirFailure::NotWritable, "not_writable"),
            (AnchorDirFailure::WriterBusy, "writer_busy"),
            (AnchorDirFailure::Unchanged, "unchanged"),
            (AnchorDirFailure::NotSet, "not_set"),
            (AnchorDirFailure::Failed, "failed"),
        ] {
            let e = CommandError::AnchorDir(f);
            assert_eq!(
                serde_json::to_value(&e).ok(),
                Some(json!({"kind": "anchor_dir", "error": {"kind": kind}}))
            );
            assert_eq!(e.to_string(), "anchor_dir");
        }
        for (f, kind) in [
            (ReAnchorFailure::NothingMissing, "nothing_missing"),
            (ReAnchorFailure::Held, "held"),
            (ReAnchorFailure::DoesNotVerify, "does_not_verify"),
            (ReAnchorFailure::Restored, "restored"),
            (ReAnchorFailure::Keychain, "keychain"),
            (ReAnchorFailure::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_value(CommandError::ReAnchor(f)).ok(),
                Some(json!({"kind": "re_anchor", "error": {"kind": kind}}))
            );
        }
        for (f, kind) in [
            (ForgetFailure::Unreadable, "unreadable"),
            (ForgetFailure::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_value(CommandError::Forget(f)).ok(),
                Some(json!({"kind": "forget", "error": {"kind": kind}}))
            );
        }
        let partial = CommandError::Forget(ForgetFailure::Keychain {
            deleted: vec!["pat/i1".into()],
            not_deleted: vec!["pat/i2".into(), "canary".into()],
        });
        assert_eq!(
            serde_json::to_value(&partial).ok(),
            Some(json!({"kind": "forget", "error": {"kind": "keychain",
                "deleted": ["pat/i1"], "not_deleted": ["pat/i2", "canary"]}}))
        );
        assert_eq!(partial.to_string(), "forget");
    }
}
