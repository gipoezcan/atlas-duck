//! Event vocabulary and the value types of the store's public API (C.3, §8.2, §8.3).

use std::fmt;
use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::path::{Path, PathBuf};

pub use crate::clock::UtcInstant;

macro_rules! event_types {
    ($($name:ident),+ $(,)?) => {
        /// The closed §8.3 list; `as_str()` is also the `event_type` column value.
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum EventType { $($name),+ }

        impl EventType {
            pub const ALL: [EventType; [$(stringify!($name)),+].len()] = [$(EventType::$name),+];

            pub fn as_str(self) -> &'static str {
                match self { $(EventType::$name => stringify!($name)),+ }
            }

            pub fn parse(s: &str) -> Option<EventType> {
                match s { $(stringify!($name) => Some(EventType::$name),)+ _ => None }
            }
        }
    };
}

event_types!(
    REQUEST_RECEIVED,
    REQUEST_REJECTED,
    REQUEST_FAILED,
    PREVIEW_FETCH,
    DECISION_STALE,
    DECISION_INVALID,
    PREVIEW_SHOWN,
    BATCH_CONFIRMED,
    DELIVERED,
    READ_FETCHED,
    READ_RELEASED,
    READ_DENIED,
    READ_FAILED,
    WRITE_EDITED,
    WRITE_APPROVED,
    WRITE_DENIED,
    WRITE_STALE,
    WRITE_EXECUTED,
    WRITE_FAILED,
    WRITE_OUTCOME_UNKNOWN,
    SCRIPT_STARTED,
    SCRIPT_CALL_SENT,
    SCRIPT_CALL,
    SCRIPT_FINISHED,
    SCRIPT_FAILED,
    SCRIPT_RELEASED,
    SCRIPT_DENIED,
    SCRIPT_DRY_RUN,
    EXPIRED,
    CANCELLED,
    ABANDONED,
    GENESIS,
    APP_START,
    APP_STOP,
    SCHEMA_MIGRATED,
    CONFIG_CHANGED,
    INSTANCE_STATE_CHANGED,
    CREDENTIAL_CHANGED,
    SYSTEM_FETCH,
    PRUNE,
    EXPORT,
    BACKUP,
    RESTORE,
    KEY_ROTATED,
    KEY_RECOVERED,
    VERIFY,
    INTEGRITY_ACK,
    LEGAL_HOLD_CHANGED,
    CLOCK_ANOMALY,
);

/// The `flags` column (F.2): a u64 bitset. Bits above `INTEGRITY_INCIDENT` are never valid.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct EventFlags(u64);

impl EventFlags {
    pub const EDITED: EventFlags = EventFlags(1 << 0);
    pub const REDACTED: EventFlags = EventFlags(1 << 1);
    pub const BATCH: EventFlags = EventFlags(1 << 2);
    pub const STALE: EventFlags = EventFlags(1 << 3);
    pub const BACKWARDS: EventFlags = EventFlags(1 << 4);
    pub const FORWARD: EventFlags = EventFlags(1 << 5);
    pub const BEHIND: EventFlags = EventFlags(1 << 6);
    pub const INTEGRITY_INCIDENT: EventFlags = EventFlags(1 << 7);
    /// Bits a caller may set; the clock flags and `integrity_incident` are store-managed.
    pub const CALLER_SETTABLE: EventFlags = EventFlags(0b1111);
    pub const CLOCK_MASK: EventFlags = EventFlags(0b111_0000);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn from_bits(bits: u64) -> EventFlags {
        EventFlags(bits)
    }

    pub const fn contains(self, other: EventFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for EventFlags {
    type Output = EventFlags;
    fn bitor(self, rhs: EventFlags) -> EventFlags {
        EventFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for EventFlags {
    fn bitor_assign(&mut self, rhs: EventFlags) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for EventFlags {
    type Output = EventFlags;
    fn bitand(self, rhs: EventFlags) -> EventFlags {
        EventFlags(self.0 & rhs.0)
    }
}

/// The `decision` column values (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionColumn {
    Approve,
    ApproveEdited,
    Release,
    ReleaseRedacted,
    Deny,
    Expire,
    Cancel,
    Reject,
}

impl DecisionColumn {
    pub const ALL: [DecisionColumn; 8] = [
        DecisionColumn::Approve,
        DecisionColumn::ApproveEdited,
        DecisionColumn::Release,
        DecisionColumn::ReleaseRedacted,
        DecisionColumn::Deny,
        DecisionColumn::Expire,
        DecisionColumn::Cancel,
        DecisionColumn::Reject,
    ];

    pub fn parse(s: &str) -> Option<DecisionColumn> {
        DecisionColumn::ALL.into_iter().find(|d| d.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DecisionColumn::Approve => "approve",
            DecisionColumn::ApproveEdited => "approve_edited",
            DecisionColumn::Release => "release",
            DecisionColumn::ReleaseRedacted => "release_redacted",
            DecisionColumn::Deny => "deny",
            DecisionColumn::Expire => "expire",
            DecisionColumn::Cancel => "cancel",
            DecisionColumn::Reject => "reject",
        }
    }
}

/// The actor columns of §8.2; everything is optional because system events have no agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Actor {
    pub agent_name: Option<String>,
    pub agent_name_source: Option<String>,
    pub client_kind: Option<String>,
    pub connection_id: Option<String>,
    pub peer_pid: Option<u32>,
    pub peer_exe: Option<PathBuf>,
    pub peer_origin_exe: Option<PathBuf>,
    pub os_user: Option<String>,
    pub atlassian_user: Option<String>,
    pub atlassian_user_key: Option<String>,
}

/// One event to append (C.3). The writer masks `flags` with `CALLER_SETTABLE`. `Debug` prints
/// the plaintext columns and never the payload (it holds fetched bodies and request bodies).
#[derive(Clone)]
pub struct NewEvent {
    pub event_type: EventType,
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    pub target: Option<String>,
    pub actor: Actor,
    pub decision: Option<DecisionColumn>,
    pub flags: EventFlags,
    /// Stored as RFC 8785 bytes; `payload_sha256` is taken over those bytes.
    pub payload: serde_json::Value,
}

impl fmt::Debug for NewEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewEvent")
            .field("event_type", &self.event_type)
            .field("request_id", &self.request_id)
            .field("op_id", &self.op_id)
            .field("op_class", &self.op_class)
            .field("instance_id", &self.instance_id)
            .field("target", &self.target)
            .field("actor", &self.actor)
            .field("decision", &self.decision)
            .field("flags", &self.flags)
            .field("payload", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub seq: u64,
    pub record_hash: [u8; 32],
}

/// The plaintext columns of one `events` row (C.3 header queries, T17); never decrypts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHeader {
    pub seq: u64,
    pub ts_utc: String,
    pub epoch: Option<String>,
    pub chain_id: String,
    pub event_type: EventType,
    pub request_id: Option<String>,
    pub op_id: Option<String>,
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    pub target: Option<String>,
    pub decision: Option<DecisionColumn>,
    pub flags: EventFlags,
    pub actor: Actor,
    pub payload_len: u64,
    pub key_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryKind {
    Jql,
    Cql,
}

/// Which keychain anchor entry is missing (Δ-M10-1, PD-170): `StoreHealth.anchors_missing`, the
/// condition under which Settings offers "Re-anchor". An entry that does not decode counts as
/// missing, as at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingAnchor {
    Head,
    FirstRetained,
    Both,
}

impl MissingAnchor {
    /// `None` when neither entry is missing.
    pub(crate) fn of(head: bool, first_retained: bool) -> Option<MissingAnchor> {
        match (head, first_retained) {
            (true, true) => Some(MissingAnchor::Both),
            (true, false) => Some(MissingAnchor::Head),
            (false, true) => Some(MissingAnchor::FirstRetained),
            (false, false) => None,
        }
    }
}

/// Proof that the native confirmation dialog returned Ok (built by `core`, M3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmed {
    pub dialog_text_sha256: [u8; 32],
}

/// The UTC time range of a compliance export, both ends inclusive (PD-160). The store resolves
/// it to a contiguous seq interval; instants outside years 0000..=9999 count as the nearest
/// bound, so [`TimeRange::all`] is the full range (the first retained record to the head).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub from_utc: UtcInstant,
    pub to_utc: UtcInstant,
}

impl TimeRange {
    /// Every record the store holds (the export dialog's default).
    pub fn all() -> TimeRange {
        TimeRange {
            from_utc: UtcInstant(i64::MIN),
            to_utc: UtcInstant(i64::MAX),
        }
    }
}

/// What a compliance export wrote (C.3, Δ-M10-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReceipt {
    /// The new subdirectory's name inside the chosen directory.
    pub dir_name: String,
    /// SHA-256 of `manifest.json`; also in the `EXPORT` record, for the recipient out of band.
    pub manifest_sha256: [u8; 32],
    pub first_seq: u64,
    pub last_seq: u64,
    pub rows: u64,
    /// The chains of the exported rows, in seq order (more than one across a `RESTORE`).
    pub chain_ids: Vec<String>,
    /// The first row marked `unanchored`, when an anchor dir is configured and the last
    /// exported row is not anchored.
    pub unanchored_from: Option<u64>,
    /// The `EXPORT` record.
    pub export_seq: u64,
}

/// Progress and cancellation of a running export (PD-181). `progress(done, total)` is called
/// on the exporting thread after each batch, with row counts; a set `cancel` ends the export
/// at the next check (before each row, so also between batches, and before the manifest) with
/// `AuditError::Cancelled`.
#[derive(Clone, Copy)]
pub struct ExportControl<'a> {
    pub progress: &'a (dyn Fn(u64, u64) + Sync),
    pub cancel: &'a std::sync::atomic::AtomicBool,
}

impl fmt::Debug for ExportControl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportControl")
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

/// What `verify_export` found (C.3, PD-162, PD-163), with the §12.1 exit code of each variant.
/// `report` is the report for stdout, one line each; its last line is the verdict text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportVerdict {
    /// Exit 0: verified against a supplied trust root (`--manifest-sha256`, `--anchor-dir`).
    Verified { report: Vec<String> },
    /// Exit 20: internally consistent, but no supplied trust root covers the whole export.
    NoTrustRoot { report: Vec<String> },
    /// Exit 21: tamper or fork detected.
    TamperOrFork { report: Vec<String> },
    /// Exit 22: usage or I/O error; the input cannot be read as an export.
    UsageOrIo { report: Vec<String> },
}

impl ExportVerdict {
    pub fn exit_code(&self) -> u8 {
        match self {
            ExportVerdict::Verified { .. } => 0,
            ExportVerdict::NoTrustRoot { .. } => 20,
            ExportVerdict::TamperOrFork { .. } => 21,
            ExportVerdict::UsageOrIo { .. } => 22,
        }
    }

    pub fn report(&self) -> &[String] {
        match self {
            ExportVerdict::Verified { report }
            | ExportVerdict::NoTrustRoot { report }
            | ExportVerdict::TamperOrFork { report }
            | ExportVerdict::UsageOrIo { report } => report,
        }
    }
}

/// The Audit window's filter (§8.10): exact matches on plaintext columns, `target` by prefix;
/// there is no payload search (L38). `None` and an empty list mean "no constraint"; `from_utc`
/// and `to_utc` are both inclusive; `flags_any` and `event_types` match any of their entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub from_utc: Option<UtcInstant>,
    pub to_utc: Option<UtcInstant>,
    pub agent_name: Option<String>,
    pub op_id: Option<String>,
    pub op_class: Option<String>,
    pub instance_id: Option<String>,
    /// Prefix match, byte-exact (no wildcards, case-sensitive).
    pub target: Option<String>,
    pub decision: Option<DecisionColumn>,
    /// A row matches when it has at least one of these bits (`flags` is a bitset, F.2); every
    /// entry must be a defined flag bit.
    pub flags_any: Vec<EventFlags>,
    pub event_types: Vec<EventType>,
}

/// Keyset position of an Audit window page: rows with `seq < before_seq` (all rows when
/// `None`), newest first, at most `limit` (1..=[`MAX_AUDIT_PAGE_ROWS`]) of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCursor {
    pub before_seq: Option<u64>,
    pub limit: u32,
}

/// The most rows one [`AuditPage`] holds.
pub const MAX_AUDIT_PAGE_ROWS: u32 = 500;

impl AuditCursor {
    /// The first page.
    pub fn first(limit: u32) -> AuditCursor {
        AuditCursor {
            before_seq: None,
            limit,
        }
    }
}

/// One page of matching headers, `seq` descending. `next` is `Some` exactly when more matching
/// rows follow. `scanned` is the number of rows this page read (equal to `rows.len()`: the
/// query is index-assisted keyset paging, not a counted full scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPage {
    pub rows: Vec<EventHeader>,
    pub next: Option<AuditCursor>,
    pub scanned: u64,
}

/// The `DELIVERED` facts of one request (§8.10 highlight; advisory, §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverySummary {
    pub count: u64,
    /// Some `DELIVERED` went to a peer other than the submitter's: the origin executable
    /// (`peer_origin_exe`) or the origin start time differs.
    pub to_other_peer: bool,
}

/// Every retained header of one request, seq ascending, plus its delivery summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrail {
    pub headers: Vec<EventHeader>,
    pub deliveries: DeliverySummary,
}

/// The most bytes one [`PayloadPage`] carries.
pub const PAYLOAD_PAGE_BYTES: usize = 256 * 1024;

/// One page of a decrypted payload (plaintext JCS bytes; a page boundary may fall inside a
/// UTF-8 sequence). `Debug` never prints the bytes, which are zeroized on drop.
pub struct PayloadPage {
    pub seq: u64,
    pub page: u32,
    pub page_count: u32,
    pub total_bytes: u64,
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PayloadPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadPage")
            .field("seq", &self.seq)
            .field("page", &self.page)
            .field("page_count", &self.page_count)
            .field("total_bytes", &self.total_bytes)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// A path chosen in a native file dialog. Only the native-dialog paths in M3/M6/M10 may
/// construct one (audit cannot depend on `core`/`app`; an M10 grep check enforces it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustChosenPath(PathBuf);

impl RustChosenPath {
    pub fn from_native_dialog(p: PathBuf) -> Self {
        RustChosenPath(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}
