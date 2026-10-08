//! Event vocabulary and the value types of the store's public API (C.3, §8.2, §8.3).

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

/// One event to append (C.3). The writer masks `flags` with `CALLER_SETTABLE`.
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub seq: u64,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryKind {
    Jql,
    Cql,
}

/// Proof that the native confirmation dialog returned Ok (built by `core`, M3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmed {
    pub dialog_text_sha256: [u8; 32],
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
