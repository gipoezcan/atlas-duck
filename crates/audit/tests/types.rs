use atlas_duck_audit::error::AuditError;
use atlas_duck_audit::keystore::KeyStoreError;
use atlas_duck_audit::types::{DecisionColumn, EventFlags, EventType, UtcInstant};

const C3_NAMES: [&str; 49] = [
    "REQUEST_RECEIVED",
    "REQUEST_REJECTED",
    "REQUEST_FAILED",
    "PREVIEW_FETCH",
    "DECISION_STALE",
    "DECISION_INVALID",
    "PREVIEW_SHOWN",
    "BATCH_CONFIRMED",
    "DELIVERED",
    "READ_FETCHED",
    "READ_RELEASED",
    "READ_DENIED",
    "READ_FAILED",
    "WRITE_EDITED",
    "WRITE_APPROVED",
    "WRITE_DENIED",
    "WRITE_STALE",
    "WRITE_EXECUTED",
    "WRITE_FAILED",
    "WRITE_OUTCOME_UNKNOWN",
    "SCRIPT_STARTED",
    "SCRIPT_CALL_SENT",
    "SCRIPT_CALL",
    "SCRIPT_FINISHED",
    "SCRIPT_FAILED",
    "SCRIPT_RELEASED",
    "SCRIPT_DENIED",
    "SCRIPT_DRY_RUN",
    "EXPIRED",
    "CANCELLED",
    "ABANDONED",
    "GENESIS",
    "APP_START",
    "APP_STOP",
    "SCHEMA_MIGRATED",
    "CONFIG_CHANGED",
    "INSTANCE_STATE_CHANGED",
    "CREDENTIAL_CHANGED",
    "SYSTEM_FETCH",
    "PRUNE",
    "EXPORT",
    "BACKUP",
    "RESTORE",
    "KEY_ROTATED",
    "KEY_RECOVERED",
    "VERIFY",
    "INTEGRITY_ACK",
    "LEGAL_HOLD_CHANGED",
    "CLOCK_ANOMALY",
];

#[test]
fn event_type_names_round_trip() {
    assert_eq!(EventType::ALL.len(), 49);
    for t in EventType::ALL {
        assert_eq!(EventType::parse(t.as_str()), Some(t));
    }
    let names: Vec<&str> = EventType::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names, C3_NAMES);
    assert_eq!(EventType::parse("request_received"), None);
    assert_eq!(EventType::parse("NOPE"), None);
}

#[test]
fn flags_bits_are_fixed() {
    assert_eq!(EventFlags::EDITED.bits(), 1);
    assert_eq!(EventFlags::REDACTED.bits(), 2);
    assert_eq!(EventFlags::BATCH.bits(), 4);
    assert_eq!(EventFlags::STALE.bits(), 8);
    assert_eq!(EventFlags::BACKWARDS.bits(), 16);
    assert_eq!(EventFlags::FORWARD.bits(), 32);
    assert_eq!(EventFlags::BEHIND.bits(), 64);
    assert_eq!(EventFlags::INTEGRITY_INCIDENT.bits(), 128);
    assert_eq!(EventFlags::CALLER_SETTABLE.bits(), 15);
    assert_eq!(EventFlags::CLOCK_MASK.bits(), 112);
    let f = EventFlags::EDITED | EventFlags::BATCH | EventFlags::BACKWARDS;
    assert_eq!(f.bits(), 21);
    assert!(f.contains(EventFlags::BATCH));
    assert!(!f.contains(EventFlags::STALE));
    assert_eq!((f & EventFlags::CALLER_SETTABLE).bits(), 5);
    assert_eq!(EventFlags::from_bits(21), f);
}

#[test]
fn decision_strings() {
    let got: Vec<&str> = [
        DecisionColumn::Approve,
        DecisionColumn::ApproveEdited,
        DecisionColumn::Release,
        DecisionColumn::ReleaseRedacted,
        DecisionColumn::Deny,
        DecisionColumn::Expire,
        DecisionColumn::Cancel,
        DecisionColumn::Reject,
    ]
    .iter()
    .map(|d| d.as_str())
    .collect();
    assert_eq!(
        got,
        [
            "approve",
            "approve_edited",
            "release",
            "release_redacted",
            "deny",
            "expire",
            "cancel",
            "reject"
        ]
    );
}

#[test]
fn utc_instant_format() {
    assert_eq!(UtcInstant(0).to_rfc3339_ms(), "1970-01-01T00:00:00.000Z");
    let t = UtcInstant(1_791_460_800_123);
    assert_eq!(t.to_rfc3339_ms(), "2026-10-08T12:00:00.123Z");
    assert_eq!(
        UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.123Z"),
        Some(t)
    );
    assert_eq!(t.date().to_string(), "2026-10-08");
    assert_eq!(UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00Z"), None);
    assert_eq!(
        UtcInstant::parse_rfc3339_ms("2026-10-08T12:00:00.123+00:00"),
        None
    );
    assert_eq!(
        UtcInstant::parse_rfc3339_ms("2026-10-08T14:00:00.123+02:00"),
        None
    );
}

fn longest_hex_run(s: &str) -> usize {
    let (mut best, mut cur) = (0, 0);
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

#[test]
fn errors_never_print_bytes() {
    let s = format!("{}", AuditError::Decrypt { seq: 7 });
    assert!(s.contains('7'));
    assert!(longest_hex_run(&s) <= 8, "{s}");
    let s = format!("{}", KeyStoreError::Other("bad data".into()));
    assert!(longest_hex_run(&s) <= 8, "{s}");
    let s = format!("{:?} {}", KeyStoreError::Corrupt, KeyStoreError::Corrupt);
    assert!(longest_hex_run(&s) <= 8, "{s}");
}

/// The names the M3 plan imports from the crate root (C.3) resolve there.
#[test]
fn c3_names_resolve_at_the_crate_root() {
    #[allow(unused_imports)]
    use atlas_duck_audit::testing::*;
    use atlas_duck_audit::{
        Actor, AuditError, Clock, Committed, Confirmed, DecisionColumn, EntryName, EventFlags,
        EventHeader, EventType, KeyStore, KeyStoreError, KeyringLocality, NewEvent, OpenError,
        OsKeyStore, QueryKind, RestoreError, RustChosenPath, Store, SystemClock, UtcInstant,
        create_new_store,
    };
    fn named<T: ?Sized>() -> &'static str {
        std::any::type_name::<T>()
    }
    let _ = create_new_store;
    for n in [
        named::<Actor>(),
        named::<AuditError>(),
        named::<dyn Clock>(),
        named::<Committed>(),
        named::<Confirmed>(),
        named::<DecisionColumn>(),
        named::<EntryName>(),
        named::<EventFlags>(),
        named::<EventHeader>(),
        named::<EventType>(),
        named::<dyn KeyStore>(),
        named::<KeyStoreError>(),
        named::<KeyringLocality>(),
        named::<NewEvent>(),
        named::<OpenError>(),
        named::<OsKeyStore>(),
        named::<QueryKind>(),
        named::<RestoreError>(),
        named::<RustChosenPath>(),
        named::<Store>(),
        named::<SystemClock>(),
        named::<UtcInstant>(),
    ] {
        assert!(n.starts_with("atlas_duck_audit::") || n.starts_with("dyn atlas_duck_audit::"));
    }
}
