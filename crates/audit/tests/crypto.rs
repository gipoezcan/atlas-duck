//! Payload envelope (zstd + AES-256-GCM), DEK wrapping, the Argon2id recovery blob and the
//! keyed query tag (§8.2/L38, §8.4, §8.6, §10.1; plan F.3–F.5, F.7).
//!
//! Every recovery test runs Argon2id at the real parameters (m = 64 MiB, t = 3, p = 4); only
//! `argon2id_rfc9106_vector` uses the RFC's small parameters, because that is its vector.

use std::collections::HashSet;

use atlas_duck_audit::crypto::{
    self, Dek, Kek, KekEntryError, compress, decompress, open, query_key, query_tag, random_nonce,
    seal, unwrap_dek, wrap_dek,
};
use atlas_duck_audit::encoding::{RowFields, ZERO_HASH, aad};
use atlas_duck_audit::error::{AuditError, OpenError};
use atlas_duck_audit::recovery::{
    self, MIN_PASSPHRASE_CHARS, RECOVERY_LAYOUT, RecoveryError, new_recovery_blob, open_recovery,
    recovery_layout, seal_recovery,
};
use atlas_duck_audit::types::QueryKind;
use atlas_duck_ipc::jcs::to_jcs_vec;
use secrecy::SecretString;
use serde_json::json;
use sha2::{Digest, Sha256};

const PAYLOAD_SHA: [u8; 32] = [0xAA; 32];
const NONCE_FIELD: [u8; 12] = [0x11; 12];

/// A minimal row; the AAD covers `format_version, chain_id, seq, ts_utc, epoch, event_type,
/// request_id, op_id, target, key_id, payload_sha256` (§8.4).
fn row(seq: u64, epoch: Option<&'static str>, key_id: u64) -> RowFields<'static> {
    RowFields {
        seq,
        format_version: 1,
        chain_id: "a4c1e9d27b3f4056b8e1c3a5d7f90b2e",
        ts_utc: "2026-10-08T09:15:00.000Z",
        epoch,
        request_id: None,
        event_type: "APP_START",
        op_id: None,
        op_class: None,
        instance_id: None,
        target: Some("5e0c7a1f9b3d4e2a8c6b0d1f3e5a7c9b"),
        agent_name: None,
        agent_name_source: None,
        client_kind: None,
        connection_id: None,
        peer_pid: None,
        peer_exe: None,
        peer_origin_exe: None,
        os_user: None,
        atlassian_user: None,
        atlassian_user_key: None,
        decision: None,
        flags: 0,
        payload_len: 2,
        payload_sha256: &PAYLOAD_SHA,
        key_id,
        nonce: &NONCE_FIELD,
        payload_ct: &[],
        prev_hash: &ZERO_HASH,
    }
}

fn kek_from(bytes: [u8; 32]) -> Kek {
    let mut entry = vec![1u8];
    entry.extend_from_slice(&bytes);
    Kek::from_entry_bytes(&entry).unwrap()
}

fn secret(s: &str) -> SecretString {
    SecretString::from(s)
}

fn is_decrypt(r: Result<Vec<u8>, AuditError>) -> bool {
    matches!(r, Err(AuditError::Decrypt { .. }))
}

#[test]
fn payload_round_trip() {
    let big = "x".repeat(1024 * 1024);
    let plain = to_jcs_vec(&json!(big)).unwrap();
    let payload_sha256: [u8; 32] = Sha256::digest(&plain).into();

    let dek = Dek::generate().unwrap();
    let nonce = random_nonce().unwrap();
    let a = aad(&row(5, Some("2026-10-08"), 2)).unwrap();
    let z = compress(&plain).unwrap();
    assert!(
        z.len() < plain.len() / 100,
        "zstd(3) of a repeated string compresses"
    );
    let ct = seal(&dek, &nonce, &a, &z).unwrap();
    assert_eq!(ct.len(), z.len() + 16);

    let z2 = open(&dek, &nonce, &a, &ct, 5).unwrap();
    assert_eq!(z2, z);
    let back = decompress(&z2, plain.len() as u64).unwrap();
    assert_eq!(back, plain);
    let h: [u8; 32] = Sha256::digest(&back).into();
    assert_eq!(h, payload_sha256);
}

#[test]
fn decompress_bounds() {
    let z = compress(b"{}").unwrap();
    assert_eq!(decompress(&z, 2).unwrap(), b"{}");
    // A length that disagrees with the frame is an error, never a truncated or padded payload.
    assert!(decompress(&z, 1).is_err());
    assert!(decompress(&z, 3).is_err());
    // Rejected before any allocation.
    assert_eq!(
        decompress(&z, 96 * 1024 * 1024 + 1),
        Err(AuditError::Invalid("payload above 96 MiB"))
    );
    assert!(decompress(b"not a zstd frame", 2).is_err());
}

#[test]
fn aad_binding() {
    let dek = Dek::generate().unwrap();
    let nonce = random_nonce().unwrap();
    let z = compress(b"{}").unwrap();
    let base = row(7, None, 1);
    let a = aad(&base).unwrap();
    let ct = seal(&dek, &nonce, &a, &z).unwrap();
    assert_eq!(open(&dek, &nonce, &a, &ct, 7).unwrap(), z);

    let other_seq = aad(&row(8, None, 1)).unwrap();
    let other_epoch = aad(&row(7, Some("2026-10-08"), 1)).unwrap();
    let other_key = aad(&row(7, None, 2)).unwrap();
    for other in [other_seq, other_epoch, other_key] {
        assert_ne!(other, a);
        assert!(is_decrypt(open(&dek, &nonce, &other, &ct, 7)));
    }
    assert_eq!(
        open(&dek, &nonce, &aad(&row(8, None, 1)).unwrap(), &ct, 8),
        Err(AuditError::Decrypt { seq: 8 })
    );
}

#[test]
fn ciphertext_swap_fails() {
    let dek = Dek::generate().unwrap();
    let z = compress(br#"{"a":1}"#).unwrap();
    let (na, nb) = (random_nonce().unwrap(), random_nonce().unwrap());
    let (aa, ab) = (
        aad(&row(10, Some("2026-10-08"), 2)).unwrap(),
        aad(&row(11, Some("2026-10-08"), 2)).unwrap(),
    );
    let ct_a = seal(&dek, &na, &aa, &z).unwrap();
    let ct_b = seal(&dek, &nb, &ab, &z).unwrap();
    assert_eq!(open(&dek, &nb, &ab, &ct_b, 11).unwrap(), z);
    assert!(is_decrypt(open(&dek, &nb, &ab, &ct_a, 11)));
    // Even with its own nonce, row A's ciphertext does not open under row B's AAD.
    assert!(is_decrypt(open(&dek, &na, &ab, &ct_a, 11)));
}

#[test]
fn nonces_unique() {
    let mut seen = HashSet::with_capacity(100_000);
    for _ in 0..100_000 {
        assert!(seen.insert(random_nonce().unwrap()), "nonce repeated");
    }
}

#[test]
fn wrong_dek_fails() {
    let (d1, d2) = (Dek::generate().unwrap(), Dek::generate().unwrap());
    assert_ne!(d1, d2);
    let nonce = random_nonce().unwrap();
    let a = aad(&row(3, None, 1)).unwrap();
    let ct = seal(&d1, &nonce, &a, b"zstd bytes").unwrap();
    assert!(is_decrypt(open(&d2, &nonce, &a, &ct, 3)));
    // A truncated ciphertext (shorter than the tag) is a decrypt failure, not a panic.
    assert!(is_decrypt(open(&d1, &nonce, &a, &ct[..10], 3)));
}

#[test]
fn dek_wrap_round_trip_and_binding() {
    let kek = Kek::generate().unwrap();
    let dek = Dek::generate().unwrap();
    let wrapped = wrap_dek(&kek, 3, Some("2026-10"), &dek).unwrap();
    assert_eq!(wrapped.len(), 60);
    assert_eq!(unwrap_dek(&kek, 3, Some("2026-10"), &wrapped).unwrap(), dek);

    assert!(unwrap_dek(&kek, 4, Some("2026-10"), &wrapped).is_err());
    assert!(unwrap_dek(&kek, 3, None, &wrapped).is_err());
    assert!(unwrap_dek(&kek, 3, Some("2026-11"), &wrapped).is_err());
    assert!(unwrap_dek(&Kek::generate().unwrap(), 3, Some("2026-10"), &wrapped).is_err());
    assert!(unwrap_dek(&kek, 3, Some("2026-10"), &wrapped[..59]).is_err());

    // The uncorroborated DEK (month NULL) does not open as month "" (NULL ≠ empty, F.2 frames).
    let w0 = wrap_dek(&kek, 1, None, &dek).unwrap();
    assert_eq!(unwrap_dek(&kek, 1, None, &w0).unwrap(), dek);
    assert!(unwrap_dek(&kek, 1, Some(""), &w0).is_err());

    // Fresh nonce per wrap.
    let w1 = wrap_dek(&kek, 3, Some("2026-10"), &dek).unwrap();
    assert_ne!(w1[..12], wrapped[..12]);
}

#[test]
fn kek_entry_layout() {
    let kek = Kek::generate().unwrap();
    let entry = kek.to_entry_bytes();
    assert_eq!(entry.len(), 33);
    assert_eq!(entry[0], 1);
    assert_eq!(Kek::from_entry_bytes(&entry).unwrap(), kek);

    let mut newer = entry.to_vec();
    newer[0] = 2;
    assert_eq!(
        Kek::from_entry_bytes(&newer),
        Err(KekEntryError::NewerLayout(2))
    );
    // A newer layout is reported whatever its length.
    assert_eq!(
        Kek::from_entry_bytes(&[7, 1, 2]),
        Err(KekEntryError::NewerLayout(7))
    );
    // Length 32: a bare key without its layout byte (here one starting with 0x01).
    assert_eq!(
        Kek::from_entry_bytes(&[1; 32]),
        Err(KekEntryError::Malformed)
    );
    assert_eq!(
        Kek::from_entry_bytes(&entry[..32]),
        Err(KekEntryError::Malformed)
    );
    assert_eq!(Kek::from_entry_bytes(&[]), Err(KekEntryError::Malformed));
    let mut zero = entry.to_vec();
    zero[0] = 0;
    assert_eq!(Kek::from_entry_bytes(&zero), Err(KekEntryError::Malformed));
    let mut long = entry.to_vec();
    long.push(0);
    assert_eq!(Kek::from_entry_bytes(&long), Err(KekEntryError::Malformed));
}

#[test]
fn kek_and_dek_equality_is_by_value() {
    let a = kek_from([5; 32]);
    assert_eq!(a, kek_from([5; 32]));
    let mut b = [5; 32];
    b[31] = 6;
    assert_ne!(a, kek_from(b));
    b[31] = 5;
    b[0] = 4;
    assert_ne!(a, kek_from(b));
    assert_eq!(Dek::from_bytes(&[9; 32]), Dek::from_bytes(&[9; 32]));
    assert_ne!(Dek::from_bytes(&[9; 32]), Dek::from_bytes(&[8; 32]));
}

#[test]
fn recovery_round_trip() {
    let kek = Kek::generate().unwrap();
    let pass = secret("twelve chars");
    assert_eq!("twelve chars".chars().count(), MIN_PASSPHRASE_CHARS);
    let blob = seal_recovery(&pass, &kek).unwrap();
    assert_eq!(blob.len(), 89);
    assert_eq!(blob[0], RECOVERY_LAYOUT);
    assert_eq!(recovery_layout(&blob), Some(1));
    assert_eq!(
        blob[17..29],
        [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04
        ]
    );
    assert_eq!(open_recovery(&pass, &blob).unwrap(), kek);

    // Fresh salt and nonce per seal.
    let blob2 = seal_recovery(&pass, &kek).unwrap();
    assert_ne!(blob2[1..17], blob[1..17]);
    assert_ne!(blob2[29..41], blob[29..41]);
}

#[test]
fn recovery_wrong_passphrase() {
    let kek = Kek::generate().unwrap();
    let blob = seal_recovery(&secret("correct horse battery"), &kek).unwrap();
    assert_eq!(
        open_recovery(&secret("correct horse battery "), &blob),
        Err(RecoveryError::WrongPassphrase)
    );
    // A tampered ciphertext or header is also a GCM failure: indistinguishable from a wrong
    // passphrase, and never `Malformed` (the AAD covers the header).
    let mut tampered = blob.clone();
    tampered[5] ^= 1;
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &tampered),
        Err(RecoveryError::WrongPassphrase)
    );
}

#[test]
fn recovery_nfc() {
    let kek = Kek::generate().unwrap();
    let composed = "Passphrase-\u{E9}123";
    let decomposed = "Passphrase-e\u{301}123";
    assert_ne!(composed.as_bytes(), decomposed.as_bytes());
    let blob = seal_recovery(&secret(composed), &kek).unwrap();
    assert_eq!(open_recovery(&secret(decomposed), &blob).unwrap(), kek);
}

#[test]
fn recovery_rules() {
    let kek = Kek::generate().unwrap();
    // 11 characters → too short, checked before any Argon2 work.
    assert!(matches!(
        new_recovery_blob(&secret("eleven char"), &secret("eleven char"), &kek),
        Err(OpenError::PassphraseTooShort)
    ));
    assert!(matches!(
        seal_recovery(&secret("eleven char"), &kek),
        Err(OpenError::PassphraseTooShort)
    ));
    // The decomposed form is 12 code points but 11 characters after NFC.
    assert_eq!("Passphrse-e\u{301}".chars().count(), 12);
    assert!(matches!(
        seal_recovery(&secret("Passphrse-e\u{301}"), &kek),
        Err(OpenError::PassphraseTooShort)
    ));
    // 12 characters of 4 UTF-8 bytes each: characters count, not bytes.
    let emoji = "\u{1F600}".repeat(12);
    let blob = new_recovery_blob(&secret(&emoji), &secret(&emoji), &kek).unwrap();
    assert_eq!(blob.len(), 89);
    assert_eq!(open_recovery(&secret(&emoji), &blob).unwrap(), kek);
    // Different second entry → mismatch, no blob.
    assert!(matches!(
        new_recovery_blob(
            &secret("correct horse battery"),
            &secret("correct horse batterY"),
            &kek
        ),
        Err(OpenError::PassphraseMismatch)
    ));
}

#[test]
fn recovery_newer_layout() {
    let mut blob = vec![0u8; 89];
    blob[0] = 2;
    assert_eq!(recovery_layout(&blob), Some(2));
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &blob),
        Err(RecoveryError::NewerLayout(2))
    );
    // Reported before any length check: a newer layout may be longer.
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &[3, 0, 0]),
        Err(RecoveryError::NewerLayout(3))
    );
    assert_eq!(recovery_layout(&[]), None);
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &[]),
        Err(RecoveryError::Malformed)
    );
    blob[0] = 0;
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &blob),
        Err(RecoveryError::Malformed)
    );
    blob[0] = 1;
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &blob[..88]),
        Err(RecoveryError::Malformed)
    );
}

#[test]
fn recovery_layout_1_pins_its_parameters() {
    // Layout 1 means m = 65536, t = 3, p = 4: other values are `Malformed` before Argon2 runs
    // (a crafted blob cannot make the app allocate an arbitrary amount of memory).
    let mut blob = vec![0u8; 89];
    blob[0] = 1;
    blob[17..29].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 3, 0, 0, 0, 4]);
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &blob),
        Err(RecoveryError::Malformed)
    );
    blob[17..29].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4]);
    assert_eq!(
        open_recovery(&secret("correct horse battery"), &blob),
        Err(RecoveryError::Malformed)
    );
}

#[test]
fn argon2_params_pinned() {
    let blob = seal_recovery(&secret("correct horse battery"), &Kek::generate().unwrap()).unwrap();
    let be = |i: usize| u32::from_be_bytes(blob[i..i + 4].try_into().unwrap());
    assert_eq!(be(17), 65536);
    assert_eq!(be(21), 3);
    assert_eq!(be(25), 4);
    assert_eq!(
        (
            recovery::ARGON2_M_KIB,
            recovery::ARGON2_T,
            recovery::ARGON2_P
        ),
        (65536, 3, 4)
    );
}

#[test]
fn argon2id_rfc9106_vector() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let ad = [0x04u8; 12];
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&ad).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let secret = [0x03u8; 8];
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut tag = [0u8; 32];
    a.hash_password_into(&[0x01; 32], &[0x02; 16], &mut tag)
        .unwrap();
    assert_eq!(
        hex::encode(tag),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

#[test]
fn query_tag_rules() {
    let kek_bytes = [0x5A; 32];
    let kek = kek_from(kek_bytes);
    let k = query_key(&kek);

    let t = query_tag(&k, QueryKind::Jql, "project = ABC");
    assert!(t.starts_with("jql:"));
    let hex_part = &t[4..];
    assert_eq!(hex_part.len(), 64);
    assert!(
        hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(query_tag(&k, QueryKind::Jql, "  project = ABC \n"), t);
    assert_eq!(query_tag(&k, QueryKind::Jql, "\tproject = ABC\r\n"), t);
    assert_ne!(query_tag(&k, QueryKind::Jql, "project  = ABC"), t);

    let composed = query_tag(&k, QueryKind::Jql, "assignee = M\u{FC}ller");
    let decomposed = query_tag(&k, QueryKind::Jql, "assignee = Mu\u{308}ller");
    assert_eq!(composed, decomposed);

    let c = query_tag(&k, QueryKind::Cql, "project = ABC");
    assert!(c.starts_with("cql:"));
    assert_eq!(
        c[4..],
        t[4..],
        "the prefix is the only difference between kinds"
    );

    let other = query_key(&kek_from([0x5B; 32]));
    assert_ne!(query_tag(&other, QueryKind::Jql, "project = ABC"), t);

    // K_q = HKDF-SHA256(salt none, ikm KEK, info "atlas-duck/query-tag/v1"), tag = HMAC.
    use hmac::{KeyInit, Mac};
    let hk = hkdf::Hkdf::<Sha256>::new(None, &kek_bytes);
    let mut expect = [0u8; 32];
    hk.expand(b"atlas-duck/query-tag/v1", &mut expect).unwrap();
    assert_eq!(*k, expect);
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&expect).unwrap();
    mac.update(b"project = ABC");
    assert_eq!(
        t,
        format!("jql:{}", hex::encode(mac.finalize().into_bytes()))
    );
}

#[test]
fn secrets_not_in_debug() {
    let kek_bytes = [0xC3; 32];
    let kek = kek_from(kek_bytes);
    let d = format!("{kek:?}");
    assert!(d.contains("REDACTED"), "{d}");
    assert!(!d.to_lowercase().contains(&hex::encode(kek_bytes)[..8]));
    assert!(!d.contains("195"), "{d}"); // 0xC3 as a decimal array element
    let dek = Dek::from_bytes(&[0xC3; 32]);
    let d = format!("{dek:?}");
    assert!(d.contains("REDACTED") && !d.contains("195"), "{d}");

    // Errors print names and numbers only.
    assert_eq!(
        crypto::UnwrapError.to_string(),
        "cannot unwrap the data key"
    );
    assert!(!RecoveryError::WrongPassphrase.to_string().is_empty());
}
