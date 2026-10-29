//! M10 T29 (§13 canary sweep, S-16 library half; §8.10, I-46): the bytes of a backup bundle
//! (snapshot, recovery blob, manifest) and of a compliance export carry no PAT canary (raw,
//! base64, percent-encoded) and no recovery-passphrase canary, while the PATs are in the keyring
//! and a data canary of the audit payloads is in the export (the sweep is not vacuous).

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use atlas_duck_audit::keystore::{EntryName, KeyStore};
use atlas_duck_audit::testing::MemKeyring;
use atlas_duck_audit::types::{Confirmed, EventType, RustChosenPath};
use atlas_duck_audit::{ExportControl, SettingChange, TimeRange, create_new_store};
use base64::Engine;
use common::*;
use serde_json::json;

/// Two instances, each with its own PAT.
const INSTANCES: [&str; 2] = ["ins_canary_1", "ins_canary_2"];

fn random_canary(kind: &str) -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("random");
    format!("{kind}-CANARY-{}", hex::encode(b))
}

fn chosen(p: &Path) -> RustChosenPath {
    RustChosenPath::from_native_dialog(p.to_path_buf())
}

/// The base64 characters that encode `secret` wherever it sits in a larger blob: for each of
/// the three byte alignments, the run of 4-character groups that depend on `secret` alone.
fn base64_cores(secret: &[u8]) -> Vec<String> {
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ];
    let mut out = Vec::new();
    for e in engines {
        out.push(e.encode(secret));
        out.push(e.encode(secret).trim_end_matches('=').to_string());
        for k in 0..3usize {
            let mut buf = vec![b'x'; k];
            buf.extend_from_slice(secret);
            let enc = e.encode(&buf);
            let start = 4 * k.div_ceil(3);
            let end = 4 * ((k + secret.len()) / 3);
            out.push(enc[start..end].to_string());
        }
    }
    out
}

/// Every form §13 names for a PAT: raw, base64 (standard and URL-safe, padded or not, at every
/// alignment) and percent-encoded (every byte, both cases).
fn needles(secret: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![secret.as_bytes().to_vec()];
    out.extend(
        base64_cores(secret.as_bytes())
            .into_iter()
            .map(String::into_bytes),
    );
    let pct_upper: String = secret.bytes().map(|b| format!("%{b:02X}")).collect();
    out.push(pct_upper.to_lowercase().into_bytes());
    out.push(pct_upper.into_bytes());
    out
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// Every regular file below `dir`, with its bytes.
fn files_below(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("read_dir") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let bytes = std::fs::read(&p).expect("read");
                out.push((p, bytes));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn backup_and_export_bytes_carry_no_pat_or_passphrase_canary() {
    let pats: Vec<String> = INSTANCES.iter().map(|_| random_canary("PAT")).collect();
    let passphrase = random_canary("PASS");
    let data = random_canary("DATA");

    let mut f = fixture(fake_clock(START), MemKeyring::new());
    let store = create_new_store(
        &f.data,
        &f.lock,
        f.config(),
        input(&f.install_id, &f.chain_id, &passphrase, &passphrase),
    )
    .expect("create_new_store");
    for (id, pat) in INSTANCES.iter().zip(&pats) {
        store
            .apply_setting(
                SettingChange::InstanceOrigin {
                    instance_id: (*id).into(),
                    origin: Some(format!("https://{id}.example")),
                },
                Some(Confirmed {
                    dialog_text_sha256: [7; 32],
                    dialog_lang: None,
                }),
            )
            .expect("origin");
        // PD-05: the keychain entry is a JSON blob holding the token.
        f.keys()
            .set(
                &EntryName::Pat((*id).into()),
                json!({ "pat": pat }).to_string().as_bytes(),
            )
            .expect("pat");
    }
    // The released bytes of a read and a write receipt: the data canary is in the log.
    store
        .append_batch(vec![
            ev(
                EventType::READ_FETCHED,
                Some("req_canary"),
                json!({ "body": format!("{{\"summary\":\"{data}\"}}") }),
            ),
            ev(
                EventType::READ_RELEASED,
                Some("req_canary"),
                json!({ "released": format!("{{\"summary\":\"{data}\"}}") }),
            ),
        ])
        .expect("append");
    store.append_batch(mixed(12)).expect("append mixed");
    store.flush_head_anchor().expect("flush");

    // The PATs are where they belong (the sweep below is not vacuous).
    for (id, pat) in INSTANCES.iter().zip(&pats) {
        let stored = f
            .keys()
            .get(&EntryName::Pat((*id).into()))
            .expect("get")
            .expect("PAT entry");
        assert!(contains(stored.as_slice(), pat.as_bytes()));
    }

    let out = tempfile::tempdir().expect("out dir");
    let backup = store.backup(chosen(out.path())).expect("backup");
    let cancel = AtomicBool::new(false);
    let progress = |_: u64, _: u64| {};
    let export = store
        .export(
            TimeRange::all(),
            chosen(out.path()),
            &ExportControl {
                progress: &progress,
                cancel: &cancel,
            },
        )
        .expect("export");

    let bundle = files_below(&backup.bundle_dir);
    let names: Vec<String> = bundle
        .iter()
        .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(names, ["audit.db", "manifest.json", "recovery.bin"]);
    let exported = files_below(&out.path().join(&export.dir_name));
    assert!(
        exported
            .iter()
            .any(|(p, b)| p.ends_with("events.jsonl") && contains(b, data.as_bytes())),
        "the export carries the data canary (positive control)"
    );

    let mut secrets: Vec<(&str, Vec<Vec<u8>>)> = pats.iter().map(|p| ("PAT", needles(p))).collect();
    secrets.push(("passphrase", needles(&passphrase)));
    for (path, bytes) in bundle.iter().chain(&exported) {
        for (kind, forms) in &secrets {
            for n in forms {
                assert!(
                    !contains(bytes, n),
                    "{} holds a {kind} canary ({})",
                    path.display(),
                    String::from_utf8_lossy(n)
                );
            }
        }
    }
    store.shutdown();
    f.release_stores();
}
