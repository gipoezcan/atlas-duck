//! §7.7 / §8.13 / §13 cross-version tests for `config.toml`.
//! Fixtures are always copied into a temp dir first, so a test can never
//! modify the checked-in files and CRLF checkouts do not matter.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use atlas_duck_core::config::{
    CONFIG_FILE_NAME, CONFIG_SCHEMA_HEAD, ConfigReadOnly, ConfigState, ConfigWriteError,
    MIGRATIONS, MigrateError, Migration, REASON_CONFIG_UNREADABLE, leaf_values, load_config,
    load_config_with, migrate_with, save_config,
};
use atlas_duck_ipc::build_info::APP_VERSION;
use toml_edit::{DocumentMut, Item};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/config");
/// A fixed old mtime, so any write during the test is visible.
const OLD_MTIME_SECS: u64 = 1_000_000_000;

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURES).join(name)
}

/// Copies a fixture to `<dir>/config.toml` and sets an old mtime.
fn install(dir: &Path, name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(CONFIG_FILE_NAME);
    fs::copy(fixture(name), &path)?;
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(OLD_MTIME_SECS);
    fs::File::options()
        .write(true)
        .open(&path)?
        .set_modified(old)?;
    Ok(path)
}

/// Bytes and mtime of a file.
fn snapshot(path: &Path) -> Result<(Vec<u8>, SystemTime), Box<dyn std::error::Error>> {
    Ok((fs::read(path)?, fs::metadata(path)?.modified()?))
}

/// Names of every entry in `dir` (to catch stray temp files).
fn dir_names(dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// Every `#` comment line of `text`, trimmed.
fn comment_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.find('#').map(|i| line[i..].trim().to_owned()))
        .collect()
}

// ---- synthetic test-only migrations ------------------------------------

fn add_key(doc: &mut DocumentMut) {
    doc["fixture"]["added_in_v2"] = toml_edit::value("new");
}

fn remove_key(doc: &mut DocumentMut) {
    if let Some(table) = doc.get_mut("fixture").and_then(Item::as_table_mut) {
        table.remove("note");
    }
}

fn rename_key(doc: &mut DocumentMut) {
    if let Some(table) = doc.get_mut("fixture").and_then(Item::as_table_mut)
        && let Some(item) = table.remove("note")
    {
        table.insert("remark", item);
    }
}

fn reinterpret_value(doc: &mut DocumentMut) {
    doc["fixture"]["numbers"] = toml_edit::value("1,2,3");
}

fn must_not_run(_: &mut DocumentMut) {
    panic!("a migration ran for a config file that is newer than or equal to head");
}

const ADD_V1_TO_V2: &[Migration] = &[Migration {
    from: 1,
    apply: add_key,
}];

const PANICKING: &[Migration] = &[
    Migration {
        from: 0,
        apply: must_not_run,
    },
    Migration {
        from: 1,
        apply: must_not_run,
    },
    Migration {
        from: 2,
        apply: must_not_run,
    },
    Migration {
        from: 3,
        apply: must_not_run,
    },
    Migration {
        from: 4,
        apply: must_not_run,
    },
    Migration {
        from: 5,
        apply: must_not_run,
    },
    Migration {
        from: 6,
        apply: must_not_run,
    },
    Migration {
        from: 7,
        apply: must_not_run,
    },
    Migration {
        from: 8,
        apply: must_not_run,
    },
];

// ---- load: absent / current ----------------------------------------------

#[test]
fn absent_file_is_absent_and_nothing_is_created() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing_dir = dir.path().join("config-dir");
    let state = load_config(&missing_dir.join(CONFIG_FILE_NAME))?;
    assert!(matches!(state, ConfigState::Absent));
    assert!(!missing_dir.exists(), "load_config created the config dir");

    let state = load_config(&dir.path().join(CONFIG_FILE_NAME))?;
    assert!(matches!(state, ConfigState::Absent));
    assert!(
        dir_names(dir.path())?.is_empty(),
        "load_config created a file"
    );
    assert!(state.read_only_info().is_none());
    assert!(!state.has_instances_source());
    Ok(())
}

#[test]
fn current_file_is_writable_and_untouched_by_load() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = install(dir.path(), "v1.toml")?;
    let before = snapshot(&path)?;
    let state = load_config(&path)?;
    let ConfigState::Writable(config) = &state else {
        return Err(format!("expected Writable, got {state:?}").into());
    };
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.written_by.as_deref(), Some("0.0.1"));
    assert_eq!(
        config.document()["fixture"]["note"].as_str(),
        Some("keep me")
    );
    assert!(state.read_only_info().is_none());
    assert!(state.has_instances_source());
    assert_eq!(
        snapshot(&path)?,
        before,
        "load_config wrote a head-schema file"
    );
    Ok(())
}

#[test]
fn save_round_trips_comments_and_updates_written_by() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = install(dir.path(), "v1.toml")?;
    let original = fs::read_to_string(&path)?;
    let ConfigState::Writable(config) = load_config(&path)? else {
        return Err("expected Writable".into());
    };
    save_config(&path, &config)?;

    let saved = fs::read_to_string(&path)?;
    for comment in comment_lines(&original) {
        assert!(saved.contains(&comment), "comment lost on save: {comment}");
    }
    assert!(saved.contains(&format!("written_by = \"{APP_VERSION}\"")));
    assert!(saved.contains("schema_version = 1 # head in M1"));
    assert_eq!(dir_names(dir.path())?, vec![CONFIG_FILE_NAME.to_owned()]);

    let ConfigState::Writable(reloaded) = load_config(&path)? else {
        return Err("expected Writable after save".into());
    };
    assert_eq!(reloaded.written_by.as_deref(), Some(APP_VERSION));
    let mut expected = leaf_values(config.document());
    expected.insert(
        r#"["written_by"]"#.to_owned(),
        format!("string:{APP_VERSION:?}"),
    );
    assert_eq!(leaf_values(reloaded.document()), expected);
    Ok(())
}

// ---- load: newer, parsable -> read-only ------------------------------------

#[test]
fn newer_parsable_file_is_read_only_and_byte_identical() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = install(dir.path(), "v2-newer.toml")?;
    let before = snapshot(&path)?;
    let state = load_config(&path)?;
    assert_eq!(
        state.read_only_info(),
        Some(&ConfigReadOnly {
            schema_version: Some(2),
            parsed: true,
            written_by: Some("9.9.9".to_owned()),
        })
    );
    assert!(state.has_instances_source(), "requests keep working (§7.7)");
    let ConfigState::ReadOnly { config, .. } = &state else {
        return Err(format!("expected ReadOnly, got {state:?}").into());
    };
    assert_eq!(
        config.document()["fixture"]["note"].as_str(),
        Some("keep me")
    );
    assert_eq!(snapshot(&path)?, before, "load touched a newer config");

    let refused = save_config(&path, config);
    assert!(
        matches!(refused, Err(ConfigWriteError::ReadOnly)),
        "{refused:?}"
    );
    assert_eq!(snapshot(&path)?, before, "save touched a newer config");
    assert_eq!(dir_names(dir.path())?, vec![CONFIG_FILE_NAME.to_owned()]);
    Ok(())
}

// ---- load: unparsable or no schema -> unreadable ---------------------------

fn assert_unreadable(name: &str, expected: ConfigReadOnly) -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = install(dir.path(), name)?;
    let before = snapshot(&path)?;
    let state = load_config(&path)?;
    assert!(
        matches!(state, ConfigState::Unreadable { .. }),
        "{name}: expected Unreadable, got {state:?}"
    );
    assert_eq!(state.read_only_info(), Some(&expected), "{name}");
    assert!(!state.has_instances_source(), "{name}: no instances (§7.7)");
    assert_eq!(snapshot(&path)?, before, "{name}: file changed");
    assert_eq!(dir_names(dir.path())?, vec![CONFIG_FILE_NAME.to_owned()]);
    Ok(())
}

#[test]
fn newer_unparsable_file_is_unreadable_and_byte_identical() -> TestResult {
    assert_unreadable(
        "v7-newer-unparsable.toml",
        ConfigReadOnly {
            schema_version: Some(7),
            parsed: false,
            written_by: Some("9.9.9".to_owned()),
        },
    )
}

#[test]
fn same_version_corrupt_file_is_unreadable_never_defaults() -> TestResult {
    assert_unreadable(
        "v1-corrupt.toml",
        ConfigReadOnly {
            schema_version: Some(1),
            parsed: false,
            written_by: Some("0.0.1".to_owned()),
        },
    )
}

#[test]
fn file_without_schema_version_is_unreadable() -> TestResult {
    assert_unreadable(
        "no-schema.toml",
        ConfigReadOnly {
            schema_version: None,
            parsed: true,
            written_by: Some("0.0.1".to_owned()),
        },
    )
}

#[test]
fn unusable_schema_values_are_unreadable() -> TestResult {
    for text in [
        "schema_version = 0\n",
        "schema_version = -1\n",
        "schema_version = \"1\"\n",
        "schema_version = 4294967296\n",
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(CONFIG_FILE_NAME);
        fs::write(&path, text)?;
        let state = load_config(&path)?;
        assert_eq!(
            state.read_only_info(),
            Some(&ConfigReadOnly {
                schema_version: None,
                parsed: true,
                written_by: None,
            }),
            "{text}"
        );
        assert_eq!(fs::read_to_string(&path)?, text);
    }
    Ok(())
}

#[test]
fn non_utf8_file_is_unreadable_with_scanned_version() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(CONFIG_FILE_NAME);
    let bytes = b"schema_version = 3\nnote = \"\xff\xfe\"\n".to_vec();
    fs::write(&path, &bytes)?;
    let state = load_config(&path)?;
    assert_eq!(
        state.read_only_info(),
        Some(&ConfigReadOnly {
            schema_version: Some(3),
            parsed: false,
            written_by: None,
        })
    );
    assert_eq!(fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn unreadable_reason_is_the_spec_string() {
    assert_eq!(REASON_CONFIG_UNREADABLE, "config_unreadable");
}

// ---- save re-checks the file on disk ---------------------------------------

#[test]
fn save_refuses_when_disk_file_became_newer_or_unreadable() -> TestResult {
    for (replacement, expect_read_only) in [
        ("v2-newer.toml", true),
        ("v7-newer-unparsable.toml", false),
        ("v1-corrupt.toml", false),
        ("no-schema.toml", false),
    ] {
        let dir = tempfile::tempdir()?;
        let path = install(dir.path(), "v1.toml")?;
        let ConfigState::Writable(config) = load_config(&path)? else {
            return Err("expected Writable".into());
        };
        // Another machine sharing the roaming/NFS config rewrote it meanwhile.
        let path = install(dir.path(), replacement)?;
        let before = snapshot(&path)?;
        let result = save_config(&path, &config);
        if expect_read_only {
            assert!(
                matches!(result, Err(ConfigWriteError::ReadOnly)),
                "{replacement}: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(ConfigWriteError::Unreadable)),
                "{replacement}: {result:?}"
            );
        }
        assert_eq!(snapshot(&path)?, before, "{replacement}: file changed");
    }
    Ok(())
}

// ---- migrations ----------------------------------------------------------

#[test]
fn additive_migration_keeps_every_key_and_comment() -> TestResult {
    let text = fs::read_to_string(fixture("v1.toml"))?;
    let mut doc: DocumentMut = text.parse()?;
    let before = leaf_values(&doc);

    assert_eq!(migrate_with(&mut doc, 1, ADD_V1_TO_V2)?, 2);

    let after = leaf_values(&doc);
    for (path, value) in &before {
        if path == r#"["schema_version"]"# {
            continue;
        }
        assert_eq!(after.get(path), Some(value), "{path} changed");
    }
    assert_eq!(
        after.get(r#"["schema_version"]"#).map(String::as_str),
        Some("integer:2")
    );
    assert_eq!(
        after
            .get(r#"["fixture"]["added_in_v2"]"#)
            .map(String::as_str),
        Some("string:\"new\"")
    );
    let migrated = doc.to_string();
    for comment in comment_lines(&text) {
        assert!(migrated.contains(&comment), "comment lost: {comment}");
    }
    Ok(())
}

#[test]
fn non_additive_migrations_are_refused() -> TestResult {
    type Step = fn(&mut DocumentMut);
    let cases: [(Step, &str); 3] = [
        (remove_key, r#"["fixture"]["note"]"#),
        (rename_key, r#"["fixture"]["note"]"#),
        (reinterpret_value, r#"["fixture"]["numbers"]"#),
    ];
    for (apply, path) in cases {
        let mut doc: DocumentMut = fs::read_to_string(fixture("v1.toml"))?.parse()?;
        let result = migrate_with(&mut doc, 1, &[Migration { from: 1, apply }]);
        assert_eq!(
            result,
            Err(MigrateError::NotAdditive {
                from: 1,
                path: path.to_owned(),
            })
        );
    }
    Ok(())
}

#[test]
fn migrate_with_stops_where_the_table_ends() -> TestResult {
    let mut doc: DocumentMut = fs::read_to_string(fixture("v1.toml"))?.parse()?;
    let before = doc.to_string();
    assert_eq!(migrate_with(&mut doc, 1, &[])?, 1);
    assert_eq!(doc.to_string(), before);
    Ok(())
}

#[test]
fn older_file_is_migrated_on_load_and_written_atomically() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = install(dir.path(), "v1.toml")?;
    let original = fs::read_to_string(&path)?;
    let state = load_config_with(&path, 2, ADD_V1_TO_V2)?;
    let ConfigState::Writable(config) = &state else {
        return Err(format!("expected Writable, got {state:?}").into());
    };
    assert_eq!(config.schema_version, 2);
    assert_eq!(config.written_by.as_deref(), Some(APP_VERSION));

    let written = fs::read_to_string(&path)?;
    assert!(written.contains("schema_version = 2 # head in M1"));
    assert!(written.contains(&format!("written_by = \"{APP_VERSION}\"")));
    assert!(written.contains("added_in_v2 = \"new\""));
    for comment in comment_lines(&original) {
        assert!(written.contains(&comment), "comment lost: {comment}");
    }
    assert_eq!(
        dir_names(dir.path())?,
        vec![CONFIG_FILE_NAME.to_owned()],
        "temp file left"
    );
    Ok(())
}

#[test]
fn load_never_runs_a_migration_for_newer_or_head_files() -> TestResult {
    for (name, head) in [
        ("v2-newer.toml", 1),
        ("v7-newer-unparsable.toml", 1),
        ("v1-corrupt.toml", 1),
        ("no-schema.toml", 1),
        ("v1.toml", 1),
        ("v7-newer-unparsable.toml", 2),
    ] {
        let dir = tempfile::tempdir()?;
        let path = install(dir.path(), name)?;
        let before = snapshot(&path)?;
        let state = load_config_with(&path, head, PANICKING)?;
        assert!(!matches!(state, ConfigState::Absent), "{name}");
        assert_eq!(snapshot(&path)?, before, "{name}: file changed");
    }
    Ok(())
}

#[test]
fn shipped_migration_table_is_a_contiguous_chain_to_head() {
    let mut froms: Vec<u32> = MIGRATIONS.iter().map(|m| m.from).collect();
    froms.sort_unstable();
    let expected: Vec<u32> = (1..CONFIG_SCHEMA_HEAD).collect();
    assert_eq!(
        froms, expected,
        "MIGRATIONS must hold exactly one step per schema below head"
    );
}

/// §13 schema test, config part: every released schema has a `v<N>.toml`
/// fixture, and each migrates to head through `MIGRATIONS` additively.
#[test]
fn every_released_fixture_migrates_to_head_additively() -> TestResult {
    let mut seen = Vec::new();
    for entry in fs::read_dir(FIXTURES)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let Some(version) = name
            .strip_prefix('v')
            .and_then(|rest| rest.strip_suffix(".toml"))
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok())
        else {
            continue;
        };
        if version > CONFIG_SCHEMA_HEAD {
            continue;
        }
        let mut doc: DocumentMut = fs::read_to_string(fixture(&name))?.parse()?;
        let before = leaf_values(&doc);
        assert_eq!(
            migrate_with(&mut doc, version, MIGRATIONS)?,
            CONFIG_SCHEMA_HEAD,
            "{name}"
        );
        let after = leaf_values(&doc);
        for (path, value) in &before {
            if path != r#"["schema_version"]"# {
                assert_eq!(after.get(path), Some(value), "{name}: {path} changed");
            }
        }
        seen.push(version);
    }
    seen.sort_unstable();
    let expected: Vec<u32> = (1..=CONFIG_SCHEMA_HEAD).collect();
    assert_eq!(seen, expected, "one v<N>.toml fixture per released schema");
    Ok(())
}
