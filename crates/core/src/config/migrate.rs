//! Additive-only `config.toml` migrations (§7.7, §8.13).
//!
//! A migration may add keys, tables and array elements. It never renames,
//! removes or reinterprets a key (§7.7), so an older binary can still read
//! a file a newer one migrated. [`migrate_with`] enforces this at run time:
//! it snapshots every leaf before each step and refuses the result when any
//! earlier path or value is gone or changed.

use std::collections::BTreeMap;
use std::fmt;

use toml_edit::{DocumentMut, Item, Table, Value};

/// Root key holding the config schema version (§7.7, §8.13).
pub const KEY_SCHEMA_VERSION: &str = "schema_version";

/// One forward step `from` -> `from + 1`.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// Schema version this step starts from.
    pub from: u32,
    /// Edits the document in place. Must only add.
    pub apply: fn(&mut DocumentMut),
}

/// The shipped migration table. Head is schema 1, so there is no step yet.
/// Each later schema adds exactly one entry `Migration { from: head - 1, .. }`
/// and a `tests/fixtures/config/v<head>.toml` fixture.
pub const MIGRATIONS: &[Migration] = &[];

/// Why a migration chain was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateError {
    /// The step starting at `from` removed or changed the value at `path`.
    NotAdditive { from: u32, path: String },
    /// No step leads from `from` towards the requested head.
    MissingStep { from: u32 },
    /// The version counter would overflow `u32`.
    VersionOverflow,
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAdditive { from, path } => write!(
                f,
                "config migration from schema {from} is not additive: {path} was removed or changed"
            ),
            Self::MissingStep { from } => {
                write!(f, "no config migration step from schema {from}")
            }
            Self::VersionOverflow => f.write_str("config schema version overflow"),
        }
    }
}

impl std::error::Error for MigrateError {}

/// Runs every step of `table` starting at `from`, one version at a time,
/// while a step with `Migration::from == current` exists. After each step
/// it sets the root `schema_version` to the new version and checks that the
/// step was additive. Returns the version reached. It knows nothing about
/// the binary's head: the caller decides whether a file may be migrated.
pub fn migrate_with(
    doc: &mut DocumentMut,
    from: u32,
    table: &[Migration],
) -> Result<u32, MigrateError> {
    let mut version = from;
    while let Some(step) = table.iter().find(|m| m.from == version) {
        let before = leaf_values(doc);
        (step.apply)(doc);
        let after = leaf_values(doc);
        if let Some(path) = first_non_additive(&before, &after) {
            return Err(MigrateError::NotAdditive {
                from: version,
                path,
            });
        }
        version = version
            .checked_add(1)
            .ok_or(MigrateError::VersionOverflow)?;
        set_root_value(doc, KEY_SCHEMA_VERSION, Value::from(i64::from(version)));
    }
    Ok(version)
}

/// Flattens a document into `path -> canonical value`. Every container is a
/// leaf too (`table` / `array` / `array_of_tables`), so dropping an empty
/// table or turning a table into a scalar is visible. Paths look like
/// `["fixture"]["items"][0]["name"]`. Formatting (whitespace, comments,
/// inline vs standard table) does not affect the result.
pub fn leaf_values(doc: &DocumentMut) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    flatten_table(doc.as_table(), "", &mut out);
    out
}

/// The first path of `before` (other than the root `schema_version`, which
/// the runner bumps) that is missing or different in `after`.
pub fn first_non_additive(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Option<String> {
    let version_path = key_segment("", KEY_SCHEMA_VERSION);
    before
        .iter()
        .filter(|(path, _)| **path != version_path)
        .find(|(path, value)| after.get(*path) != Some(*value))
        .map(|(path, _)| path.clone())
}

/// Replaces a root value but keeps the old value's decor (e.g. a trailing
/// comment on the same line). Inserts the key when it is missing.
pub(crate) fn set_root_value(doc: &mut DocumentMut, key: &str, new: Value) {
    match doc.get_mut(key).and_then(Item::as_value_mut) {
        Some(old) => {
            let decor = old.decor().clone();
            *old = new;
            *old.decor_mut() = decor;
        }
        None => {
            doc[key] = Item::Value(new);
        }
    }
}

fn key_segment(prefix: &str, key: &str) -> String {
    format!("{prefix}[{key:?}]")
}

fn flatten_table(table: &Table, prefix: &str, out: &mut BTreeMap<String, String>) {
    for (key, item) in table.iter() {
        flatten_item(item, &key_segment(prefix, key), out);
    }
}

fn flatten_item(item: &Item, path: &str, out: &mut BTreeMap<String, String>) {
    match item {
        Item::None => {}
        Item::Value(value) => flatten_value(value, path, out),
        Item::Table(table) => {
            out.insert(path.to_owned(), "table".to_owned());
            flatten_table(table, path, out);
        }
        Item::ArrayOfTables(tables) => {
            out.insert(path.to_owned(), "array_of_tables".to_owned());
            for (index, table) in tables.iter().enumerate() {
                let element = format!("{path}[{index}]");
                out.insert(element.clone(), "table".to_owned());
                flatten_table(table, &element, out);
            }
        }
    }
}

fn flatten_value(value: &Value, path: &str, out: &mut BTreeMap<String, String>) {
    let canonical = match value {
        Value::String(s) => format!("string:{:?}", s.value()),
        Value::Integer(i) => format!("integer:{}", i.value()),
        Value::Float(x) => format!("float:{:?}", x.value()),
        Value::Boolean(b) => format!("boolean:{}", b.value()),
        Value::Datetime(d) => format!("datetime:{}", d.value()),
        Value::Array(array) => {
            for (index, element) in array.iter().enumerate() {
                flatten_value(element, &format!("{path}[{index}]"), out);
            }
            "array".to_owned()
        }
        Value::InlineTable(table) => {
            for (key, element) in table.iter() {
                flatten_value(element, &key_segment(path, key), out);
            }
            "table".to_owned()
        }
    };
    out.insert(path.to_owned(), canonical);
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn leaf_values_covers_every_toml_shape() -> TestResult {
        let doc: DocumentMut =
            "a = 1\nb = { c = \"x\" }\nd = [true, 2.5]\n[e]\n[[f]]\ng = 1979-05-27\n".parse()?;
        let leaves = leaf_values(&doc);
        let expected: BTreeMap<String, String> = [
            (r#"["a"]"#, "integer:1"),
            (r#"["b"]"#, "table"),
            (r#"["b"]["c"]"#, "string:\"x\""),
            (r#"["d"]"#, "array"),
            (r#"["d"][0]"#, "boolean:true"),
            (r#"["d"][1]"#, "float:2.5"),
            (r#"["e"]"#, "table"),
            (r#"["f"]"#, "array_of_tables"),
            (r#"["f"][0]"#, "table"),
            (r#"["f"][0]["g"]"#, "datetime:1979-05-27"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(leaves, expected);
        Ok(())
    }

    #[test]
    fn formatting_does_not_change_leaf_values() -> TestResult {
        let standard: DocumentMut = "# c\n[t]\nk = 1 # trailing\n".parse()?;
        let inline: DocumentMut = "t = { k = 1 }\n".parse()?;
        assert_eq!(leaf_values(&standard), leaf_values(&inline));
        Ok(())
    }

    #[test]
    fn set_root_value_keeps_trailing_comment() -> TestResult {
        let mut doc: DocumentMut = "schema_version = 1 # keep\n".parse()?;
        set_root_value(&mut doc, KEY_SCHEMA_VERSION, Value::from(2_i64));
        assert_eq!(doc.to_string(), "schema_version = 2 # keep\n");
        Ok(())
    }
}
