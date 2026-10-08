//! §5.3 item-level mirrors: counterparts of a dropped or masked entry, and the fail-closed
//! mirror check before release.
//!
//! `src`/`dst` are item-relative (registry contract): a concrete location `base.src[i].rest`
//! has its counterpart at `base.dst[j].rest`, for any `base`. Entries pair by the mirror's `key`
//! value; a keyless entry pairs by position only when both arrays have the same length.

use atlas_duck_registry::Mirror;
use serde_json::Value;

use super::BlockReason;
use super::path::{self, Loc, Step};

/// A per-item field drop that must also be gone from the mirrored entry (re-checked after all
/// ops).
pub(crate) struct DroppedOnEntry {
    array: Loc,
    key: &'static str,
    /// The entry's key value, or `None` for a positional pair.
    key_value: Option<Value>,
    index: usize,
    rest: Loc,
}

pub(crate) enum Counterpart {
    /// The counterpart location (an entry, a location inside one, or the whole mirrored array)
    /// and, for a location inside an entry, what the check must verify.
    Found(Loc, Option<DroppedOnEntry>),
    /// The entry (`name[3]`) cannot be paired.
    Unmatchable(String),
}

fn starts_with_keys(loc: &[Step], at: usize, keys: &[Step]) -> bool {
    loc.get(at..at + keys.len()) == Some(keys)
}

/// Counterparts of `loc` in the current document, for every mirror and both directions.
pub(crate) fn counterparts(doc: &Value, mirrors: &[Mirror], loc: &[Step]) -> Vec<Counterpart> {
    let mut out = Vec::new();
    for m in mirrors {
        for (side, other) in [(m.src, m.dst), (m.dst, m.src)] {
            let side = path::keys(side);
            let other = path::keys(other);
            for at in 0..loc.len() {
                if !starts_with_keys(loc, at, &side) {
                    continue;
                }
                let base = &loc[..at];
                let other_arr = path::join(base, &other);
                let Some(Value::Array(dst)) = path::get(doc, &other_arr) else {
                    continue;
                };
                let i = match loc.get(at + side.len()) {
                    // The whole mirrored array.
                    None => {
                        out.push(Counterpart::Found(other_arr, None));
                        continue;
                    }
                    Some(Step::Index(i)) => *i,
                    Some(Step::Key(_)) => continue,
                };
                let side_arr = path::join(base, &side);
                let Some(Value::Array(src)) = path::get(doc, &side_arr) else {
                    continue;
                };
                let Some(entry) = src.get(i) else { continue };
                let rest = &loc[at + side.len() + 1..];
                let (key_value, js) = match entry.get(m.key) {
                    Some(kv) => (
                        Some(kv.clone()),
                        dst.iter()
                            .enumerate()
                            .filter(|(_, e)| e.get(m.key) == Some(kv))
                            .map(|(j, _)| j)
                            .collect::<Vec<_>>(),
                    ),
                    None if src.len() == dst.len() => (None, vec![i]),
                    None => {
                        out.push(Counterpart::Unmatchable(path::display(&path::with(
                            &side_arr,
                            Step::Index(i),
                        ))));
                        continue;
                    }
                };
                for j in js {
                    let target = path::join(&path::with(&other_arr, Step::Index(j)), rest);
                    let check = (!rest.is_empty()).then(|| DroppedOnEntry {
                        array: other_arr.clone(),
                        key: m.key,
                        key_value: key_value.clone(),
                        index: j,
                        rest: rest.to_vec(),
                    });
                    out.push(Counterpart::Found(target, check));
                }
            }
        }
    }
    out
}

/// §5.3 mirror check: every `dst` entry (under any base) has a `src` counterpart, keyless ones
/// only in equal-length arrays, and no per-item drop is still present on its mirrored entry.
pub(crate) fn check(
    doc: &Value,
    mirrors: &[Mirror],
    dropped: &[DroppedOnEntry],
    blocked: &mut Vec<BlockReason>,
) {
    let mut found = Vec::new();
    path::walk(doc, &mut Vec::new(), &mut |loc, v| {
        if !v.is_object() {
            return;
        }
        for m in mirrors {
            let dst_loc = path::join(loc, &path::keys(m.dst));
            let Some(Value::Array(dst)) = path::get(v, &path::keys(m.dst)) else {
                continue;
            };
            let src = path::get(v, &path::keys(m.src)).and_then(Value::as_array);
            for (j, e) in dst.iter().enumerate() {
                let at = path::display(&path::with(&dst_loc, Step::Index(j)));
                match (e.get(m.key), src) {
                    (Some(kv), Some(src)) if src.iter().any(|x| x.get(m.key) == Some(kv)) => {}
                    (None, Some(src)) if src.len() == dst.len() => {}
                    (None, Some(_)) => found.push(BlockReason::MirrorUnmatchable { path: at }),
                    _ => found.push(BlockReason::MirrorOrphan { path: at }),
                }
            }
        }
    });
    blocked.extend(found);
    for d in dropped {
        let Some(Value::Array(arr)) = path::get(doc, &d.array) else {
            continue;
        };
        let entries: Vec<usize> = match &d.key_value {
            Some(kv) => arr
                .iter()
                .enumerate()
                .filter(|(_, e)| e.get(d.key) == Some(kv))
                .map(|(j, _)| j)
                .collect(),
            None => vec![d.index],
        };
        for j in entries {
            let loc = path::join(&path::with(&d.array, Step::Index(j)), &d.rest);
            if path::get(doc, &loc).is_some() {
                blocked.push(BlockReason::MirrorOrphan {
                    path: path::display(&loc),
                });
            }
        }
    }
}
