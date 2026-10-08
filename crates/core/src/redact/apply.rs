//! [`apply`]: drops with copies and mirrors, masks, mirror check, final pass (§5.3).

use std::collections::{BTreeSet, HashSet};
use std::hash::Hash;

use atlas_duck_registry::{CopyRule, RedactionRules};
use serde_json::Value;

use super::mirror::{self, Counterpart, DroppedOnEntry};
use super::path::{self, Loc, Pattern, Step};
use super::views::{Masked, Needle, Segments, mask_value};
use super::{
    BlockReason, DropScope, REDACTED, RedactionMeta, RedactionOp, RedactionOutcome,
    RedactionPreset, UrlMode,
};

/// The `{field}` placeholder of copy rules.
const FIELD: &str = "{field}";

/// Applies `ops` to a copy of `candidate`. `items_key` is the op's `paginated.items_key` (the
/// array `items_dropped` counts, §7.5); `None` for an op that is not paged. Plan Δ: the plan's
/// signature has no `items_key`, but `RedactionRules` does not carry it.
pub fn apply(
    candidate: &Value,
    rules: &RedactionRules,
    items_key: Option<&str>,
    ops: &[RedactionOp],
) -> RedactionOutcome {
    let mut r = Redactor {
        doc: candidate.clone(),
        rules,
        items_key,
        meta: RedactionMeta::default(),
        blocked: Vec::new(),
        also: Vec::new(),
        dropped_on_entries: Vec::new(),
        url_patterns: rules
            .url_fields
            .iter()
            .filter_map(|p| path::parse(p))
            .collect(),
    };
    for op in ops {
        match op {
            RedactionOp::DropItem {
                array_path,
                key,
                value,
            } => r.drop_item(array_path, key, value),
            RedactionOp::DropField { path, scope } => r.drop_field(path, *scope),
            RedactionOp::Preset(p) => r.preset(*p),
            RedactionOp::MaskText { .. } | RedactionOp::UrlField { .. } => {}
        }
    }
    let url_mode = ops.iter().rev().find_map(|op| match op {
        RedactionOp::UrlField { mode } => Some(*mode),
        _ => None,
    });
    let mut every: Vec<Needle> = Vec::new();
    let mut singles: Vec<(Needle, Option<&str>)> = Vec::new();
    for op in ops {
        if let RedactionOp::MaskText {
            text,
            every_occurrence,
            at,
        } = op
            && let Some(n) = Needle::new(text)
        {
            r.also.extend(hits(&r.doc, &n));
            if *every_occurrence {
                every.push(n);
            } else {
                singles.push((n, at.as_deref()));
            }
        }
    }
    if !every.is_empty() {
        r.mask_every(&every, url_mode);
    }
    for (n, at) in &singles {
        r.mask_single(n, *at, url_mode);
    }
    mirror::check(&r.doc, rules.mirrors, &r.dropped_on_entries, &mut r.blocked);
    if !every.is_empty() {
        r.final_pass(&every);
    }
    let needs_confirmation = singles
        .iter()
        .filter_map(|(n, _)| {
            let left = count(&r.doc, n);
            match left {
                0 => None,
                1 => Some("1 other occurrence remains".to_owned()),
                _ => Some(format!("{left} other occurrences remain")),
            }
        })
        .collect();
    RedactionOutcome {
        released: r.doc,
        meta: r.meta,
        blocked: dedup(r.blocked),
        needs_confirmation,
        also_appears_in: dedup(r.also),
    }
}

/// §6.3 "also appears in": every location with a canonical hit for `needle` (string values, the
/// text of numbers, object keys), in document order.
pub fn also_appears_in(candidate: &Value, needle: &str) -> Vec<String> {
    Needle::new(needle).map_or_else(Vec::new, |n| hits(candidate, &n))
}

fn dedup<T: Clone + Eq + Hash>(v: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// Visits every place a string can hide: string values, the text of numbers and object keys (a
/// key's location is the key itself).
fn texts(doc: &Value, f: &mut impl FnMut(&[Step], &str)) {
    path::walk(doc, &mut Vec::new(), &mut |loc, v| match v {
        Value::String(s) => f(loc, s),
        Value::Number(n) => f(loc, &n.to_string()),
        Value::Object(o) => {
            for k in o.keys() {
                f(&path::with(loc, Step::Key(k.clone())), k);
            }
        }
        _ => {}
    });
}

fn hits(doc: &Value, n: &Needle) -> Vec<String> {
    let mut out = Vec::new();
    texts(doc, &mut |loc, s| {
        if n.hit_in(&Segments::of(s)) {
            out.push(path::display(loc));
        }
    });
    out
}

fn count(doc: &Value, n: &Needle) -> u64 {
    let mut total = 0;
    texts(doc, &mut |_, s| total += n.count(s));
    total
}

struct Redactor<'a> {
    doc: Value,
    rules: &'a RedactionRules,
    items_key: Option<&'a str>,
    meta: RedactionMeta,
    blocked: Vec<BlockReason>,
    also: Vec<String>,
    dropped_on_entries: Vec<DroppedOnEntry>,
    url_patterns: Vec<Pattern>,
}

impl Redactor<'_> {
    fn note_field(&mut self, name: &str) {
        if !self.meta.fields_dropped.iter().any(|f| f == name) {
            self.meta.fields_dropped.push(name.to_owned());
        }
    }

    /// Bookkeeping for a location an op itself drops (not a copy or a mirror).
    fn note_direct(&mut self, loc: &[Step]) {
        match loc.last() {
            Some(Step::Key(k)) => {
                let k = k.clone();
                self.note_field(&k);
            }
            Some(Step::Index(_)) => {
                let counts = match self.items_key {
                    Some(items) => loc.len() == 2 && loc[0] == Step::Key(items.to_owned()),
                    None => true,
                };
                if counts {
                    self.meta.items_dropped += 1;
                }
            }
            None => {}
        }
    }

    fn missing(&mut self, path: &str) {
        self.blocked.push(BlockReason::MaskTargetMissing {
            path: path.to_owned(),
        });
    }

    fn drop_item(&mut self, array_path: &str, key: &str, value: &Value) {
        let Some(pat) = path::parse(array_path) else {
            return self.missing(array_path);
        };
        let mut targets = Vec::new();
        for arr in pat.resolve(&self.doc) {
            if let Some(Value::Array(a)) = path::get(&self.doc, &arr) {
                for (i, e) in a.iter().enumerate() {
                    if e.get(key) == Some(value) {
                        targets.push(path::with(&arr, Step::Index(i)));
                    }
                }
            }
        }
        self.drop_locs(targets, BTreeSet::new());
    }

    fn drop_field(&mut self, field_path: &str, scope: DropScope) {
        let Some(mut pat) = path::parse(field_path) else {
            return self.missing(field_path);
        };
        let all_items = scope == DropScope::AllItems;
        if all_items {
            pat = pat.widened();
        }
        // Copies hang off the item root, so they go even where the item has no `fields.<X>`
        // itself (a rendered or changelog copy alone must not stay behind).
        let mut remove = BTreeSet::new();
        if let Some((base, x)) = pat.field_suffix() {
            let mut copied = false;
            for root in base.resolve(&self.doc) {
                copied |= self.copies(&root, &x, all_items, &mut remove);
            }
            if copied {
                self.note_field(&x);
            }
        }
        let targets = pat.resolve(&self.doc);
        self.drop_locs(targets, remove);
    }

    /// Removes `targets`, their mirrored counterparts and `remove` (copies), all resolved
    /// against the document before anything is removed.
    fn drop_locs(&mut self, targets: Vec<Loc>, mut remove: BTreeSet<Loc>) {
        for loc in targets {
            let fresh = remove.insert(loc.clone());
            self.note_direct(&loc);
            if fresh {
                self.mirrored(&loc, &mut remove);
            }
        }
        for loc in remove.iter().rev() {
            path::remove(&mut self.doc, loc);
        }
    }

    /// Registry copies of field `x` under the item root `base` (item-relative), plus the
    /// document-root copies for a drop across all items. `true` if any copy exists.
    fn copies(&self, base: &[Step], x: &str, all_items: bool, remove: &mut BTreeSet<Loc>) -> bool {
        let mut found = false;
        let mut add = |remove: &mut BTreeSet<Loc>, locs: Vec<Loc>| {
            found |= !locs.is_empty();
            remove.extend(locs);
        };
        for rule in self.rules.copies {
            match rule {
                CopyRule::Path(p) => {
                    if let Some(pat) = path::parse(p) {
                        add(remove, pat.substitute(FIELD, x).resolve_at(&self.doc, base));
                    }
                }
                CopyRule::RootPath(p) => {
                    if all_items && let Some(pat) = path::parse(p) {
                        add(remove, pat.substitute(FIELD, x).resolve(&self.doc));
                    }
                }
                CopyRule::ChangelogItems {
                    items_path,
                    key_fields,
                } => {
                    let Some(pat) = path::parse(items_path) else {
                        continue;
                    };
                    for arr_loc in pat.resolve_at(&self.doc, base) {
                        let Some(Value::Array(items)) = path::get(&self.doc, &arr_loc) else {
                            continue;
                        };
                        let hit: Vec<usize> = items
                            .iter()
                            .enumerate()
                            .filter(|(_, it)| {
                                key_fields
                                    .iter()
                                    .any(|k| it.get(*k).and_then(Value::as_str) == Some(x))
                            })
                            .map(|(i, _)| i)
                            .collect();
                        if hit.is_empty() {
                            continue;
                        }
                        let locs = if hit.len() == items.len() {
                            // An emptied `items` would look like an empty history (U-29): the
                            // history goes as a whole, or the array key if it is not an element.
                            match arr_loc.split_last() {
                                Some((_, parent @ [.., Step::Index(_)])) => vec![parent.to_vec()],
                                _ => vec![arr_loc],
                            }
                        } else {
                            hit.into_iter()
                                .map(|i| path::with(&arr_loc, Step::Index(i)))
                                .collect()
                        };
                        add(remove, locs);
                    }
                }
            }
        }
        found
    }

    fn mirrored(&mut self, loc: &[Step], remove: &mut BTreeSet<Loc>) {
        for c in mirror::counterparts(&self.doc, self.rules.mirrors, loc) {
            match c {
                Counterpart::Found(target, check) => {
                    if path::get(&self.doc, &target).is_some() {
                        remove.insert(target);
                    }
                    self.dropped_on_entries.extend(check);
                }
                Counterpart::Unmatchable(at) => self
                    .blocked
                    .push(BlockReason::MirrorUnmatchable { path: at }),
            }
        }
    }

    fn preset(&mut self, p: RedactionPreset) {
        let (container, keep): (Loc, &str) = match p {
            RedactionPreset::StatusOnly => (Vec::new(), "status"),
            RedactionPreset::ErrorClassOnly => (vec![Step::Key("script_error".into())], "class"),
        };
        let Some(Value::Object(o)) = path::get_mut(&mut self.doc, &container) else {
            return;
        };
        let gone: Vec<String> = o.keys().filter(|k| k.as_str() != keep).cloned().collect();
        for k in &gone {
            o.remove(k);
        }
        for k in &gone {
            self.note_field(k);
        }
    }

    fn is_url(&self, loc: &[Step]) -> bool {
        self.url_patterns.iter().any(|p| p.matches(loc))
    }

    /// §5.3 rule 2 for a URL-valued field with a hit; `false` if no choice was made.
    fn url_hit(&mut self, loc: &[Step], mode: Option<UrlMode>) -> bool {
        match (mode, loc.last()) {
            (Some(UrlMode::Drop), Some(Step::Key(k))) => {
                let k = k.clone();
                path::remove(&mut self.doc, loc);
                self.note_field(&k);
                true
            }
            (Some(_), _) => {
                if let Some(v) = path::get_mut(&mut self.doc, loc) {
                    *v = Value::String(REDACTED.into());
                    self.meta.spans_masked += 1;
                }
                true
            }
            (None, _) => false,
        }
    }

    fn string_locs(&self) -> Vec<Loc> {
        let mut out = Vec::new();
        path::walk(&self.doc, &mut Vec::new(), &mut |loc, v| {
            if v.is_string() {
                out.push(loc.to_vec());
            }
        });
        out
    }

    fn mask_every(&mut self, every: &[Needle], url_mode: Option<UrlMode>) {
        for loc in self.string_locs() {
            let Some(Value::String(s)) = path::get(&self.doc, &loc) else {
                continue;
            };
            let original = s.clone();
            if self.is_url(&loc) {
                let v = Segments::of(&original);
                if every.iter().any(|n| n.hit_in(&v)) {
                    // No choice: the value stays and the final pass blocks.
                    self.url_hit(&loc, url_mode);
                }
                continue;
            }
            let mut cur = original.clone();
            for n in every {
                cur = self.mask_at(&loc, cur, n, false);
            }
            if cur != original
                && let Some(v) = path::get_mut(&mut self.doc, &loc)
            {
                *v = Value::String(cur);
            }
        }
    }

    /// Masks `value` (at `loc`), recording spans and an ambiguous result.
    fn mask_at(&mut self, loc: &[Step], value: String, n: &Needle, first_only: bool) -> String {
        match mask_value(&value, n, first_only) {
            Masked::NoHit => value,
            Masked::Done { value, spans } => {
                self.meta.spans_masked += spans;
                value
            }
            Masked::Ambiguous { value, spans } => {
                self.meta.spans_masked += spans;
                let at = path::display(loc);
                self.also.push(at.clone());
                self.blocked
                    .push(BlockReason::ReencodeAmbiguous { path: at });
                value
            }
        }
    }

    fn mask_single(&mut self, n: &Needle, at: Option<&str>, url_mode: Option<UrlMode>) {
        let loc = match at {
            Some(p) => match path::parse(p).and_then(|pat| pat.as_loc()) {
                Some(loc) => loc,
                None => return self.missing(p),
            },
            None => {
                let first = self.string_locs().into_iter().find(|loc| {
                    matches!(path::get(&self.doc, loc), Some(Value::String(s)) if n.hit_in(&Segments::of(s)))
                });
                match first {
                    Some(loc) => loc,
                    // Nothing to mask anywhere.
                    None => return,
                }
            }
        };
        let display = path::display(&loc);
        let Some(Value::String(s)) = path::get(&self.doc, &loc) else {
            return self.missing(&display);
        };
        let s = s.clone();
        if !n.hit_in(&Segments::of(&s)) {
            return self.missing(&display);
        }
        if self.is_url(&loc) {
            if !self.url_hit(&loc, url_mode) {
                self.blocked
                    .push(BlockReason::MaskStillOccurs { path: display });
            }
            return;
        }
        let masked = self.mask_at(&loc, s, n, true);
        if let Some(v) = path::get_mut(&mut self.doc, &loc) {
            *v = Value::String(masked);
        }
        // §5.3: a per-item mask also applies to the mirrored entry (every hit in that value).
        for c in mirror::counterparts(&self.doc, self.rules.mirrors, &loc) {
            match c {
                Counterpart::Found(target, Some(_)) => {
                    if let Some(Value::String(t)) = path::get(&self.doc, &target) {
                        let t = t.clone();
                        let masked = self.mask_at(&target, t, n, false);
                        if let Some(v) = path::get_mut(&mut self.doc, &target) {
                            *v = Value::String(masked);
                        }
                    }
                }
                Counterpart::Found(_, None) => {}
                Counterpart::Unmatchable(at) => self
                    .blocked
                    .push(BlockReason::MirrorUnmatchable { path: at }),
            }
        }
    }

    /// §5.3 rules 3/4: any remaining hit of an every-occurrence string (value, number text,
    /// key), and any value still changing after 3 rounds, blocks the release.
    fn final_pass(&mut self, every: &[Needle]) {
        let mut found: Vec<(BlockReason, String)> = Vec::new();
        let ambiguous: BTreeSet<String> = self
            .blocked
            .iter()
            .filter(|b| matches!(b, BlockReason::ReencodeAmbiguous { .. }))
            .map(|b| b.path().to_owned())
            .collect();
        texts(&self.doc, &mut |loc, s| {
            let v = Segments::of(s);
            let at = path::display(loc);
            if v.unstable() {
                found.push((
                    BlockReason::UnstableEncoding { path: at.clone() },
                    at.clone(),
                ));
            }
            if every.iter().any(|n| n.hit_in(&v)) && !ambiguous.contains(&at) {
                found.push((BlockReason::MaskStillOccurs { path: at.clone() }, at));
            }
        });
        for (b, at) in found {
            self.blocked.push(b);
            self.also.push(at);
        }
    }
}
