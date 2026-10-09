//! [`apply`]: drops with copies and mirrors, masks, mirror check, final pass (§5.3).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

use atlas_duck_registry::{CopyRule, RedactionRules};
use serde_json::Value;

use super::mirror::{self, Counterpart, DroppedOnEntry};
use super::path::{self, Loc, Pattern, Step};
use super::views::{Budget, Masked, Needle, TextInfo, inspect, mask_value};
use super::{
    BlockReason, DropScope, REDACTED, RedactionMeta, RedactionOp, RedactionOutcome,
    RedactionPreset, UrlMode,
};

/// The `{field}` placeholder of copy rules.
const FIELD: &str = "{field}";

/// Applies `ops` to a copy of `candidate`, the bare response body (paths and `url_fields` are
/// body-absolute). `items_key` is the op's `paginated.items_key` (the array `items_dropped`
/// counts, §7.5); `None` for an op that is not paged. Plan Δ: the plan's signature has no
/// `items_key`, but `RedactionRules` does not carry it.
pub fn apply(
    candidate: &Value,
    rules: &RedactionRules,
    items_key: Option<&str>,
    ops: &[RedactionOp],
) -> RedactionOutcome {
    let mut r = Redactor {
        original: candidate,
        doc: candidate.clone(),
        rules,
        items_key,
        meta: RedactionMeta::default(),
        blocked: Vec::new(),
        also: Vec::new(),
        dropped_on_entries: Vec::new(),
        dirty: HashSet::new(),
        budget: Budget::for_apply(text_bytes(candidate)),
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
    // Every mask's needle, in op order; `every`/`singles` index into it.
    let mut needles: Vec<Needle> = Vec::new();
    let mut every: Vec<usize> = Vec::new();
    let mut singles: Vec<(usize, Option<&str>)> = Vec::new();
    for op in ops {
        if let RedactionOp::MaskText {
            text,
            every_occurrence,
            at,
        } = op
            && let Some(n) = Needle::new(text)
        {
            if *every_occurrence {
                every.push(needles.len());
            } else {
                singles.push((needles.len(), at.as_deref()));
            }
            needles.push(n);
        }
    }

    // One inspection per text after the drops; reused wherever the text did not change.
    let pre = Scan::new(&r.doc, &needles, None, &r.budget);
    for i in 0..needles.len() {
        for (key, info) in pre.iter() {
            if info.hits[i] {
                r.also.push(path::display(&key.1));
            }
        }
    }
    if !every.is_empty() {
        r.mask_every(&needles, &every, &pre, url_mode);
    }
    for &(i, at) in &singles {
        r.mask_single(&needles, i, at, url_mode, &pre);
    }
    mirror::check(&r.doc, rules.mirrors, &r.dropped_on_entries, &mut r.blocked);
    let post = Scan::new(&r.doc, &needles, Some((&pre, &r.dirty)), &r.budget);
    r.redact_dropped_names(&needles, &every);
    if !needles.is_empty() {
        r.final_pass(&post, &every);
    }
    let needs_confirmation = singles
        .iter()
        .filter_map(|&(i, _)| {
            let left = r.count_left(&post, &needles, i);
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
    let Some(n) = Needle::new(needle) else {
        return Vec::new();
    };
    let needles = [n];
    Scan::new(
        candidate,
        &needles,
        None,
        &Budget::for_apply(text_bytes(candidate)),
    )
    .iter()
    .filter(|(_, info)| info.hits[0])
    .map(|(key, _)| path::display(&key.1))
    .collect()
}

fn dedup<T: Clone + Eq + Hash>(v: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// A string value or number (its text), or an object key (located at the key itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Value,
    Key,
}

type TextKey = (Kind, Loc);

/// Visits every place a string can hide: string values, the text of numbers and object keys.
fn texts(doc: &Value, f: &mut impl FnMut(Kind, &[Step], &str)) {
    path::walk(doc, &mut Vec::new(), &mut |loc, v| match v {
        Value::String(s) => f(Kind::Value, loc, s),
        Value::Number(n) => f(Kind::Value, loc, &n.to_string()),
        Value::Object(o) => {
            for k in o.keys() {
                f(Kind::Key, &path::with(loc, Step::Key(k.clone())), k);
            }
        }
        _ => {}
    });
}

/// Bytes of every string value, number text and key: what the work budget is relative to.
fn text_bytes(doc: &Value) -> usize {
    let mut n = 0usize;
    texts(doc, &mut |_, _, s| n = n.saturating_add(s.len()));
    n
}

fn text_at(doc: &Value, key: &TextKey) -> Option<String> {
    match key.0 {
        Kind::Value => match path::get(doc, &key.1)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        },
        Kind::Key => match key.1.last()? {
            Step::Key(k) => Some(k.clone()),
            Step::Index(_) => None,
        },
    }
}

/// Every text of a document with its [`TextInfo`], in document order.
struct Scan {
    order: Vec<TextKey>,
    info: HashMap<TextKey, TextInfo>,
}

impl Scan {
    /// With `prev`, texts at a location that was not rewritten reuse the earlier inspection.
    fn new(
        doc: &Value,
        needles: &[Needle],
        prev: Option<(&Scan, &HashSet<Loc>)>,
        budget: &Budget,
    ) -> Scan {
        let mut order = Vec::new();
        let mut info = HashMap::new();
        if needles.is_empty() {
            return Scan { order, info };
        }
        texts(doc, &mut |kind, loc, s| {
            let key = (kind, loc.to_vec());
            let reuse = prev.and_then(|(p, dirty)| {
                (kind == Kind::Key || !dirty.contains(loc))
                    .then(|| p.info.get(&key).cloned())
                    .flatten()
            });
            info.insert(
                key.clone(),
                reuse.unwrap_or_else(|| inspect(s, needles, budget)),
            );
            order.push(key);
        });
        Scan { order, info }
    }

    fn iter(&self) -> impl Iterator<Item = (&TextKey, &TextInfo)> {
        self.order
            .iter()
            .filter_map(|k| self.info.get(k).map(|i| (k, i)))
    }

    fn get(&self, kind: Kind, loc: &[Step]) -> Option<&TextInfo> {
        self.info.get(&(kind, loc.to_vec()))
    }
}

struct Redactor<'a> {
    original: &'a Value,
    doc: Value,
    rules: &'a RedactionRules,
    items_key: Option<&'a str>,
    meta: RedactionMeta,
    blocked: Vec<BlockReason>,
    also: Vec<String>,
    dropped_on_entries: Vec<DroppedOnEntry>,
    /// String values rewritten or removed by a mask.
    dirty: HashSet<Loc>,
    /// The canonical-form work budget of this call (shared by every text).
    budget: Budget,
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
        self.blocked.push(BlockReason::OpTargetMissing {
            path: path.to_owned(),
        });
    }

    fn elements(doc: &Value, pat: &Pattern, key: &str, value: &Value) -> Vec<Loc> {
        let mut out = Vec::new();
        for arr in pat.resolve(doc) {
            if let Some(Value::Array(a)) = path::get(doc, &arr) {
                for (i, e) in a.iter().enumerate() {
                    if e.get(key) == Some(value) {
                        out.push(path::with(&arr, Step::Index(i)));
                    }
                }
            }
        }
        out
    }

    fn drop_item(&mut self, array_path: &str, key: &str, value: &Value) {
        let Some(pat) = path::parse(array_path) else {
            return self.missing(array_path);
        };
        // The UI offers only what is there: matching nothing in the candidate is a mismatch
        // (e.g. a key holding `.`), not a no-op. An earlier op may have removed it already.
        if Self::elements(self.original, &pat, key, value).is_empty() {
            return self.missing(array_path);
        }
        let targets = Self::elements(&self.doc, &pat, key, value);
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
        let suffix = pat.field_suffix();
        let copies_in = |doc: &Value, remove: &mut BTreeSet<Loc>| {
            let mut copied = false;
            if let Some((base, x)) = &suffix {
                for root in base.resolve(doc) {
                    copied |= copies(self.rules, doc, &root, x, all_items, remove);
                }
            }
            copied
        };
        let existed = !pat.resolve(self.original).is_empty()
            || copies_in(self.original, &mut BTreeSet::new());
        if !existed {
            return self.missing(field_path);
        }
        let mut remove = BTreeSet::new();
        if copies_in(&self.doc, &mut remove)
            && let Some((_, x)) = &suffix
        {
            self.note_field(x);
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

    /// Allowlists. A candidate without the container the preset is for blocks: "keep only X"
    /// must never quietly keep everything.
    fn preset(&mut self, p: RedactionPreset) {
        // (container, the one key kept there), outermost first.
        let levels: Vec<(Loc, &str)> = match p {
            RedactionPreset::StatusOnly => vec![(Vec::new(), "status")],
            RedactionPreset::ErrorClassOnly => vec![
                (Vec::new(), "script_error"),
                (vec![Step::Key("script_error".into())], "class"),
            ],
        };
        let fits = levels.iter().all(|(at, keep)| {
            matches!(path::get(&self.doc, at), Some(Value::Object(o)) if o.contains_key(*keep))
        });
        if !fits {
            return self.missing(needed_path(p));
        }
        let mut gone = Vec::new();
        for (at, keep) in levels {
            if let Some(Value::Object(o)) = path::get_mut(&mut self.doc, &at) {
                let drop: Vec<String> = o.keys().filter(|k| k.as_str() != keep).cloned().collect();
                for k in drop {
                    o.remove(&k);
                    gone.push(k);
                }
            }
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
                self.dirty.insert(loc.to_vec());
                true
            }
            (Some(_), _) => {
                if let Some(v) = path::get_mut(&mut self.doc, loc) {
                    *v = Value::String(REDACTED.into());
                    self.meta.spans_masked += 1;
                    self.dirty.insert(loc.to_vec());
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

    fn set_string(&mut self, loc: &[Step], s: String) {
        if let Some(v) = path::get_mut(&mut self.doc, loc) {
            *v = Value::String(s);
            self.dirty.insert(loc.to_vec());
        }
    }

    fn mask_every(
        &mut self,
        needles: &[Needle],
        every: &[usize],
        pre: &Scan,
        url_mode: Option<UrlMode>,
    ) {
        for loc in self.string_locs() {
            let Some(info) = pre.get(Kind::Value, &loc) else {
                continue;
            };
            let hit: Vec<usize> = every.iter().copied().filter(|&i| info.hits[i]).collect();
            // Over budget: nothing about it can be known; the final pass blocks it.
            if hit.is_empty() || info.over_budget {
                continue;
            }
            if self.is_url(&loc) {
                // No choice: the value stays and the final pass blocks.
                self.url_hit(&loc, url_mode);
                continue;
            }
            let Some(Value::String(s)) = path::get(&self.doc, &loc) else {
                continue;
            };
            let original = s.clone();
            let mut cur = original.clone();
            for i in hit {
                cur = self.mask_at(&loc, cur, &needles[i], false).0;
            }
            if cur != original {
                self.set_string(&loc, cur);
            }
        }
    }

    /// Masks `value` (at `loc`), recording spans and an ambiguous result; `true` if anything
    /// was masked.
    fn mask_at(
        &mut self,
        loc: &[Step],
        value: String,
        n: &Needle,
        first_only: bool,
    ) -> (String, bool) {
        match mask_value(&value, n, first_only, &self.budget) {
            Masked::NoHit => (value, false),
            Masked::Done { value, spans } => {
                self.meta.spans_masked += spans;
                (value, true)
            }
            Masked::Ambiguous { value, spans } => {
                self.meta.spans_masked += spans;
                let at = path::display(loc);
                self.also.push(at.clone());
                self.blocked
                    .push(BlockReason::ReencodeAmbiguous { path: at });
                (value, spans > 0)
            }
        }
    }

    fn hit_now(&self, loc: &[Step], s: &str, needles: &[Needle], i: usize, pre: &Scan) -> bool {
        match pre.get(Kind::Value, loc) {
            Some(info) if !self.dirty.contains(loc) => info.hits[i],
            _ => inspect(s, std::slice::from_ref(&needles[i]), &self.budget).hits[0],
        }
    }

    fn mask_single(
        &mut self,
        needles: &[Needle],
        i: usize,
        at: Option<&str>,
        url_mode: Option<UrlMode>,
        pre: &Scan,
    ) {
        let n = &needles[i];
        let loc = match at {
            Some(p) => match path::parse(p).and_then(|pat| pat.as_loc()) {
                Some(loc) => loc,
                None => return self.missing(p),
            },
            None => {
                let first = self.string_locs().into_iter().find(|loc| {
                    matches!(path::get(&self.doc, loc), Some(Value::String(s)) if self.hit_now(loc, s, needles, i, pre))
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
        if !self.hit_now(&loc, &s, needles, i, pre) {
            return self.missing(&display);
        }
        if self.is_url(&loc) {
            if !self.url_hit(&loc, url_mode) {
                self.blocked
                    .push(BlockReason::MaskStillOccurs { path: display });
            }
            return;
        }
        let (masked, any) = self.mask_at(&loc, s, n, true);
        if !any {
            // A hit that only an encoded match across a placeholder makes (I-3).
            self.blocked
                .push(BlockReason::MaskStillOccurs { path: display });
            return;
        }
        self.set_string(&loc, masked);
        // §5.3: a per-item mask also applies to the mirrored entry (every hit in that value).
        for c in mirror::counterparts(&self.doc, self.rules.mirrors, &loc) {
            match c {
                Counterpart::Found(target, Some(_)) => {
                    if let Some(Value::String(t)) = path::get(&self.doc, &target) {
                        let t = t.clone();
                        let (masked, any) = self.mask_at(&target, t, n, false);
                        if any {
                            self.set_string(&target, masked);
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

    /// `meta.redactions.fields_dropped` reaches the agent too (review T14 I-2): a dropped name
    /// that holds an every-occurrence string, or cannot be inspected, is withheld as
    /// `[REDACTED]` (one entry per such field).
    fn redact_dropped_names(&mut self, needles: &[Needle], every: &[usize]) {
        if needles.is_empty() {
            return;
        }
        for name in &mut self.meta.fields_dropped {
            let info = inspect(name, needles, &self.budget);
            let hit = every.iter().any(|&i| info.hits[i]);
            if hit || info.over_budget || (info.unstable && !every.is_empty()) {
                *name = REDACTED.to_owned();
                if hit {
                    self.meta.spans_masked += 1;
                }
            }
        }
    }

    /// §5.3 rules 3/4: any remaining hit of an every-occurrence string (value, number text,
    /// key), and any value still changing after 3 rounds, blocks the release; so does, for any
    /// mask, a text over the work budget.
    fn final_pass(&mut self, post: &Scan, every: &[usize]) {
        let ambiguous: HashSet<String> = self
            .blocked
            .iter()
            .filter(|b| matches!(b, BlockReason::ReencodeAmbiguous { .. }))
            .map(|b| b.path().to_owned())
            .collect();
        for ((_, loc), info) in post.iter() {
            let at = path::display(loc);
            if info.over_budget || (info.unstable && !every.is_empty()) {
                self.blocked
                    .push(BlockReason::UnstableEncoding { path: at.clone() });
                self.also.push(at.clone());
            }
            if every.iter().any(|&i| info.hits[i]) && !ambiguous.contains(&at) {
                self.blocked
                    .push(BlockReason::MaskStillOccurs { path: at.clone() });
                self.also.push(at);
            }
        }
    }

    /// Occurrences of needle `i` left in the released candidate (values, number text, keys,
    /// dropped field names).
    fn count_left(&self, post: &Scan, needles: &[Needle], i: usize) -> u64 {
        let n = &needles[i];
        let in_doc: u64 = post
            .iter()
            .filter(|(_, info)| info.hits[i])
            .filter_map(|(key, _)| text_at(&self.doc, key))
            .map(|s| n.count(&s, &self.budget).max(1))
            .sum();
        let in_names: u64 = self
            .meta
            .fields_dropped
            .iter()
            .map(|name| n.count(name, &self.budget))
            .sum();
        in_doc + in_names
    }
}

fn needed_path(p: RedactionPreset) -> &'static str {
    match p {
        RedactionPreset::StatusOnly => "status",
        RedactionPreset::ErrorClassOnly => "script_error.class",
    }
}

/// Registry copies of field `x` under the item root `base` (item-relative), plus the
/// document-root copies for a drop across all items. `true` if any copy exists.
fn copies(
    rules: &RedactionRules,
    doc: &Value,
    base: &[Step],
    x: &str,
    all_items: bool,
    remove: &mut BTreeSet<Loc>,
) -> bool {
    let mut found = false;
    let mut add = |remove: &mut BTreeSet<Loc>, locs: Vec<Loc>| {
        found |= !locs.is_empty();
        remove.extend(locs);
    };
    for rule in rules.copies {
        match rule {
            CopyRule::Path(p) => {
                if let Some(pat) = path::parse(p) {
                    add(remove, pat.substitute(FIELD, x).resolve_at(doc, base));
                }
            }
            CopyRule::RootPath(p) => {
                if all_items && let Some(pat) = path::parse(p) {
                    add(remove, pat.substitute(FIELD, x).resolve(doc));
                }
            }
            CopyRule::ChangelogItems {
                items_path,
                key_fields,
            } => {
                let Some(pat) = path::parse(items_path) else {
                    continue;
                };
                for arr_loc in pat.resolve_at(doc, base) {
                    let Some(Value::Array(items)) = path::get(doc, &arr_loc) else {
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
