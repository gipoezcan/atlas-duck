//! [`apply`]: drops with copies and mirrors, mirror check, masks, final pass (§5.3).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;

use atlas_duck_registry::{CopyRule, RedactionRules};
use serde_json::Value;

use super::mirror::{self, Counterpart, DroppedOnEntry, Flagged};
use super::path::{self, Ident, Loc, Pattern, Step};
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
        flagged: mirror::flagged(candidate, rules.mirrors),
        removed: Vec::new(),
        origin: HashMap::new(),
        keys: mirror::Keys::default(),
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
    // §5.3 mirror check after the drops and before any mask, on the keys as the source shows
    // them; an entry the source's check flags blocks unless it was dropped whole (review T19c
    // I-1).
    mirror::check(&r.doc, rules.mirrors, &r.dropped_on_entries, &mut r.blocked);
    r.blocked.extend(r.flagged.iter().map(Flagged::reason));
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
    let post = Scan::new(&r.doc, &needles, Some((&pre, &r.dirty)), &r.budget);
    r.redact_dropped_names(&needles, &every);
    if !needles.is_empty() {
        r.final_pass(&post, &every);
    }
    let left: Vec<u64> = singles
        .iter()
        .map(|&(i, _)| r.count_left(&post, &needles, i))
        .collect();
    let needs_confirmation = left
        .iter()
        .filter_map(|&left| match left {
            0 => None,
            1 => Some("1 other occurrence remains".to_owned()),
            _ => Some(format!("{left} other occurrences remain")),
        })
        .collect();
    RedactionOutcome {
        released: r.doc,
        meta: r.meta,
        blocked: dedup(r.blocked),
        needs_confirmation,
        other_occurrences: left.iter().fold(0, |a, &n| a.saturating_add(n)),
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
    /// The entries the source's mirror check flags that are still in `doc`, where they now are.
    flagged: Vec<Flagged>,
    /// Every location the drop phase removed, in order: what follows a source location to where
    /// it is now (review T19c I-1').
    removed: Vec<Loc>,
    /// Every array the drop phase removed elements from, by its source location: the source
    /// index of each element still there. What maps a location back to the source in O(depth);
    /// undoing `removed` cost O(removals) per lookup (review T19c fix2 I-2).
    origin: HashMap<Loc, Vec<usize>>,
    /// The mirror keys the pairing computed since the last removal (review T19c fix2 I-2).
    keys: mirror::Keys,
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

    /// The source location of `cur`, a location in `doc`: the drop phase's removals undone
    /// through `origin` (only a removed element moves a location).
    fn source_loc(&self, cur: &[Step]) -> Loc {
        let mut at = Vec::with_capacity(cur.len());
        for step in cur {
            let step = match step {
                Step::Index(i) => Step::Index(match self.origin.get(&at) {
                    Some(left) => match left.get(*i) {
                        Some(&s) => s,
                        // Past the end: as far past the source's.
                        None => i - left.len() + self.source_len(&at),
                    },
                    None => *i,
                }),
                Step::Key(_) => step.clone(),
            };
            at.push(step);
        }
        at
    }

    /// The length of the source's array at `src`.
    fn source_len(&self, src: &[Step]) -> usize {
        path::get(self.original, src)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    /// Field `key` of the element at `cur` as the source has it. The drop phase only removes,
    /// so where the element still has `key` it is the same value; where it has not, a drop took
    /// the key and the element is still the source's (review T19c I-1').
    fn source_field(&self, cur: &[Step], key: &str) -> Option<Value> {
        path::get(self.original, &self.source_loc(cur))?
            .get(key)
            .cloned()
    }

    /// Whether the source location `src` went whole with an earlier removal.
    fn went(&self, src: &[Step]) -> bool {
        let mut at = src.to_vec();
        !self
            .removed
            .iter()
            .all(|removed| path::after_removal(&mut at, removed))
    }

    fn elements(
        doc: &Value,
        pat: &Pattern,
        key: &str,
        value: &Value,
        ident: &Ident<'_>,
    ) -> Vec<Loc> {
        let mut out = Vec::new();
        for arr in pat.resolve_at_by(doc, &[], ident) {
            if let Some(Value::Array(a)) = path::get(doc, &arr) {
                for (i, e) in a.iter().enumerate() {
                    let at = path::with(&arr, Step::Index(i));
                    let hit = match e.get(key) {
                        Some(v) => v == value,
                        None => ident(&at, key).as_ref() == Some(value),
                    };
                    if hit {
                        out.push(at);
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
        // Identity is the source's: an element whose key an earlier op dropped is still named.
        let ident = |l: &[Step], k: &str| self.source_field(l, k);
        let targets = Self::elements(&self.doc, &pat, key, value, &ident);
        // The UI offers only what is there: matching nothing is a mismatch (e.g. a key holding
        // `.`), not a no-op, unless every element it names in the source went whole with an
        // earlier op (L123, M8 T19c). One still there (an array named past a shifted index)
        // cannot be proven gone and is refused (review T19c I-1').
        if targets.is_empty() {
            let named = Self::elements(self.original, &pat, key, value, &path::no_ident);
            if named.is_empty() || !named.iter().all(|s| self.went(s)) {
                self.missing(array_path);
            }
            return;
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
        let suffix = pat.field_suffix();
        let copies_in = |doc: &Value, ident: &Ident<'_>, remove: &mut BTreeSet<Loc>| {
            let mut copied = false;
            if let Some((base, x)) = &suffix {
                for root in base.resolve_at_by(doc, &[], ident) {
                    copied |= copies(self.rules, doc, &root, x, all_items, ident, remove);
                }
            }
            copied
        };
        let ident = |l: &[Step], k: &str| self.source_field(l, k);
        let mut remove = BTreeSet::new();
        let copied = copies_in(&self.doc, &ident, &mut remove);
        let targets = pat.resolve_at_by(&self.doc, &[], &ident);
        if targets.is_empty() && !copied {
            // As for an item drop: it must name something in the source or in the document the
            // earlier ops left (index paths resolve against the latter, the shown revision). An
            // op naming by identity is a no-op only if what it names in the source went whole;
            // a stale index is (T24: a silent no-op).
            let mut named = BTreeSet::new();
            copies_in(self.original, &path::no_ident, &mut named);
            named.extend(pat.resolve(self.original));
            if named.is_empty() || (pat.has_identity() && !named.iter().all(|s| self.went(s))) {
                self.missing(field_path);
            }
            return;
        }
        if copied && let Some((_, x)) = &suffix {
            self.note_field(x);
        }
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
        // The key alone of an entry without counterpart: the entry stays, so it blocks.
        for loc in &remove {
            if let Some(entry) = mirror::unpaired_key(&self.doc, self.rules.mirrors, loc) {
                self.blocked.push(BlockReason::MirrorOrphan {
                    path: path::display(&entry),
                });
            }
        }
        for loc in remove.iter().rev() {
            self.remove(loc);
        }
    }

    /// Removes `loc`, follows the flagged entries across it and logs it.
    fn remove(&mut self, loc: &[Step]) {
        // An element's array: where it is in the source (its own removal does not move it).
        let array = match loc.split_last() {
            Some((Step::Index(i), parent)) => Some((*i, self.source_loc(parent))),
            _ => None,
        };
        if path::remove(&mut self.doc, loc).is_some() {
            self.flagged
                .retain_mut(|f| path::after_removal(&mut f.at, loc));
            self.removed.push(loc.to_vec());
            if let Some((i, src)) = array {
                let len = self.source_len(&src);
                let left = self.origin.entry(src).or_insert_with(|| (0..len).collect());
                if i < left.len() {
                    left.remove(i);
                }
            }
            self.keys.clear();
        }
    }

    /// Within one batch of drops (`drop_locs` resolves every counterpart before it removes
    /// anything) the mirror keys are computed once per array.
    fn counterparts(&self, loc: &[Step]) -> Vec<Counterpart> {
        mirror::counterparts(
            &self.doc,
            self.rules.mirrors,
            loc,
            &|l, k| self.source_field(l, k),
            &self.keys,
        )
    }

    fn mirrored(&mut self, loc: &[Step], remove: &mut BTreeSet<Loc>) {
        for c in self.counterparts(loc) {
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
            let drop: Vec<String> = match path::get(&self.doc, &at) {
                Some(Value::Object(o)) => {
                    o.keys().filter(|k| k.as_str() != keep).cloned().collect()
                }
                _ => Vec::new(),
            };
            for k in drop {
                self.remove(&path::with(&at, Step::Key(k.clone())));
                gone.push(k);
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
        // §5.3: a per-item mask also applies to the mirrored entry (every hit in that value). It
        // pairs by the source's key, so neither this rewrite nor an earlier mask decides which
        // entry that is (review T19c fix m-1, fix2 n-3).
        let counterparts = self.counterparts(&loc);
        self.set_string(&loc, masked);
        for c in counterparts {
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
/// document-root copies for a drop across all items. `true` if any copy exists. A changelog item
/// whose key field a drop removed is matched through `ident`.
fn copies(
    rules: &RedactionRules,
    doc: &Value,
    base: &[Step],
    x: &str,
    all_items: bool,
    ident: &Ident<'_>,
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
                        .filter(|(i, it)| {
                            key_fields.iter().any(|k| match it.get(*k) {
                                Some(v) => v.as_str() == Some(x),
                                None => {
                                    ident(&path::with(&arr_loc, Step::Index(*i)), k)
                                        .as_ref()
                                        .and_then(Value::as_str)
                                        == Some(x)
                                }
                            })
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
