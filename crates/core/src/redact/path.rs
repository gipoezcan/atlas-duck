//! The redaction path grammar (plan-named) and concrete JSON locations.
//!
//! A pattern is dot-separated segments: `name` (object key), `*` (any one key), followed by any
//! number of selectors `[]` (every element), `[3]` (one element) or `[key=value]` (elements whose
//! field `key` is the string `value`, or a number/bool spelled `value`). A first segment may be
//! selectors only (`[].self`: the elements of a root array). Reported locations use `name[3]`.

use std::fmt::Write as _;

use serde_json::Value;

/// One step of a concrete location.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    Key(String),
    Index(usize),
}

/// A concrete location in a document. Ordered so that iterating a set of locations in reverse
/// removes children before parents and later array elements before earlier ones.
pub(crate) type Loc = Vec<Step>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Sel {
    All,
    Index(usize),
    Eq(String, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seg {
    /// `None`: a leading selector-only segment.
    name: Option<String>,
    sels: Vec<Sel>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pattern(Vec<Seg>);

/// `None` for an empty or malformed path.
pub(crate) fn parse(s: &str) -> Option<Pattern> {
    let mut segs = Vec::new();
    for (i, part) in split_top(s)?.into_iter().enumerate() {
        let (name, mut rest) = match part.find('[') {
            Some(b) => (&part[..b], &part[b..]),
            None => (part, ""),
        };
        let mut sels = Vec::new();
        while !rest.is_empty() {
            let close = rest.find(']')?;
            if !rest.starts_with('[') {
                return None;
            }
            let inner = &rest[1..close];
            sels.push(if inner.is_empty() {
                Sel::All
            } else if inner.bytes().all(|b| b.is_ascii_digit()) {
                Sel::Index(inner.parse().ok()?)
            } else {
                let (k, v) = inner.split_once('=')?;
                if k.is_empty() {
                    return None;
                }
                Sel::Eq(k.to_owned(), v.to_owned())
            });
            rest = &rest[close + 1..];
        }
        let name = match (name.is_empty(), i) {
            (true, 0) if !sels.is_empty() => None,
            (true, _) => return None,
            (false, _) => Some(name.to_owned()),
        };
        segs.push(Seg { name, sels });
    }
    Some(Pattern(segs))
}

/// Splits at `.` outside brackets; `None` for an empty path, an empty segment or unbalanced
/// brackets.
fn split_top(s: &str) -> Option<Vec<&str>> {
    if s.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' if depth == 0 => depth = 1,
            '[' => return None,
            ']' => depth = depth.checked_sub(1)?,
            '.' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    parts.push(&s[start..]);
    if parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(parts)
}

impl Pattern {
    /// Every element selector before the last segment becomes `[]` (a drop "across all
    /// items"). The last segment keeps its selectors: `issues[key=A]` still names one issue.
    pub(crate) fn widened(mut self) -> Pattern {
        let n = self.0.len();
        for seg in self.0.iter_mut().take(n.saturating_sub(1)) {
            for sel in &mut seg.sels {
                *sel = Sel::All;
            }
        }
        self
    }

    /// For a pattern ending in plain `fields.<X>`: the item-root pattern before it (empty =
    /// the document root) and `X`.
    pub(crate) fn field_suffix(&self) -> Option<(Pattern, String)> {
        let [base @ .., f, x] = self.0.as_slice() else {
            return None;
        };
        let plain = |s: &Seg, want: Option<&str>| {
            s.sels.is_empty()
                && match (s.name.as_deref(), want) {
                    (Some(n), Some(w)) => n == w,
                    (Some(n), None) => n != "*",
                    (None, _) => false,
                }
        };
        (plain(f, Some("fields")) && plain(x, None))
            .then(|| (Pattern(base.to_vec()), x.name.clone().unwrap_or_default()))
    }

    /// Replaces every segment named `from` by `to` (the `{field}` placeholder of copy rules).
    pub(crate) fn substitute(mut self, from: &str, to: &str) -> Pattern {
        for seg in &mut self.0 {
            if seg.name.as_deref() == Some(from) {
                seg.name = Some(to.to_owned());
            }
        }
        self
    }

    /// The pattern as a concrete location, if it has no wildcard and no `[]`/`[k=v]` selector.
    pub(crate) fn as_loc(&self) -> Option<Loc> {
        let mut loc = Vec::new();
        for seg in &self.0 {
            match seg.name.as_deref() {
                Some("*") => return None,
                Some(n) => loc.push(Step::Key(n.to_owned())),
                None => {}
            }
            for sel in &seg.sels {
                match sel {
                    Sel::Index(i) => loc.push(Step::Index(*i)),
                    _ => return None,
                }
            }
        }
        Some(loc)
    }

    /// Existing locations under `base` (document order).
    pub(crate) fn resolve_at(&self, doc: &Value, base: &[Step]) -> Vec<Loc> {
        let Some(start) = get(doc, base) else {
            return Vec::new();
        };
        let mut cur: Vec<(Loc, &Value)> = vec![(base.to_vec(), start)];
        for seg in &self.0 {
            let mut next = Vec::new();
            for (loc, v) in cur {
                match seg.name.as_deref() {
                    None => next.push((loc, v)),
                    Some("*") => {
                        if let Value::Object(o) = v {
                            for (k, x) in o {
                                next.push((with(&loc, Step::Key(k.clone())), x));
                            }
                        }
                    }
                    Some(n) => {
                        if let Some(x) = v.get(n) {
                            next.push((with(&loc, Step::Key(n.to_owned())), x));
                        }
                    }
                }
            }
            for sel in &seg.sels {
                let mut out = Vec::new();
                for (loc, v) in next {
                    let Value::Array(a) = v else { continue };
                    for (i, e) in a.iter().enumerate() {
                        let keep = match sel {
                            Sel::All => true,
                            Sel::Index(j) => i == *j,
                            Sel::Eq(k, val) => e.get(k).is_some_and(|x| scalar_is(x, val)),
                        };
                        if keep {
                            out.push((with(&loc, Step::Index(i)), e));
                        }
                    }
                }
                next = out;
            }
            cur = next;
        }
        cur.into_iter().map(|(l, _)| l).collect()
    }

    pub(crate) fn resolve(&self, doc: &Value) -> Vec<Loc> {
        self.resolve_at(doc, &[])
    }

    /// Whether the concrete `loc` is one this pattern addresses (`[k=v]` never matches here;
    /// `url_fields` use only `name`, `*` and `[]`).
    pub(crate) fn matches(&self, loc: &[Step]) -> bool {
        let mut i = 0;
        for seg in &self.0 {
            match (seg.name.as_deref(), loc.get(i)) {
                (None, _) => {}
                (Some("*"), Some(Step::Key(_))) => i += 1,
                (Some(n), Some(Step::Key(k))) if n == k => i += 1,
                _ => return false,
            }
            for sel in &seg.sels {
                match (sel, loc.get(i)) {
                    (Sel::All, Some(Step::Index(_))) => i += 1,
                    (Sel::Index(j), Some(Step::Index(k))) if j == k => i += 1,
                    _ => return false,
                }
            }
        }
        i == loc.len()
    }
}

/// `[k=v]` compares a string field, or a number/bool by its JSON spelling.
pub(crate) fn scalar_is(x: &Value, val: &str) -> bool {
    match x {
        Value::String(s) => s == val,
        Value::Number(n) => n.to_string() == val,
        Value::Bool(b) => b.to_string() == val,
        _ => false,
    }
}

pub(crate) fn with(loc: &[Step], step: Step) -> Loc {
    let mut l = loc.to_vec();
    l.push(step);
    l
}

pub(crate) fn join(a: &[Step], b: &[Step]) -> Loc {
    let mut l = a.to_vec();
    l.extend_from_slice(b);
    l
}

/// `a.b` as key steps.
pub(crate) fn keys(dotted: &str) -> Loc {
    dotted.split('.').map(|k| Step::Key(k.to_owned())).collect()
}

/// `name[3]` form: keys joined by `.`, indexes appended.
pub(crate) fn display(loc: &[Step]) -> String {
    let mut s = String::new();
    for step in loc {
        match step {
            Step::Key(k) => {
                if !s.is_empty() {
                    s.push('.');
                }
                s.push_str(k);
            }
            Step::Index(i) => {
                let _ = write!(s, "[{i}]");
            }
        }
    }
    s
}

pub(crate) fn get<'a>(doc: &'a Value, loc: &[Step]) -> Option<&'a Value> {
    let mut v = doc;
    for step in loc {
        v = match step {
            Step::Key(k) => v.as_object()?.get(k)?,
            Step::Index(i) => v.as_array()?.get(*i)?,
        };
    }
    Some(v)
}

pub(crate) fn get_mut<'a>(doc: &'a mut Value, loc: &[Step]) -> Option<&'a mut Value> {
    let mut v = doc;
    for step in loc {
        v = match step {
            Step::Key(k) => v.as_object_mut()?.get_mut(k)?,
            Step::Index(i) => v.as_array_mut()?.get_mut(*i)?,
        };
    }
    Some(v)
}

/// Removes the key or element at `loc`; never writes a placeholder.
pub(crate) fn remove(doc: &mut Value, loc: &[Step]) -> Option<Value> {
    let (last, parent) = loc.split_last()?;
    match (get_mut(doc, parent)?, last) {
        (Value::Object(o), Step::Key(k)) => o.remove(k),
        (Value::Array(a), Step::Index(i)) if *i < a.len() => Some(a.remove(*i)),
        _ => None,
    }
}

/// Every node of `v` with its location, in document order (keys sorted, elements in order).
pub(crate) fn walk<'a>(v: &'a Value, loc: &mut Loc, f: &mut impl FnMut(&[Step], &'a Value)) {
    f(loc, v);
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                loc.push(Step::Key(k.clone()));
                walk(x, loc, f);
                loc.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                loc.push(Step::Index(i));
                walk(x, loc, f);
                loc.pop();
            }
        }
        _ => {}
    }
}
