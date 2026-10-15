// Locations in the candidate and the redaction ops built on them (spec 5.3, C.7). Ops are written
// in the redaction path grammar (`crates/core/src/redact/path.rs`): dot-separated keys, `[3]` an
// element, `[k=v]` the elements whose field `k` is the string `v`, a leading selector-only segment
// for a root array. The UI only builds ops; whether they hold is Rust's decision (spec 2.4).

import type { DropScope, RedactionOp, RedactionPreset, UrlMode } from '../../shared/ipc/types';

/** spec 5.3: the placeholder a mask leaves. A selection of exactly it is refused (M3 plan ~1724). */
export const REDACTED = '[REDACTED]';

/**
 * A unique identity of an array element: its string field `key` (`id`, else `key`) holds `value`,
 * which no other element of the same array spells the same way. A `[key=value]` selector built on
 * it names this element whatever other drops removed before it.
 */
export interface Ident {
  key: string;
  value: string;
}

/** One step from the root: an object key, or an array element (with its identity when it has one). */
export type Step = { key: string } | { index: number; ident: Ident | null };

export type Loc = readonly Step[];

/** The fields an element's identity is read from, in order (the Jira mirror key is `id`). */
export const IDENT_KEYS = ['id', 'key'] as const;

/**
 * N-6: a key the grammar cannot name. `.`, `[` and `]` split or open a segment, `*` is the
 * any-key wildcard, an empty key is an empty segment. A path is never built through one.
 */
export function addressable(key: string): boolean {
  return key !== '' && key !== '*' && !/[.[\]]/.test(key);
}

/** A string that can stand in a `[k=v]` selector (`[` or `]` would end or break it). */
export function selectorSafe(value: string): boolean {
  return !/[[\]]/.test(value);
}

/** The position of the first key on `loc` that cannot be addressed, or -1. */
export function firstUnaddressable(loc: Loc): number {
  return loc.findIndex((s) => 'key' in s && !addressable(s.key));
}

/**
 * `loc` in the path grammar, or null through a key that cannot be addressed. Elements are named by
 * their identity selector when `selectors` and they have one, by index otherwise.
 */
export function pathOf(loc: Loc, selectors = true): string | null {
  let out = '';
  for (const step of loc) {
    if ('key' in step) {
      if (!addressable(step.key)) return null;
      out += out === '' ? step.key : `.${step.key}`;
    } else {
      out +=
        selectors && step.ident !== null
          ? `[${step.ident.key}=${step.ident.value}]`
          : `[${step.index}]`;
    }
  }
  return out;
}

/** The plain `name[3]` form Rust reports locations in (`also appears in`, `at`); null as `pathOf`. */
export const concreteOf = (loc: Loc): string | null => pathOf(loc, false);

/** The display form of a location, any key included (for text only, never an op). */
export function displayOf(loc: Loc): string {
  let out = '';
  for (const step of loc) {
    if ('key' in step) out += out === '' ? step.key : `.${step.key}`;
    else out += `[${step.index}]`;
  }
  return out === '' ? '(root)' : out;
}

/** Whether `loc` names an element by index (no identity): its meaning moves when an earlier element goes. */
export function indexDependent(loc: Loc): boolean {
  return loc.some((s) => 'index' in s && s.ident === null);
}

const isElement = (loc: Loc): boolean => {
  const last = loc[loc.length - 1];
  return last !== undefined && 'index' in last;
};

/** Whether a field drop "across all items" means more than this item: an element on the way. */
export const inItems = (loc: Loc): boolean => loc.slice(0, -1).some((s) => 'index' in s);

/**
 * "Drop item" of the element at `loc` (spec 5.3 drop items): by its identity (`drop_item {array_loc,
 * key, value}`) when it has one and its array is not the root, else as a field drop of the element
 * itself (`drop_field {field_loc: "...[3]"}`, which Rust removes from its array, mirrors included).
 * Null when `loc` is not an element or cannot be addressed.
 */
export function dropItemOp(loc: Loc): RedactionOp | null {
  const last = loc[loc.length - 1];
  if (last === undefined || !('index' in last)) return null;
  const parent = loc.slice(0, -1);
  if (last.ident !== null && parent.length > 0) {
    const arrayLoc = pathOf(parent);
    if (arrayLoc === null) return null;
    return { drop_item: { array_loc: arrayLoc, key: last.ident.key, value: last.ident.value } };
  }
  const fieldLoc = pathOf(loc);
  return fieldLoc === null ? null : { drop_field: { field_loc: fieldLoc, scope: 'per_item' } };
}

/** "Drop field" (this item, or across all items) of the object member at `loc`. */
export function dropFieldOp(loc: Loc, scope: DropScope): RedactionOp | null {
  if (loc.length === 0 || isElement(loc)) return null;
  if (scope === 'all_items' && !inItems(loc)) return null;
  const fieldLoc = pathOf(loc);
  return fieldLoc === null ? null : { drop_field: { field_loc: fieldLoc, scope } };
}

/** The drop of `loc` itself: an element as an item, a member as a field of this item. */
export const dropOf = (loc: Loc): RedactionOp | null =>
  isElement(loc) ? dropItemOp(loc) : dropFieldOp(loc, 'per_item');

/**
 * "Mask text" (spec 5.3): every occurrence by default; `at` (the value's plain location) masks the
 * one occurrence there. Null for a text the UI refuses: empty, or exactly the placeholder.
 */
export function maskOp(text: string, at: Loc | null): RedactionOp | null {
  if (text === '' || text === REDACTED) return null;
  if (at === null) return { mask_text: { text, every_occurrence: true, at: null } };
  const loc = concreteOf(at);
  return loc === null ? null : { mask_text: { text, every_occurrence: false, at: loc } };
}

export const urlFieldOp = (mode: UrlMode): RedactionOp => ({ url_field: { mode } });

export const presetOp = (preset: RedactionPreset): RedactionOp => ({ preset });

export const isDrop = (op: RedactionOp): boolean => 'drop_item' in op || 'drop_field' in op || 'preset' in op;

export const isMask = (op: RedactionOp): boolean => 'mask_text' in op;

export const isSingleMask = (op: RedactionOp): boolean =>
  'mask_text' in op && !op.mask_text.every_occurrence;

/** JSON with object keys sorted, so equal ops have equal text whatever order their keys came in. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (typeof v === 'object' && v !== null) {
    const entries = Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${canonical(x)}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/** One op of the panel's unsent round, with the location it was built on (null for text-only ops). */
export interface RoundOp {
  op: RedactionOp;
  loc: Loc | null;
}

function compareLoc(a: Loc, b: Loc): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i] as Step;
    const y = b[i] as Step;
    if ('key' in x && 'key' in y) {
      if (x.key !== y.key) return x.key < y.key ? -1 : 1;
    } else if ('index' in x && 'index' in y) {
      if (x.index !== y.index) return x.index - y.index;
    } else {
      return 'key' in x ? -1 : 1;
    }
  }
  return a.length - b.length;
}

/**
 * The round in the order Rust may apply it. Rust resolves each drop against the document the
 * earlier drops left, so an element named by index must be resolved before anything removes an
 * element ahead of it: drops by index go first, later elements and children before earlier ones and
 * parents (reverse document order); everything named without an index (keys, identities, masks,
 * presets) follows in the order it was added.
 */
export function ordered(round: readonly RoundOp[]): RedactionOp[] {
  const byIndex = round.filter((r) => r.loc !== null && isDrop(r.op) && indexDependent(r.loc));
  const rest = round.filter((r) => !byIndex.includes(r));
  byIndex.sort((a, b) => compareLoc(b.loc as Loc, a.loc as Loc));
  return [...byIndex, ...rest].map((r) => r.op);
}

type PatternStep = { name: string } | { all: true } | { index: number };

/** A `url_fields` pattern (`name`, `*`, `[]`, `[3]`, a leading `[]` segment) as steps; null if not one. */
function patternSteps(pattern: string): PatternStep[] | null {
  const out: PatternStep[] = [];
  const segments = pattern.split('.');
  for (const [i, seg] of segments.entries()) {
    const m = /^([^[\]]*)((?:\[\d*\])*)$/.exec(seg);
    if (m === null) return null;
    const [, name = '', sels = ''] = m;
    if (name === '' && (i > 0 || sels === '')) return null;
    if (name !== '') out.push({ name });
    for (const s of sels.matchAll(/\[(\d*)\]/g)) {
      out.push(s[1] === '' ? { all: true } : { index: Number(s[1]) });
    }
  }
  return out;
}

/**
 * Whether `loc` is a URL-valued field of the op (`RedactionRules::url_fields`, as Rust's
 * `Pattern::matches`): only to mark it in the tree; what a mask does there is Rust's to decide.
 */
export function isUrlField(patterns: readonly string[], loc: Loc): boolean {
  return patterns.some((p) => {
    const steps = patternSteps(p);
    if (steps === null || steps.length !== loc.length) return false;
    return steps.every((s, i) => {
      const at = loc[i] as Step;
      if ('name' in s) return 'key' in at && (s.name === '*' || s.name === at.key);
      if ('all' in s) return 'index' in at;
      return 'index' in at && at.index === s.index;
    });
  });
}

/** Whether `loc` lies at or under `under`. */
export function within(loc: Loc, under: Loc): boolean {
  return under.length <= loc.length && compareLoc(loc.slice(0, under.length), under) === 0;
}
