import { describe, expect, it } from 'vitest';

import { members, readCandidate, scalarText, stringOf, CANDIDATE_MAX_BYTES } from './json';
import {
  addressable,
  canonical,
  dropFieldOp,
  dropItemOp,
  firstUnaddressable,
  isUrlField,
  maskOp,
  ordered,
  pathOf,
  type Loc,
  type RoundOp,
} from './paths';
import { draftOf, releaseReady } from './state';
import { TreeModel, type TreeNode } from './Tree';

const enc = (s: string) => new TextEncoder().encode(s);
const k = (key: string) => ({ key });
const i = (index: number, id: string | null = null) => ({
  index,
  ident: id === null ? null : { key: 'id', value: id },
});

describe('paths in the redaction grammar', () => {
  it('n6_unaddressable_keys_are_never_in_a_path', () => {
    for (const bad of ['user.email', 'a[0]', 'b]', '*', '']) {
      expect(addressable(bad)).toBe(false);
      const loc: Loc = [k('fields'), k(bad), k('x')];
      expect(pathOf(loc)).toBeNull();
      expect(firstUnaddressable(loc)).toBe(1);
      expect(dropFieldOp(loc, 'per_item')).toBeNull();
      expect(maskOp('t', loc)).toBeNull();
    }
    // `=`, spaces, `a*b` and non-ASCII are fine as names.
    for (const ok of ['a=b', 'a b', 'a*b', 'Müller']) expect(addressable(ok)).toBe(true);
    expect(pathOf([k('fields'), k('a=b')])).toBe('fields.a=b');
  });

  it('drop_item_and_field_ops_shapes', () => {
    const comment: Loc = [k('fields'), k('comment'), k('comments'), i(1, '10002')];
    expect(dropItemOp(comment)).toEqual({
      drop_item: { array_loc: 'fields.comment.comments', key: 'id', value: '10002' },
    });
    // Without an identity the element is dropped as a field at its index.
    expect(dropItemOp([k('fields'), k('labels'), i(2)])).toEqual({
      drop_field: { field_loc: 'fields.labels[2]', scope: 'per_item' },
    });
    // A root array has no array path: its element is a selector-only first segment.
    expect(dropItemOp([i(0, 'x')])).toEqual({ drop_field: { field_loc: '[id=x]', scope: 'per_item' } });
    expect(dropItemOp([i(3)])).toEqual({ drop_field: { field_loc: '[3]', scope: 'per_item' } });
    // Parents are named by identity where they have one, by index where not.
    const field: Loc = [k('issues'), i(0, 'ABC-1'), k('fields'), k('summary')];
    expect(dropFieldOp(field, 'per_item')).toEqual({
      drop_field: { field_loc: 'issues[id=ABC-1].fields.summary', scope: 'per_item' },
    });
    expect(dropFieldOp(field, 'all_items')).toEqual({
      drop_field: { field_loc: 'issues[id=ABC-1].fields.summary', scope: 'all_items' },
    });
    // "All items" only where an element lies on the way; an element is no field.
    expect(dropFieldOp([k('fields'), k('summary')], 'all_items')).toBeNull();
    expect(dropFieldOp([k('labels'), i(0)], 'per_item')).toBeNull();
    expect(dropItemOp([k('fields')])).toBeNull();
  });

  it('mask_every_occurrence_default_single_sets_at', () => {
    expect(maskOp('Falcon', null)).toEqual({ mask_text: { text: 'Falcon', every_occurrence: true, at: null } });
    // `at` is the plain location (Rust: `as_loc`, no selectors), even for an element with an identity.
    const at: Loc = [k('fields'), k('comment'), k('comments'), i(1, '10002'), k('body')];
    expect(maskOp('Falcon', at)).toEqual({
      mask_text: { text: 'Falcon', every_occurrence: false, at: 'fields.comment.comments[1].body' },
    });
  });

  it('redacted_placeholder_selection_refused', () => {
    expect(maskOp('[REDACTED]', null)).toBeNull();
    expect(maskOp('', null)).toBeNull();
    expect(maskOp('[REDACTED] x', null)).not.toBeNull();
  });

  it('round_drops_by_index_go_first_in_reverse_document_order', () => {
    const drop = (loc: Loc): RoundOp => ({ op: dropItemOp(loc) ?? dropFieldOp(loc, 'per_item')!, loc });
    const a0 = drop([k('labels'), i(0)]);
    const a2 = drop([k('labels'), i(2)]);
    const child = drop([k('items'), i(1), k('name')]);
    const parent = drop([k('items'), i(1)]);
    const byId = drop([k('items'), i(4, 'z')]);
    const mask: RoundOp = { op: maskOp('t', null)!, loc: null };
    const out = ordered([byId, a0, mask, parent, a2, child]);
    expect(out).toEqual([a2.op, a0.op, child.op, parent.op, byId.op, mask.op]);
  });

  it('canonical_sorts_keys_at_every_depth', () => {
    expect(canonical({ b: 1, a: [{ d: 1, c: 2 }] })).toBe('{"a":[{"c":2,"d":1}],"b":1}');
    expect(canonical({ a: 1, b: 2 })).toBe(canonical({ b: 2, a: 1 }));
  });

  it('url_fields_match_like_rust', () => {
    const p = ['self', '_links.*', 'results[]._links.*', '[].self'];
    expect(isUrlField(p, [k('self')])).toBe(true);
    expect(isUrlField(p, [k('_links'), k('webui')])).toBe(true);
    expect(isUrlField(p, [k('results'), i(3), k('_links'), k('base')])).toBe(true);
    expect(isUrlField(p, [i(0), k('self')])).toBe(true);
    expect(isUrlField(p, [k('fields'), k('self')])).toBe(false);
    expect(isUrlField(p, [k('_links')])).toBe(false);
  });
});

describe('the draft Release sends', () => {
  const X = { drop_field: { field_loc: 'fields.summary', scope: 'per_item' as const } };
  const Y: RoundOp = { op: dropFieldOp([k('fields'), k('labels')], 'per_item')!, loc: [k('fields'), k('labels')] };
  const M: RoundOp = { op: maskOp('Falcon', null)!, loc: null };

  it('keeps_the_revision_ops_in_front_and_adds_the_url_choice_with_a_mask', () => {
    const ctx = { ops: [X], url_fields: [] };
    expect(draftOf(ctx, [], null, false)).toMatchObject({ ops: [X], unsent: false });
    expect(draftOf(ctx, [Y], null, false).ops).toEqual([X, Y.op]);
    expect(draftOf(ctx, [M], null, false).ops).toEqual([X, M.op, { url_field: { mode: 'replace_whole' } }]);
    expect(draftOf(ctx, [M], 'drop', false).ops).toEqual([X, M.op, { url_field: { mode: 'drop' } }]);
    // Remove all: no ops at all (a revision with the full candidate).
    expect(draftOf(ctx, [Y], null, true)).toMatchObject({ ops: [], unsent: true });
    // A mode equal to the revision's own changes nothing.
    const withMode = { ops: [X, { url_field: { mode: 'drop' as const } }], url_fields: [] };
    expect(draftOf(withMode, [], 'drop', false).unsent).toBe(false);
    expect(draftOf(withMode, [], 'replace_whole', false).unsent).toBe(true);
  });

  it('release_ready_only_for_the_report_of_these_ops_on_this_revision', () => {
    const draft = draftOf({ ops: [], url_fields: [] }, [Y], null, false);
    const ok = { blocked: [], also_appears_in: [], other_occurrences: 0, released_bytes: 1 };
    expect(releaseReady(draft, 'r1', null, null)).toBe(false);
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, report: ok }, null)).toBe(true);
    expect(releaseReady(draft, 'r1', { rev: 'r0', key: draft.key, report: ok }, null)).toBe(false);
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: '[]', report: ok }, null)).toBe(false);
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, failed: true }, null)).toBe(false);
    const blocked = { ...ok, blocked: [{ reason: 'op_target_missing', path: 'x' }] };
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, report: blocked }, null)).toBe(false);
    const others = { ...ok, other_occurrences: 2 };
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, report: others }, null)).toBe(false);
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, report: others }, '[]')).toBe(false);
    expect(releaseReady(draft, 'r1', { rev: 'r1', key: draft.key, report: others }, draft.key)).toBe(true);
    // Nothing unsent: the shown revision is released as it is, no report needed.
    expect(releaseReady(draftOf({ ops: [], url_fields: [] }, [], null, false), 'r1', null, null)).toBe(true);
  });
});

describe('the candidate text', () => {
  it('reads_exact_bytes_and_refuses_what_is_not_json', () => {
    expect(readCandidate(new Uint8Array([0x7b, 0xff, 0x7d]))).toBeNull();
    expect(readCandidate(enc('{"a":'))).toBeNull();
    expect(readCandidate(enc('{"a":1} x'))).toBeNull();
    expect(readCandidate(new Uint8Array(CANDIDATE_MAX_BYTES + 1))).toBeNull();
    const c = readCandidate(enc('{"z":1.0,"__proto__":"p","a\\"b":"x\\u0041\\n","n":[true,null,-2e3]}'));
    expect(c).not.toBeNull();
    if (c === null) return;
    const m = members(c.text, c.root);
    // The bytes' order, keys decoded, numbers as spelled.
    expect(m.map((x) => x.key)).toEqual(['z', '__proto__', 'a"b', 'n']);
    expect(scalarText(c.text, m[0]!.span)).toBe('1.0');
    expect(stringOf(c.text, m[2]!.span)).toBe('xA\n');
    expect(members(c.text, m[3]!.span).map((x) => scalarText(c.text, x.span))).toEqual(['true', 'null', '-2e3']);
  });

  it('identities_are_unique_selector_safe_strings', () => {
    const doc = {
      a: [{ id: '1' }, { id: '2' }, { id: '2' }, { key: 'K' }, { id: 7 }, { id: '7' }, { id: 'x]' }, 'plain', { id: 8 }],
    };
    const c = readCandidate(enc(JSON.stringify(doc)));
    if (c === null) throw new Error('not read');
    const model = new TreeModel(c);
    const [arr] = model.children(model.root) as [TreeNode];
    const idents = model.children(arr).map((n) => {
      const last = n.loc[n.loc.length - 1];
      return last !== undefined && 'index' in last ? last.ident : 'no index';
    });
    expect(idents).toEqual([
      { key: 'id', value: '1' },
      null, // "2" twice
      null,
      { key: 'key', value: 'K' },
      null, // a number is no identity
      null, // "7" is spelled by the number 7 too: `[id=7]` would match both
      null, // a bracket would break the selector
      null,
      null, // a unique number is still no identity (`drop_item` compares JSON values exactly)
    ]);
  });
});
