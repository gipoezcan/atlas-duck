import { useEffect, useId, useMemo, useRef, useState, type ReactNode, type Ref } from 'react';

import { own } from '../../shared/text/own';
import type {
  BlockReason,
  RedactionContext,
  RedactionOp,
  RedactionPreset,
  UrlMode,
} from '../../shared/ipc/types';
import { AgentText } from '../../shared/text/AgentText';
import { escapeInvisible, unusual } from '../../shared/text/unusual';
import { EDIT_ENTRY_ATTR, POSITIVE_ATTR } from '../keyboard';
import { members, stringOf } from './json';
import {
  canonical,
  concreteOf,
  displayOf,
  dropFieldOp,
  dropItemOp,
  dropOf,
  firstUnaddressable,
  inItems,
  isDrop,
  isMask,
  isSingleMask,
  isUrlField,
  locationFree,
  maskOp,
  presetOp,
  REDACTED,
  singleMaskProblem,
  within,
  type Loc,
  type RoundOp,
} from './paths';
import { baseUrlMode, type CandidateState, type Draft, type FlaggedState, type ReportState } from './state';
import { cut, Tree, TreeModel, type TreeNode } from './Tree';
import { useText } from '../../shared/i18n/context';
import type { Dict } from '../../shared/i18n';

/** The selected value's text is shown up to this many code points. */
export const VALUE_SHOWN_MAX = 100_000;

const singleProblemText = (t: Dict) =>
  ({
    bracket: t.approvals.redaction.single_bracket,
    repeated: t.approvals.redaction.single_repeated,
    encoded: t.approvals.redaction.single_encoded,
  }) as const;

/** Why the last action added nothing, next to the controls it came from. */
interface Hint {
  text: string;
  at: 'node' | 'presets';
}

/** Agent text in a line: the value as a quoted, bidi-isolated text node. */
const Text = ({ value }: { value: string }) => <AgentText value={value} unusual={unusual(value)} />;

/** One op as text: a fixed label and the op's own strings (agent or upstream text). */
function OpText({ op }: { op: RedactionOp }) {
  const t = useText();
  if ('drop_item' in op) {
    const { array_loc, key, value } = op.drop_item;
    return (
      <>
        {t.approvals.redaction.drop_item}: <Text value={array_loc} /> <Text value={`${key} = ${JSON.stringify(value)}`} />
      </>
    );
  }
  if ('drop_field' in op) {
    const label =
      op.drop_field.scope === 'all_items' ? t.approvals.redaction.drop_field_all : t.approvals.redaction.drop_field_item;
    return (
      <>
        {label}: <Text value={op.drop_field.field_loc} />
      </>
    );
  }
  if ('mask_text' in op) {
    const { text, at } = op.mask_text;
    return (
      <>
        {t.approvals.redaction.mask_add}: <Text value={text} />
        {at === null ? null : (
          <>
            {' '}
            {t.approvals.redaction.mask_only_here}: <Text value={at} />
          </>
        )}
      </>
    );
  }
  if ('url_field' in op) {
    return (
      <>
        {t.approvals.redaction.url_mode}:{' '}
        {op.url_field.mode === 'drop' ? t.approvals.redaction.url_drop : t.approvals.redaction.url_replace_whole}
      </>
    );
  }
  return (
    <>{op.preset === 'status_only' ? t.approvals.redaction.preset_status_only : t.approvals.redaction.preset_error_class_only}</>
  );
}

export interface PanelProps {
  candidate: CandidateState | null;
  context: RedactionContext;
  /** Rust's "also appears in" of the revision's own masks (`Preview.also_appears_in`), shown before release. */
  appliedAlsoAppearsIn: readonly string[];
  /** The unsent round: ops built on what this revision shows. */
  round: readonly RoundOp[];
  onRound: (round: RoundOp[]) => void;
  urlChoice: UrlMode | null;
  onUrlChoice: (mode: UrlMode) => void;
  removeAll: boolean;
  onRemoveAll: (on: boolean) => void;
  /** What Release sends (`state.ts` `draftOf`). */
  draft: Draft;
  /** Rust's report, if it is the one for `draft` on this revision (the caller checked). */
  report: ReportState | null;
  confirmed: boolean;
  onConfirm: (on: boolean) => void;
  /** The body is an upstream error card (preset "Release status only"). */
  upstreamError: boolean;
  /** The item is a script (preset "Keep error class only" for an error card). */
  script: boolean;
  /** The 5.3 mirror check blocks this revision (M-11): its flagged entries can be dropped from the tree. */
  mirrorBlocked: boolean;
  /** Rust's flagged entries of a mirror-blocked revision, once asked (the caller checked the revision). */
  flagged: FlaggedState | null;
  canRelease: boolean;
  onRelease: () => void;
  /** Text typed for a mask and not added yet: the decision path treats it as unsent. */
  onPendingInput: (pending: boolean) => void;
  ref?: Ref<HTMLElement>;
}

/**
 * The read redaction panel (spec 5.3, 6.3; plan Task 17): the candidate as a tree with per-node
 * drop and mask actions, the presets, the URL-field choice, Rust's `redaction_preview` report for
 * exactly the ops Release would send, and the Release button. Release and every gate on it live
 * in `Detail` (`send()`); this component builds ops and shows text, it decides nothing.
 */
export function Panel(props: PanelProps) {
  const t = useText();
  const { candidate, context, round, onRound, draft, removeAll, ref } = props;
  const model = useMemo(
    () => (candidate?.state === 'ready' ? new TreeModel(candidate.candidate) : null),
    [candidate],
  );
  // The drops that clear the flagged entries: a tree walk per entry, so only when the tree or the list changes.
  const probe = props.flagged;
  const flaggedPlan = useMemo(
    () => (model === null || probe === null || 'failed' in probe ? null : flaggedRound(model, probe.flagged)),
    [model, probe],
  );
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(new Set());
  const [selected, setSelected] = useState<TreeNode | null>(null);
  const [maskText, setMaskText] = useState('');
  const [onlyHere, setOnlyHere] = useState(false);
  const [hint, setHint] = useState<Hint | null>(null);
  const valueRef = useRef<HTMLDivElement>(null);
  const releaseHint = useId();
  const { onPendingInput } = props;

  // The root starts open (a fresh model on a new revision).
  useEffect(() => {
    setExpanded(model === null ? new Set() : new Set([model.root.id]));
    setSelected(null);
  }, [model]);

  useEffect(() => {
    onPendingInput(maskText !== '');
  }, [maskText, onPendingInput]);
  useEffect(() => () => onPendingInput(false), [onPendingInput]);

  const roundDrops = round.filter((r) => isDrop(r.op));
  const roundSingles = round.some((r) => isSingleMask(r.op));
  const roundMasks = round.some((r) => isMask(r.op));
  const anyMask = roundMasks || context.ops.some(isMask);
  // Review T17 C1: Rust places a single-occurrence mask after every drop of the set, so a drop
  // appended to a revision that holds one would move it (core
  // `a_later_drop_moves_a_revision_single_occurrence_mask`). Only "Remove all" is left for drops.
  const baseSingles = context.ops.some(isSingleMask);
  // A repeat inside the round does nothing; across rounds only a location-free op does. A
  // location names what this revision shows: `fields.labels[0]` again is the next label.
  const inRound = new Set(round.map((r) => canonical(r.op)));
  const applied = new Set(context.ops.filter(locationFree).map(canonical));

  /** Adds `op` to the round; a refusal says why. */
  const add = (op: RedactionOp | null, loc: Loc | null, where: Hint['at'] = 'node'): boolean => {
    setHint(null);
    if (op === null) return false;
    const key = canonical(op);
    if (inRound.has(key) || applied.has(key)) {
      setHint({ text: inRound.has(key) ? t.approvals.redaction.already_in_round : t.approvals.redaction.already_applied, at: where });
      return false;
    }
    onRound([...round, { op, loc }]);
    return true;
  };

  const droppedLoc = (loc: Loc) => roundDrops.some((r) => r.loc !== null && within(loc, r.loc));

  /** Adds the typed mask; the text and the checkbox are kept when it is refused. */
  const addMask = (node: TreeNode, value: string, single: boolean) => {
    const refusal =
      maskText === ''
        ? t.approvals.redaction.mask_empty
        : maskText.includes(REDACTED)
          ? t.approvals.redaction.mask_placeholder
          : value.includes(maskText)
            ? null
            : t.approvals.redaction.mask_not_in_value;
    if (refusal !== null) {
      setHint({ text: refusal, at: 'node' });
      return;
    }
    const at = single ? node.loc : null;
    if (add(maskOp(maskText, at), at)) {
      setMaskText('');
      setOnlyHere(false);
    }
  };

  const takeSelection = () => {
    const sel = window.getSelection();
    const box = valueRef.current;
    if (sel === null || box === null || sel.rangeCount === 0) return;
    if (!box.contains(sel.anchorNode) || !box.contains(sel.focusNode)) return;
    setHint(null);
    setMaskText(sel.toString());
  };

  const actions = (node: TreeNode): ReactNode => {
    const { loc } = node;
    const value = node.span.kind === 'string' && model !== null ? stringOf(model.text, node.span) : null;
    const bad = firstUnaddressable(loc);
    const blockedDrops = roundSingles || baseSingles || removeAll;
    const already = droppedLoc(loc);
    // Since M8 T19c Rust resolves each op against the document the revision's ops left, which is
    // the tree shown here, so an index names the same element after earlier drops (M6 T17 rule (b)
    // is lifted); the round is ordered by `ordered()`.
    const dropButton = (label: string, op: RedactionOp | null, at: Loc) => (
      <button type="button" disabled={blockedDrops || already || op === null} onClick={() => add(op, at)}>
        {label}
      </button>
    );
    let drops: ReactNode = null;
    if (bad >= 0) {
      const parent = loc.slice(0, bad);
      drops = (
        <p className="unaddressable">
          {parent.length === 0 ? t.approvals.redaction.root_unaddressable : t.approvals.redaction.unaddressable}{' '}
          {parent.length === 0 ? null : dropButton(t.approvals.redaction.drop_parent, dropOf(parent), parent)}
        </p>
      );
    } else if (loc.length > 0) {
      const last = loc[loc.length - 1];
      drops =
        last !== undefined && 'index' in last ? (
          dropButton(t.approvals.redaction.drop_item, dropItemOp(loc), loc)
        ) : (
          <>
            {dropButton(t.approvals.redaction.drop_field_item, dropFieldOp(loc, 'per_item'), loc)}
            {inItems(loc) ? dropButton(t.approvals.redaction.drop_field_all, dropFieldOp(loc, 'all_items'), loc) : null}
          </>
        );
    }
    const problem = value === null ? null : singleMaskProblem(value, maskText, roundMasks);
    const singleOk = roundDrops.length === 0 && concreteOf(loc) !== null && problem === null;
    return (
      <>
        <div className="redaction-actions">
          {drops}
          {already ? <span>{t.approvals.redaction.already_dropped}</span> : null}
          {roundSingles ? <p>{t.approvals.redaction.drops_need_no_singles}</p> : null}
          {baseSingles && drops !== null ? <p>{t.approvals.redaction.drops_need_no_applied_singles}</p> : null}
        </div>
        {value === null ? null : (
          <div className="mask-form">
            <label>
              {t.approvals.redaction.mask_label}{' '}
              <input
                type="text"
                value={maskText}
                disabled={removeAll}
                onChange={(e) => {
                  setHint(null);
                  setMaskText(e.target.value);
                }}
              />
            </label>
            <button type="button" disabled={removeAll} onClick={takeSelection}>
              {t.approvals.redaction.mask_use_selection}
            </button>
            <label>
              <input
                type="checkbox"
                checked={onlyHere && singleOk}
                disabled={!singleOk || removeAll}
                onChange={(e) => setOnlyHere(e.target.checked)}
              />{' '}
              {t.approvals.redaction.mask_only_here}
            </label>
            <button type="button" disabled={removeAll} onClick={() => addMask(node, value, onlyHere && singleOk)}>
              {t.approvals.redaction.mask_add}
            </button>
            {roundDrops.length > 0 ? <p>{t.approvals.redaction.single_needs_no_drops}</p> : null}
            {problem === null ? null : <p>{singleProblemText(t)[problem]}</p>}
          </div>
        )}
        <span className="field-hint" role="alert">
          {hint?.at === 'node' ? hint.text : ''}
        </span>
      </>
    );
  };

  const selectedPane = (node: TreeNode): ReactNode => {
    if (model === null) return null;
    const value = node.span.kind === 'string' ? stringOf(model.text, node.span) : null;
    const points = value === null ? 0 : Array.from(value).length;
    const shownValue = value === null ? null : cut(value, VALUE_SHOWN_MAX);
    const escaped = shownValue === null ? null : escapeInvisible(shownValue);
    return (
      <section className="redaction-selected" aria-label={t.approvals.redaction.selected}>
        <p>
          {t.approvals.redaction.selected}: <Text value={displayOf(node.loc)} />
        </p>
        {value === null || shownValue === null ? null : (
          <>
            <div className="tree-value-full" ref={valueRef} tabIndex={0} aria-label={t.approvals.redaction.value}>
              <AgentText value={shownValue} unusual={unusual(value)} />
              {points > VALUE_SHOWN_MAX ? <p>{t.approvals.redaction.value_cut(VALUE_SHOWN_MAX, points)}</p> : null}
            </div>
            {escaped === null || escaped === shownValue ? null : (
              <div className="tree-value-escaped" aria-label={t.approvals.redaction.value_escaped}>
                {t.approvals.redaction.value_escaped}: <AgentText value={escaped} unusual={unusual(escaped)} />
              </div>
            )}
          </>
        )}
        {actions(node)}
      </section>
    );
  };

  const report = props.report;
  const reportView = (): ReactNode => {
    if (!draft.unsent) return null;
    if (report === null) return <p role="status">{t.approvals.redaction.checking}</p>;
    if (!('report' in report)) return <p role="alert">{t.approvals.redaction.check_failed}</p>;
    const r = report.report;
    return (
      <div className="redaction-report">
        {r.blocked.length === 0 ? null : (
          <div role="alert">
            <strong>{t.approvals.redaction.blocked}</strong>
            <ul>
              {r.blocked.map((b, i) => (
                <li key={i}>
                  {own(t.approvals.block_reason, b.reason) ?? b.reason}
                  {b.path === '' ? null : (
                    <>
                      {': '}
                      <Text value={b.path} />
                    </>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {r.also_appears_in.length === 0 ? null : (
          <div>
            {t.approvals.redaction.also_appears_in}
            <ul className="also-appears-in">
              {r.also_appears_in.map((p, i) => (
                <li key={i}>
                  <Text value={p} />
                </li>
              ))}
            </ul>
          </div>
        )}
        {r.other_occurrences === 0 ? null : (
          <p>
            {t.approvals.redaction.other_occurrences(r.other_occurrences)}{' '}
            <label>
              <input
                type="checkbox"
                checked={props.confirmed}
                onChange={(e) => props.onConfirm(e.target.checked)}
              />{' '}
              {t.approvals.redaction.confirm_others}
            </label>
          </p>
        )}
        <p>{t.approvals.redaction.released_bytes(r.released_bytes)}</p>
      </div>
    );
  };

  /**
   * A mirror-blocked revision (M-11): the flagged entries as text, and one action that adds their
   * drops to the round. Rust's `redaction_preview` still decides whether the drops clear them.
   */
  const flaggedView = (): ReactNode => {
    const found = props.flagged;
    if (found === null) return <p role="status">{t.approvals.redaction.flagged_checking}</p>;
    if ('failed' in found || found.flagged.length === 0) return <p role="alert">{t.approvals.redaction.flagged_missing}</p>;
    const plan = flaggedPlan;
    const missing = plan === null ? [] : plan.round.filter((r) => !inRound.has(canonical(r.op)));
    return (
      <div className="redaction-flagged">
        <strong>{t.approvals.redaction.flagged_heading}</strong>
        <ul>
          {found.flagged.slice(0, FLAGGED_SHOWN).map((b, i) => (
            <li key={i}>
              {own(t.approvals.block_reason, b.reason) ?? b.reason}
              {': '}
              <Text value={b.path} />
            </li>
          ))}
        </ul>
        {/* Only the list is cut: the drops below name every flagged entry. */}
        {found.flagged.length > FLAGGED_SHOWN ? (
          <p>{t.approvals.redaction.flagged_more(found.flagged.length - FLAGGED_SHOWN)}</p>
        ) : null}
        <button
          type="button"
          disabled={plan === null || plan.round.length === 0 || missing.length === 0 || roundSingles || removeAll}
          onClick={() => onRound([...round, ...missing])}
        >
          {t.approvals.redaction.drop_flagged}
        </button>{' '}
        <span>{t.approvals.redaction.drop_flagged_note}</span>
        {plan !== null && plan.unresolved ? <p role="alert">{t.approvals.redaction.flagged_unresolved}</p> : null}
      </div>
    );
  };

  const presets: RedactionPreset[] = [];
  if (props.upstreamError) presets.push('status_only');
  if (props.script && model !== null && scriptErrorCard(model)) presets.push('error_class_only');
  const mode = props.urlChoice ?? baseUrlMode(context.ops) ?? 'replace_whole';
  const showUrl = context.url_fields.length > 0 || anyMask;

  const body = (): ReactNode => {
    if (candidate === null || candidate.state === 'loading') return <p role="status">{t.approvals.redaction.loading}</p>;
    if (candidate.state === 'failed') {
      return (
        <p role="alert">
          {t.approvals.redaction.read_failed}{' '}
          <button type="button" onClick={candidate.retry}>
            {t.approvals.redaction.retry}
          </button>
        </p>
      );
    }
    if (model === null) return <p role="alert">{t.approvals.redaction.unavailable}</p>;
    return (
      <>
        <Tree
          model={model}
          expanded={expanded}
          onToggle={(n) =>
            setExpanded((e) => {
              const next = new Set(e);
              if (!next.delete(n.id)) next.add(n.id);
              return next;
            })
          }
          selectedId={selected?.id ?? null}
          onSelect={(n) => {
            setSelected(n);
            setHint(null);
            setOnlyHere(false);
          }}
          marks={(n) => ({ link: isUrlField(context.url_fields, n.loc), dropped: droppedLoc(n.loc) })}
        />
        {selected === null ? null : selectedPane(selected)}
      </>
    );
  };

  return (
    <section className="redaction-panel" aria-label={t.approvals.redaction.label} ref={ref} {...{ [EDIT_ENTRY_ATTR]: '' }}>
      <p>{t.approvals.redaction.intro}</p>
      <p className="field-keys">{t.approvals.redaction.keys}</p>
      <div className="redaction-ops">
        <strong>{t.approvals.redaction.applied_heading}</strong>
        {context.ops.length === 0 ? (
          <span> {t.approvals.redaction.none_applied}</span>
        ) : (
          <ul>
            {context.ops.map((op, i) => (
              <li key={i}>
                <OpText op={op} />
              </li>
            ))}
          </ul>
        )}
        {props.appliedAlsoAppearsIn.length === 0 ? null : (
          <div>
            {t.approvals.redaction.also_appears_in}
            <ul className="also-appears-in">
              {props.appliedAlsoAppearsIn.map((p, i) => (
                <li key={i}>
                  <Text value={p} />
                </li>
              ))}
            </ul>
          </div>
        )}
        {context.ops.length === 0 ? null : removeAll ? (
          <p role="status">
            {t.approvals.redaction.remove_all_pending}{' '}
            <button type="button" onClick={() => props.onRemoveAll(false)}>
              {t.approvals.redaction.undo_remove_all}
            </button>
          </p>
        ) : (
          <button type="button" onClick={() => props.onRemoveAll(true)}>
            {t.approvals.redaction.remove_all}
          </button>
        )}
      </div>
      {round.length === 0 ? null : (
        <div className="redaction-ops">
          <strong>{t.approvals.redaction.round_heading}</strong>
          <ul>
            {round.map((r, i) => (
              <li key={i}>
                <OpText op={r.op} />{' '}
                <button type="button" onClick={() => onRound(round.filter((_, j) => j !== i))}>
                  {t.approvals.redaction.remove}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {presets.length === 0 ? null : (
        <div className="redaction-presets" role="group" aria-label={t.approvals.redaction.presets}>
          {presets.map((p) => (
            <button
              key={p}
              type="button"
              disabled={removeAll || roundSingles || baseSingles}
              onClick={() => add(presetOp(p), null, 'presets')}
            >
              {p === 'status_only' ? t.approvals.redaction.preset_status_only : t.approvals.redaction.preset_error_class_only}
            </button>
          ))}
          {baseSingles ? <p>{t.approvals.redaction.drops_need_no_applied_singles}</p> : null}
          <span className="field-hint" role="alert">
            {hint?.at === 'presets' ? hint.text : ''}
          </span>
        </div>
      )}
      {showUrl ? (
        <fieldset className="redaction-url" disabled={removeAll}>
          <legend>{t.approvals.redaction.url_mode}</legend>
          {(['replace_whole', 'drop'] as const).map((m) => (
            <label key={m}>
              <input type="radio" name="url-mode" checked={mode === m} onChange={() => props.onUrlChoice(m)} />{' '}
              {m === 'drop' ? t.approvals.redaction.url_drop : t.approvals.redaction.url_replace_whole}
            </label>
          ))}
        </fieldset>
      ) : null}
      {props.mirrorBlocked ? flaggedView() : null}
      {reportView()}
      <div className="redaction-release">
        <button
          type="button"
          {...{ [POSITIVE_ATTR]: '' }}
          aria-describedby={releaseHint}
          disabled={!props.canRelease}
          onClick={props.onRelease}
        >
          {t.approvals.redaction.release}
        </button>{' '}
        <span id={releaseHint}>{t.approvals.redaction.release_redacted_hint}</span>
      </div>
      {body()}
    </section>
  );
}

/** The flagged entries listed at most; the rest is a count (the drops still name every entry). */
const FLAGGED_SHOWN = 50;

/**
 * The drops that clear `flagged` (core `redact`: an entry the mirror check flags blocks until a drop
 * removes it whole). An orphan is dropped as an item, by its identity where it has one; entries that
 * cannot be matched are not fixed by dropping them (`mirrored()` refuses), so their whole list goes.
 * Lists come first and anything under a dropped location is not named again (no op of a round
 * addresses the child of an earlier drop). `unresolved`: a flagged entry that is not in the tree or
 * cannot be dropped from here. The round's order is `ordered()`'s, not this list's.
 */
function flaggedRound(model: TreeModel, flagged: readonly BlockReason[]): { round: RoundOp[]; unresolved: boolean } {
  const round: RoundOp[] = [];
  const gone: Loc[] = [];
  let unresolved = false;
  const take = (op: RedactionOp | null, loc: Loc) => {
    if (op === null) {
      unresolved = true;
    } else if (!gone.some((g) => within(loc, g))) {
      round.push({ op, loc });
      gone.push(loc);
    }
  };
  const nodes = flagged.map((b) => ({ reason: b.reason, node: model.find(b.path) }));
  for (const { reason, node } of nodes) {
    if (reason === 'mirror_unmatchable' && node !== null) {
      const list = node.loc.slice(0, -1);
      take(dropOf(list), list);
    }
  }
  for (const { reason, node } of nodes) {
    if (node === null) unresolved = true;
    else if (reason !== 'mirror_unmatchable') take(dropItemOp(node.loc), node.loc);
  }
  return { round, unresolved };
}

/** A script's error-details candidate `{script_error: {class, …}}` (§9.5): "Keep error class only" applies. */
function scriptErrorCard(model: TreeModel): boolean {
  const root = members(model.text, model.root.span);
  const err = root.find((m) => m.key === 'script_error');
  return err !== undefined && members(model.text, err.span).some((m) => m.key === 'class');
}
