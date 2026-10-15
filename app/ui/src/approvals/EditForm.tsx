import { useId } from 'react';

import { AgentText } from '../shared/text/AgentText';
import type { EditForm as EditFormModel, EditInput } from '../shared/ipc/types';
import { EDIT_TEXT } from '../shared/strings';
import { JsonFallback, readJson } from './JsonFallback';
import { EDIT_ENTRY_ATTR } from './keyboard';

/** What the user typed into one input; which fields count depends on the input's kind. */
export interface Draft {
  text: string;
  bool: boolean | null;
  /** A multi-pick's checked labels. */
  picks: string[];
  /** A choice entered as raw JSON instead of picked. */
  asJson: boolean;
}

export type Drafts = Readonly<Record<string, Draft>>;

function initialText(input: EditInput): string {
  const v = input.value;
  if (v === null) return '';
  if (input.kind.kind === 'json') return JSON.stringify(v, null, 2);
  return typeof v === 'string' ? v : JSON.stringify(v);
}

function initialDraft(input: EditInput): Draft {
  return {
    text: input.kind.kind === 'choice' ? '' : initialText(input),
    bool: typeof input.value === 'boolean' ? input.value : null,
    picks: [],
    asJson: false,
  };
}

const draftOf = (input: EditInput, drafts: Drafts): Draft => drafts[input.path] ?? initialDraft(input);

/** What `buildEdits` made of the drafts. */
export interface BuiltEdits {
  /** The `edits` of a `decide`: changed values to set, cleared keys to remove (never `null`). */
  edits: { set: Record<string, unknown>; remove: string[] };
  /** A changed input whose text is not valid for its kind, by path: the local syntax hint. */
  errors: Readonly<Record<string, string>>;
  /** The edits are past the size Rust accepts (`EDITS_MAX_BYTES`): a local hint, Rust stays the bound. */
  oversize: boolean;
  /** Some input differs from the revision's value. */
  changed: boolean;
}

/** The bound Rust puts on the serialized `edits` (`EDITS_MAX_BYTES`, 1 MiB). */
const EDITS_MAX_BYTES = 1024 * 1024;
const INTEGER =/^-?\d+$/;
const DECIMAL = /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/;

/**
 * The `{set, remove}` of every changed, editable input. A cleared input is removed, never set to
 * `null`; a read-only input (a target or baseline) is never read, whatever its draft says. Syntax
 * is checked only far enough to build a JSON value (a number, a JSON text); whether the edit is
 * acceptable is Rust's decision (spec 2.4).
 */
export function buildEdits(form: EditFormModel, drafts: Drafts): BuiltEdits {
  const set: [string, unknown][] = [];
  const remove: string[] = [];
  const errors: Record<string, string> = {};
  for (const input of form.inputs) {
    if (input.read_only) continue;
    const d = draftOf(input, drafts);
    const { kind } = input;
    // "Changed" compares values, not text: `050` for 50 or re-indented JSON is no change.
    const setIfChanged = (value: unknown) => {
      if (!sameJson(value, input.value)) set.push([input.path, value]);
    };
    const readJsonInto = (text: string) => {
      const read = readJson(text);
      if (!read.ok) errors[input.path] = EDIT_TEXT.json_invalid;
      else if (read.value === null) {
        if (input.value !== null) remove.push(input.path);
      } else setIfChanged(read.value);
    };
    if (kind.kind === 'choice') {
      if (d.asJson) {
        if (d.text.trim() !== '') readJsonInto(d.text);
      } else if (kind.multiple === true) {
        const picked = kind.allowed_values.filter((l) => d.picks.includes(l));
        if (picked.length > 0) setIfChanged(picked);
      } else if (d.text !== '') {
        setIfChanged(d.text);
      }
      continue;
    }
    if (kind.kind === 'boolean') {
      // An absent boolean counts as unchecked: checking and unchecking it again is no change, and
      // `false` is sent only to replace a `true`.
      const was = input.value === true;
      if (d.bool !== null && d.bool !== was) set.push([input.path, d.bool]);
      continue;
    }
    const original = initialText(input);
    if (d.text === original) continue;
    if (d.text === '') {
      remove.push(input.path);
      continue;
    }
    switch (kind.kind) {
      case 'integer':
        if (INTEGER.test(d.text) && Number.isSafeInteger(Number(d.text))) {
          setIfChanged(Number(d.text));
        } else errors[input.path] = EDIT_TEXT.integer_invalid;
        break;
      case 'number':
        if (DECIMAL.test(d.text) && Number.isFinite(Number(d.text))) {
          setIfChanged(Number(d.text));
        } else errors[input.path] = EDIT_TEXT.number_invalid;
        break;
      case 'json': {
        // Blank text is a clear of the original value, or no change when there was none.
        if (d.text.trim() === '') {
          if (original !== '') remove.push(input.path);
          break;
        }
        readJsonInto(d.text);
        break;
      }
      default:
        set.push([input.path, d.text]);
    }
  }
  const edits = { set: Object.fromEntries(set), remove };
  return {
    // `fromEntries` defines own properties: no key can reach a prototype.
    edits,
    errors,
    oversize: set.length + remove.length > 0 && new TextEncoder().encode(JSON.stringify(edits)).length > EDITS_MAX_BYTES,
    changed: set.length > 0 || remove.length > 0 || Object.keys(errors).length > 0,
  };
}

/** JSON equality of two values read from JSON: key order does not matter. */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const x = a as Record<string, unknown>;
  const y = b as Record<string, unknown>;
  const keys = Object.keys(x);
  return (
    keys.length === Object.keys(y).length &&
    keys.every((k) => Object.prototype.hasOwnProperty.call(y, k) && sameJson(x[k], y[k]))
  );
}

/** Characters a reader cannot see or that reorder text (bidi controls, zero-width, other format and control characters). */
const UNUSUAL = /(?![\n\t])[\p{Cc}\p{Cf}\u2028\u2029]/u;

interface EditFormProps {
  form: EditFormModel;
  drafts: Drafts;
  onDraft: (path: string, draft: Draft) => void;
  onReset: () => void;
  onSubmit: () => void;
  /** The window allows an edit now (opened, not inert, nothing in flight): Rust checks it again. */
  canSubmit: boolean;
  /** Core's message of a refused edit (`''` when it carried none), or null. */
  rejection: string | null;
}

/**
 * The Structured tab of a write (spec 5.4 step 4): one input per entry of `Preview.edit_form`, as
 * Rust built it. Targets and baselines are shown disabled. "Edit & approve" sends the changes as
 * `edits`; the answer is a new revision that must be opened and approved separately (PD-20). Agent
 * text is only ever a control's value or inside `AgentText`; nothing here is markup.
 */
export function EditForm({ form, drafts, onDraft, onReset, onSubmit, canSubmit, rejection }: EditFormProps) {
  const base = useId();
  const built = buildEdits(form, drafts);
  const hasErrors = Object.keys(built.errors).length > 0 || built.oversize;
  const own = form.inputs.filter((i) => !i.pre_added);
  const added = form.inputs.filter((i) => i.pre_added);

  const field = (input: EditInput, n: number) => {
    const id = `${base}-${n}`;
    const hintId = `${id}-hint`;
    const d = draftOf(input, drafts);
    const set = (patch: Partial<Draft>) => onDraft(input.path, { ...d, ...patch });
    const marks = (
      <>
        {input.required ? <span className="required"> ({EDIT_TEXT.required})</span> : null}
        {input.read_only ? <span className="read-only"> ({EDIT_TEXT.read_only})</span> : null}
      </>
    );
    const entry = { [EDIT_ENTRY_ATTR]: '' };
    const error = built.errors[input.path];
    // The live region stays in the DOM, so a message added later is announced.
    const hint = (
      <span id={hintId} className="field-hint" aria-live="polite">
        {error ?? ''}
      </span>
    );
    const required = input.required ? true : undefined;
    const { kind } = input;

    if (input.read_only) {
      // Never sent, so it does not need to round-trip through a control: shown as agent text, which
      // marks invisible and bidi characters. A disabled input would show them raw.
      const text = typeof input.value === 'string' ? input.value : JSON.stringify(input.value);
      const labelId = `${id}-label`;
      return (
        <div className="field" key={input.path} role="group" aria-labelledby={labelId}>
          <span id={labelId} className="field-label">
            {input.label}
            {marks}
          </span>{' '}
          {input.value === null || text === undefined ? (
            <span className="none">{EDIT_TEXT.none}</span>
          ) : (
            <AgentText value={text} unusual={UNUSUAL.test(text)} />
          )}
        </div>
      );
    }
    if (kind.kind === 'choice' && kind.multiple === true && !d.asJson) {
      return (
        <fieldset className="field" key={input.path}>
          <legend>
            {input.label}
            {marks}
          </legend>
          {kind.allowed_values.map((label, i) => (
            <label key={`${i}-${label}`} className="pick">
              <input
                type="checkbox"
                {...entry}
                checked={d.picks.includes(label)}
                onChange={(e) =>
                  set({
                    picks: e.target.checked
                      ? [...d.picks, label]
                      : d.picks.filter((l) => l !== label),
                  })
                }
              />{' '}
              {label}
            </label>
          ))}
          <AsJson id={`${id}-json`} label={input.label} on={d.asJson} onChange={(on) => set({ asJson: on, text: '' })} />
        </fieldset>
      );
    }
    let control;
    if (kind.kind === 'choice') {
      control = d.asJson ? (
        <JsonFallback id={id} value={d.text} onChange={(text) => set({ text })} invalid={error !== undefined} hintId={hintId} required={required} />
      ) : (
        <select
          id={id}
          {...entry}
          value={d.text}
          aria-required={required}
          aria-describedby={hintId}
          onChange={(e) => set({ text: e.target.value })}
        >
          <option value="">{EDIT_TEXT.choice_none}</option>
          {kind.allowed_values.map((label, i) => (
            <option key={`${i}-${label}`} value={label}>
              {label}
            </option>
          ))}
        </select>
      );
    } else if (kind.kind === 'json') {
      control = (
        <JsonFallback id={id} value={d.text} onChange={(text) => set({ text })} invalid={error !== undefined} hintId={hintId} required={required} />
      );
    } else if (kind.kind === 'long_text') {
      control = (
        <textarea
          id={id}
          {...entry}
          value={d.text}
          aria-required={required}
          aria-describedby={hintId}
          onChange={(e) => set({ text: e.target.value })}
        />
      );
    } else if (kind.kind === 'boolean') {
      control = (
        <input
          id={id}
          type="checkbox"
          {...entry}
          checked={d.bool === true}
          aria-required={required}
          aria-describedby={hintId}
          onChange={(e) => set({ bool: e.target.checked })}
        />
      );
    } else {
      control = (
        <input
          id={id}
          type="text"
          {...entry}
          inputMode={kind.kind === 'integer' ? 'numeric' : kind.kind === 'number' ? 'decimal' : 'text'}
          value={d.text}
          aria-required={required}
          aria-invalid={error !== undefined}
          aria-describedby={hintId}
          onChange={(e) => set({ text: e.target.value })}
        />
      );
    }
    return (
      <div className="field" key={input.path}>
        <label htmlFor={id}>
          {input.label}
          {marks}
        </label>
        {control}
        {kind.kind === 'json' || (kind.kind === 'choice' && d.asJson) ? null : hint}
        {kind.kind === 'choice' ? (
          <AsJson id={`${id}-json`} label={input.label} on={d.asJson} onChange={(on) => set({ asJson: on, text: '' })} />
        ) : null}
      </div>
    );
  };

  return (
    <section className="edit-form" aria-label={EDIT_TEXT.label}>
      <p>{EDIT_TEXT.intro}</p>
      <p className="field-keys">{EDIT_TEXT.keys}</p>
      <fieldset>
        <legend>{EDIT_TEXT.params}</legend>
        {own.map((input, n) => field(input, n))}
      </fieldset>
      {added.length === 0 ? null : (
        <fieldset className="missing-fields">
          <legend>{EDIT_TEXT.missing}</legend>
          {added.map((input, n) => field(input, own.length + n))}
        </fieldset>
      )}
      {rejection === null ? null : (
        <p role="alert" className="edit-rejected">
          {rejection === '' ? (
            EDIT_TEXT.rejected_plain
          ) : (
            <>
              {EDIT_TEXT.rejected} <AgentText value={rejection} />
            </>
          )}
        </p>
      )}
      <div className="edit-actions">
        <button type="button" {...{ [EDIT_ENTRY_ATTR]: '' }} disabled={!canSubmit || !built.changed || hasErrors} onClick={onSubmit}>
          {EDIT_TEXT.submit}
        </button>
        <button type="button" {...{ [EDIT_ENTRY_ATTR]: '' }} disabled={!built.changed} onClick={onReset}>
          {EDIT_TEXT.reset}
        </button>
        <span className="field-hint" aria-live="polite">
          {built.oversize ? EDIT_TEXT.too_large : built.changed ? '' : EDIT_TEXT.nothing_to_send}
        </span>
      </div>
    </section>
  );
}

function AsJson({ id, label, on, onChange }: { id: string; label: string; on: boolean; onChange: (on: boolean) => void }) {
  return (
    <label className="as-json" htmlFor={id}>
      <input id={id} type="checkbox" {...{ [EDIT_ENTRY_ATTR]: '' }} checked={on} onChange={(e) => onChange(e.target.checked)} />{' '}
      {EDIT_TEXT.as_json(label)}
    </label>
  );
}
