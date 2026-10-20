import { useId, useState, type FormEvent } from 'react';

import type { AuditFilter, AuditFlag } from '../shared/ipc/types';
import { AUDIT_TEXT as T } from '../shared/strings';
import { own } from '../shared/text/own';
import { utcOf } from './text';

/** `MAX_FILTER_TEXT_BYTES` of `crates/audit/src/query.rs`: Rust refuses a longer text too. */
export const MAX_FILTER_TEXT_BYTES = 2048;

/** The 8.2 flags in their bit order (`FLAG_NAMES`, `app/src-tauri/src/commands/audit.rs`). */
const FLAGS: readonly AuditFlag[] = [
  'edited',
  'redacted',
  'batch',
  'stale',
  'clock_backwards',
  'clock_forward',
  'clock_behind',
  'integrity_incident',
];

/** The `decision` column values (`DecisionColumn::ALL`, `crates/audit/src/types.rs`). */
const DECISIONS = [
  'approve',
  'approve_edited',
  'release',
  'release_redacted',
  'deny',
  'expire',
  'cancel',
  'reject',
] as const;

/** The registry classes (spec 5.6) a request's `op_class` holds. */
const CLASSES = ['read', 'write', 'script'] as const;

const TEXT_KEYS = ['agent_name', 'op_id', 'instance_id', 'target'] as const;
type TextKey = (typeof TEXT_KEYS)[number];

interface Form {
  from: string;
  to: string;
  agent_name: string;
  op_id: string;
  op_class: string;
  instance_id: string;
  target: string;
  decision: string;
  flags: readonly AuditFlag[];
}

const EMPTY: Form = {
  from: '',
  to: '',
  agent_name: '',
  op_id: '',
  op_class: '',
  instance_id: '',
  target: '',
  decision: '',
  flags: [],
};

type Errors = Partial<Record<'from' | 'to' | TextKey, string>>;

/** The refusable fields in the order the form shows them. */
const FIELD_ORDER = ['from', 'to', 'agent_name', 'op_id', 'instance_id', 'target'] as const;

const utf8 = new TextEncoder();

/**
 * The typed filter of the form (spec 8.10, L38): one key per filled field, nothing for an empty
 * one, so the store sees no constraint there. Texts are matched exactly (the target by prefix) and
 * sent as typed; one over `MAX_FILTER_TEXT_BYTES` or holding a NUL is refused here, as Rust would.
 */
export function buildFilter(form: Form): { filter: AuditFilter } | { errors: Errors } {
  const errors: Errors = {};
  const filter: AuditFilter = {};
  const from = utcOf(form.from);
  const to = utcOf(form.to);
  if (from === undefined) errors.from = T.time_invalid;
  else if (from !== null) filter.from_utc = from;
  if (to === undefined) errors.to = T.time_invalid;
  else if (to !== null) filter.to_utc = to;
  // Both are the fixed-width `ts_utc` form: text order is time order.
  if (typeof from === 'string' && typeof to === 'string' && from > to) errors.to = T.range_order;
  for (const key of TEXT_KEYS) {
    const value = form[key];
    if (value === '') continue;
    if (value.includes('\u0000')) errors[key] = T.filter_nul;
    else if (utf8.encode(value).length > MAX_FILTER_TEXT_BYTES) errors[key] = T.filter_too_long;
    else filter[key] = value;
  }
  if (form.op_class !== '') filter.op_class = form.op_class;
  if (form.decision !== '') filter.decision = form.decision;
  if (form.flags.length > 0) filter.flags_any = FLAGS.filter((f) => form.flags.includes(f));
  return Object.keys(errors).length > 0 ? { errors } : { filter };
}

/**
 * The Audit window's filters (spec 8.10): a time range, agent, operation, class, instance, target,
 * decision and flags, each a typed input. There is no payload search (L38). "Apply filters" hands
 * the typed filter to the list; a refused field is named next to it and nothing is sent.
 */
export function Filters({ onApply }: { onApply: (filter: AuditFilter) => void }) {
  const [form, setForm] = useState<Form>(EMPTY);
  const [errors, setErrors] = useState<Errors>({});
  const ids = useId();

  const set = <K extends keyof Form>(key: K, value: Form[K]) => setForm((f) => ({ ...f, [key]: value }));

  const apply = (e: FormEvent) => {
    e.preventDefault();
    const built = buildFilter(form);
    if ('errors' in built) {
      setErrors(built.errors);
      // To the first refused field, in the form's order.
      const first = FIELD_ORDER.find((key) => built.errors[key] !== undefined);
      if (first !== undefined) document.getElementById(`${ids}-${first}`)?.focus();
      return;
    }
    setErrors({});
    onApply(built.filter);
  };

  const clear = () => {
    setForm(EMPTY);
    setErrors({});
    onApply({});
  };

  const toggle = (flag: AuditFlag, on: boolean) =>
    set('flags', on ? [...form.flags, flag] : form.flags.filter((f) => f !== flag));

  /** A labelled input, with its refusal named next to it. */
  const field = (key: 'from' | 'to' | TextKey, label: string, type: 'text' | 'datetime-local') => {
    const id = `${ids}-${key}`;
    const error = errors[key];
    return (
      <div className="audit-field">
        <label htmlFor={id}>{label}</label>
        <input
          id={id}
          type={type}
          step={type === 'datetime-local' ? '0.001' : undefined}
          value={form[key]}
          aria-invalid={error === undefined ? undefined : true}
          aria-describedby={error === undefined ? undefined : `${id}-error`}
          onChange={(e) => set(key, e.currentTarget.value)}
        />
        {error === undefined ? null : (
          <span id={`${id}-error`} className="audit-field-error">
            {error}
          </span>
        )}
      </div>
    );
  };

  const select = (
    key: 'op_class' | 'decision',
    label: string,
    values: readonly string[],
    labels: Readonly<Record<string, string>>,
  ) => {
    const id = `${ids}-${key}`;
    return (
      <div className="audit-field">
        <label htmlFor={id}>{label}</label>
        <select id={id} value={form[key]} onChange={(e) => set(key, e.currentTarget.value)}>
          <option value="">{T.any}</option>
          {values.map((v) => (
            <option key={v} value={v}>
              {own(labels, v) ?? T.unknown_name}
            </option>
          ))}
        </select>
      </div>
    );
  };

  return (
    <form className="audit-filters" aria-label={T.filters} onSubmit={apply} noValidate>
      <p>{T.filters_note}</p>
      <div className="audit-fields">
        {field('from', T.from, 'datetime-local')}
        {field('to', T.to, 'datetime-local')}
        {field('agent_name', T.agent_name, 'text')}
        {field('op_id', T.op_id, 'text')}
        {select('op_class', T.op_class, CLASSES, T.class_labels)}
        {field('instance_id', T.instance_id, 'text')}
        {field('target', T.target, 'text')}
        {select('decision', T.decision, DECISIONS, T.decision_labels)}
      </div>
      <fieldset className="audit-flags">
        <legend>{T.flags}</legend>
        {FLAGS.map((flag) => (
          <label key={flag}>
            <input
              type="checkbox"
              checked={form.flags.includes(flag)}
              onChange={(e) => toggle(flag, e.currentTarget.checked)}
            />
            {own(T.flag_labels, flag) ?? flag}
          </label>
        ))}
      </fieldset>
      {Object.keys(errors).length > 0 ? <p role="alert">{T.filter_errors}</p> : null}
      <div className="audit-actions">
        <button type="submit">{T.apply}</button>
        <button type="button" onClick={clear}>
          {T.clear}
        </button>
      </div>
    </form>
  );
}
