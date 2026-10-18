import { useState } from 'react';

import { settingsApply } from '../shared/ipc/invoke';
import type { Confinement, ScriptLimits, SettingsView } from '../shared/ipc/types';
import { SETTINGS_TEXT as T } from '../shared/strings';
import { Guard } from './Guard';
import { parseWhole } from './Limits';
import { useAction } from './useAction';

type ScriptKey = keyof ScriptLimits;

/** The `restart_pending` name of the whole `[scripts]` table (core's `KEY_SCRIPT_LIMITS`). */
const KEY_SCRIPT_LIMITS = 'script_limits';

/** The eight §9.4 limits, in the spec's order. */
const KEYS: readonly ScriptKey[] = [
  'timeout_s',
  'heap_mb',
  'process_mb',
  'max_calls',
  'max_fetch_mb',
  'max_call_result_mb',
  'max_result_mb',
  'max_concurrent_calls',
];

/** The §9.4 defaults, shown as a hint only: what is in force is the view's value, and the bounds are core's. */
const DEFAULTS: Readonly<ScriptLimits> = {
  timeout_s: 120,
  heap_mb: 256,
  process_mb: 512,
  max_calls: 200,
  max_fetch_mb: 50,
  max_call_result_mb: 16,
  max_result_mb: 16,
  max_concurrent_calls: 4,
};

interface ScriptLimitsProps {
  view: SettingsView;
  onChanged: () => void;
  /** config.toml is read-only: the form is off. */
  readOnly: boolean;
}

/**
 * The script limits form (spec 9.4, PD-139): the eight limits in force, the spec default beside each.
 * One Apply sends the changed keys as a single `script_limits` change; Rust checks the bounds and
 * both memory invariants, confirms a raise in its own dialog, and its refusals are shown as text. A
 * field the user edited keeps its text across re-reads (as in `Limits`).
 */
export function ScriptLimitsForm({ view, onChanged, readOnly }: ScriptLimitsProps) {
  const [draft, setDraft] = useState<Partial<Record<ScriptKey, string>>>({});
  const [local, setLocal] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);
  const action = useAction();
  const shown = (key: ScriptKey): string => String(view.limits.script[key]);

  const submit = () => {
    const changed: Partial<ScriptLimits> = {};
    for (const key of KEYS) {
      const text = draft[key];
      if (text === undefined || text === shown(key)) continue;
      const n = parseWhole(text);
      if (n === null) {
        setLocal(T.not_a_number);
        return;
      }
      changed[key] = n;
    }
    setLocal(null);
    setApplied(false);
    if (Object.keys(changed).length === 0) return;
    void action.run(() => settingsApply([{ key: 'script_limits', value: changed }])).then((v) => {
      if (v === undefined) return;
      setDraft({});
      setApplied(true);
      onChanged();
    });
  };

  return (
    <section aria-label={T.script_limits}>
      <h2>{T.script_limits}</h2>
      <Guard disabled={readOnly}>
        {KEYS.map((key) => (
          <div key={key} className="field">
            <label>
              {T.script_limit_labels[key]}
              <input
                type="text"
                inputMode="numeric"
                value={draft[key] ?? shown(key)}
                aria-describedby={`script-default-${key}`}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
              />
            </label>
            <span id={`script-default-${key}`} className="default-hint">
              {' '}
              ({T.script_default(DEFAULTS[key])})
            </span>
          </div>
        ))}
        {view.restart_pending.includes(KEY_SCRIPT_LIMITS) ? (
          <p className="restart-waiting">{T.restart_waiting}</p>
        ) : null}
        <p>{T.script_limits_note}</p>
        <button type="button" disabled={action.pending} onClick={submit}>
          {T.apply}
        </button>
        {local === null ? null : <p role="alert">{local}</p>}
        {action.error === null ? null : <p role="alert">{action.error}</p>}
        {applied ? <p role="status">{T.applied}</p> : null}
      </Guard>
    </section>
  );
}

interface DegradedToggleProps {
  view: SettingsView;
  confinement: Confinement;
  onChanged: () => void;
}

/**
 * "Allow scripts with degraded confinement" (spec 9.4, 10.3, PD-141). The box follows the stored
 * setting; a change is one `settings_apply` and Rust confirms turning it on in its own dialog, so a
 * cancel leaves the box as it was and shows the text. While scripts do run degraded the caution has
 * no dismiss. The setting is audit-authoritative, not a config.toml key, so a read-only config
 * does not turn it off.
 */
export function DegradedToggle({ view, confinement, onChanged }: DegradedToggleProps) {
  const action = useAction();
  const set = (value: boolean) => {
    void action.run(() => settingsApply([{ key: 'allow_degraded_scripts', value }])).then((v) => {
      if (v !== undefined) onChanged();
    });
  };
  return (
    <div className="field">
      <label>
        <input
          type="checkbox"
          checked={view.allow_degraded_scripts}
          disabled={action.pending}
          onChange={(e) => set(e.target.checked)}
        />
        {T.degraded_toggle}
      </label>
      <p>{T.degraded_note}</p>
      {confinement.scripts === 'degraded' ? (
        <p role="status" className="caution-strip">
          {T.scripts_degraded_caution}
        </p>
      ) : null}
      {view.allow_degraded_scripts && confinement.scripts === 'enabled' ? (
        <p>{T.degraded_inactive}</p>
      ) : null}
      {action.error === null ? null : <p role="alert">{action.error}</p>}
    </div>
  );
}
