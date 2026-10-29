import { useState } from 'react';
import { useText } from '../shared/i18n/context';

import { settingsApply } from '../shared/ipc/invoke';
import type { SettingChange, SettingsView } from '../shared/ipc/types';
import { Guard } from './Guard';
import { useAction } from './useAction';

/** A whole number, or `null` when the text is not one (range checks are core's). */
export function parseWhole(text: string): number | null {
  const t = text.trim();
  return /^\d{1,15}$/.test(t) ? Number(t) : null;
}

type LimitKey = 'jira_comments_cap' | 'candidate_cache_mb' | 'max_pending_bytes_mb' | 'expiry_hours';

const KEYS: readonly LimitKey[] = [
  'jira_comments_cap',
  'candidate_cache_mb',
  'max_pending_bytes_mb',
  'expiry_hours',
];

/** Core's rule (PD-76): only the comments cap applies at once; the others at the next start. */
const NEXT_START: ReadonlySet<string> = new Set([
  'candidate_cache_mb',
  'max_pending_bytes_mb',
  'expiry_hours',
]);

const shown = (view: SettingsView, key: LimitKey): string => {
  const v = view.limits[key];
  return v === null ? '' : String(v);
};

interface LimitsProps {
  view: SettingsView;
  onChanged: () => void;
  /** config.toml is read-only: the form is off. */
  readOnly: boolean;
}

/**
 * The limits form. A field the user edited keeps its text across re-reads of the settings (a
 * `settings_changed` event must not overwrite typing); a field not edited follows the view.
 */
export function Limits({ view, onChanged, readOnly }: LimitsProps) {
  const t = useText();
  const [draft, setDraft] = useState<Partial<Record<LimitKey, string>>>({});
  const [local, setLocal] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);
  const action = useAction();

  const submit = () => {
    const changes: SettingChange[] = [];
    for (const key of KEYS) {
      const text = draft[key];
      if (text === undefined || text === shown(view, key)) continue;
      if (key === 'max_pending_bytes_mb' && text.trim() === '') {
        changes.push({ key, value: null });
        continue;
      }
      const n = parseWhole(text);
      if (n === null) {
        setLocal(t.settings.not_a_number);
        return;
      }
      changes.push({ key, value: n });
    }
    setLocal(null);
    setApplied(false);
    if (changes.length === 0) return;
    void action.run(() => settingsApply(changes)).then((v) => {
      if (v === undefined) return;
      setDraft({});
      setApplied(true);
      onChanged();
    });
  };

  return (
    <section aria-label={t.settings.limits}>
      <h2>{t.settings.limits}</h2>
      <Guard disabled={readOnly}>
      {KEYS.map((key) => (
        <div key={key} className="field">
          <label>
            {t.settings.limit_labels[key]}
            <input
              type="text"
              inputMode="numeric"
              value={draft[key] ?? shown(view, key)}
              onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
            />
          </label>
          {NEXT_START.has(key) || view.restart_pending.includes(key) ? (
            <span className="restart-marker"> ({t.settings.restart_marker})</span>
          ) : null}
          {view.restart_pending.includes(key) ? (
            <span className="restart-waiting"> {t.settings.restart_waiting}</span>
          ) : null}
        </div>
      ))}
      <button type="button" className="primary" disabled={action.pending} onClick={submit}>
        {t.settings.apply}
      </button>
      {local === null ? null : <p role="alert">{local}</p>}
      {action.error === null ? null : <p role="alert">{action.error}</p>}
      {applied ? <p role="status">{t.settings.applied}</p> : null}
      </Guard>
    </section>
  );
}
