import { useState } from 'react';

import { pruneBacklogNow, settingsApply } from '../shared/ipc/invoke';
import type { AttentionMode, PruneReport, SettingChange, SettingsView } from '../shared/ipc/types';
import { SETTINGS_TEXT as T } from '../shared/strings';
import { parseWhole } from './Limits';
import { Guard } from './Guard';
import { Cfg, own } from './text';
import { useAction } from './useAction';

const MODES: readonly AttentionMode[] = ['show_without_activating', 'badge_only', 'show_and_focus'];

interface RetentionProps {
  view: SettingsView;
  onChanged: () => void;
  readOnly: boolean;
}

/**
 * Retention, legal hold and the attention mode and the prune backlog line (the external anchor
 * directory has its own section, `AnchorDir`). Retention and hold go through core's native confirmation when they
 * weaken a guarantee; a declined confirmation is `cancelled`: the hold and the mode snap back to
 * the stored value, the typed retention days stay in the field beside the error text. A read-only
 * config turns the config-writing controls off; the prune button is core's call.
 */
export function Retention({ view, onChanged, readOnly }: RetentionProps) {
  const [days, setDays] = useState<string | null>(null);
  const [local, setLocal] = useState<string | null>(null);
  const retention = useAction();
  const hold = useAction();
  const mode = useAction();
  const prune = useAction();
  const [report, setReport] = useState<PruneReport | null>(null);

  const applyDays = () => {
    if (days === null) return;
    const n = parseWhole(days);
    if (n === null) {
      setLocal(T.not_a_number);
      return;
    }
    setLocal(null);
    const change: SettingChange = { key: 'retention_days', value: n };
    void retention.run(() => settingsApply([change])).then((v) => {
      if (v === undefined) return;
      setDays(null);
      onChanged();
    });
  };

  const setHold = (value: boolean) => {
    void hold.run(() => settingsApply([{ key: 'legal_hold', value }])).then((v) => {
      if (v !== undefined) onChanged();
    });
  };

  const setMode = (value: AttentionMode) => {
    void mode.run(() => settingsApply([{ key: 'attention_mode', value }])).then((v) => {
      if (v !== undefined) onChanged();
    });
  };

  const backlog = view.health.prune_backlog;
  return (
    <section aria-label={T.retention}>
      <h2>{T.retention}</h2>
      <Guard disabled={readOnly}>
      <div className="field">
        <label>
          {T.retention_days}
          <input
            type="text"
            inputMode="numeric"
            value={days ?? String(view.retention_days)}
            onChange={(e) => setDays(e.target.value)}
          />
        </label>
        <button type="button" className="primary" disabled={retention.pending || days === null} onClick={applyDays}>
          {T.apply}
        </button>
        {local === null ? null : <p role="alert">{local}</p>}
        {retention.error === null ? null : <p role="alert">{retention.error}</p>}
      </div>
      <div className="field">
        <label>
          <input
            type="checkbox"
            checked={view.legal_hold}
            disabled={hold.pending}
            onChange={(e) => setHold(e.target.checked)}
          />
          {T.legal_hold}
        </label>
        {hold.error === null ? null : <p role="alert">{hold.error}</p>}
      </div>
      <div className="field">
        <label>
          {T.attention}
          <select
            value={view.attention_mode}
            disabled={mode.pending}
            onChange={(e) => setMode(e.target.value as AttentionMode)}
          >
            {MODES.map((m) => (
              <option key={m} value={m}>
                {T.attention_modes[m]}
              </option>
            ))}
          </select>
        </label>
        <p>{T.presentation_note}</p>
        {mode.error === null ? null : <p role="alert">{mode.error}</p>}
      </div>
      </Guard>
      <section aria-label={T.prune}>
        <h3>{T.prune}</h3>
        {view.health.last_prune_failed ? <p>{T.prune_failed_last}</p> : null}
        {backlog === null ? null : (
          <>
            <p>
              <Cfg value={backlog} />
            </p>
            <button
              type="button"
              className="danger"
              disabled={prune.pending}
              onClick={() =>
                void prune.run(() => pruneBacklogNow()).then((r) => {
                  if (r === undefined) return;
                  setReport(r);
                  onChanged();
                })
              }
            >
              {T.prune_button}
            </button>
          </>
        )}
        {prune.error === null ? null : <p role="alert">{prune.error}</p>}
        {report === null ? null : <PruneResult report={report} />}
      </section>
    </section>
  );
}

function PruneResult({ report }: { report: PruneReport }) {
  if (report.result === 'pruned') {
    return (
      <p role="status">
        {T.pruned(report.count, report.cutoff)}
        {report.clamped ? ` ${T.pruned_clamped}` : ''}
      </p>
    );
  }
  const known = own(T.prune_reasons, report.reason);
  return (
    <p role="status">
      {T.prune_skipped}: {known ?? <Cfg value={report.reason} />}
    </p>
  );
}
