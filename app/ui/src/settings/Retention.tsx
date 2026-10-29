import { useState } from 'react';
import { useText } from '../shared/i18n/context';

import { pruneBacklogNow, settingsApply } from '../shared/ipc/invoke';
import type { AttentionMode, PruneReport, SettingChange, SettingsView } from '../shared/ipc/types';
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
  const t = useText();
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
      setLocal(t.settings.not_a_number);
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
    <section aria-label={t.settings.retention}>
      <h2>{t.settings.retention}</h2>
      <Guard disabled={readOnly}>
      <div className="field">
        <label>
          {t.settings.retention_days}
          <input
            type="text"
            inputMode="numeric"
            value={days ?? String(view.retention_days)}
            onChange={(e) => setDays(e.target.value)}
          />
        </label>
        <button type="button" className="primary" disabled={retention.pending || days === null} onClick={applyDays}>
          {t.settings.apply}
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
          {t.settings.legal_hold}
        </label>
        {hold.error === null ? null : <p role="alert">{hold.error}</p>}
      </div>
      <div className="field">
        <label>
          {t.settings.attention}
          <select
            value={view.attention_mode}
            disabled={mode.pending}
            onChange={(e) => setMode(e.target.value as AttentionMode)}
          >
            {MODES.map((m) => (
              <option key={m} value={m}>
                {t.settings.attention_modes[m]}
              </option>
            ))}
          </select>
        </label>
        <p>{t.settings.presentation_note}</p>
        {mode.error === null ? null : <p role="alert">{mode.error}</p>}
      </div>
      </Guard>
      <section aria-label={t.settings.prune}>
        <h3>{t.settings.prune}</h3>
        {view.health.last_prune_failed ? <p>{t.settings.prune_failed_last}</p> : null}
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
              {t.settings.prune_button}
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
  const t = useText();
  if (report.result === 'pruned') {
    return (
      <p role="status">
        {t.settings.pruned(report.count, report.cutoff)}
        {report.clamped ? ` ${t.settings.pruned_clamped}` : ''}
      </p>
    );
  }
  const known = own(t.settings.prune_reasons, report.reason);
  return (
    <p role="status">
      {t.settings.prune_skipped}: {known ?? <Cfg value={report.reason} />}
    </p>
  );
}
