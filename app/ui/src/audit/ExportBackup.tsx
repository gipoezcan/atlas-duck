import { useEffect, useId, useRef, useState } from 'react';

import { backupTrigger, exportCancel, exportTrigger } from '../shared/ipc/invoke';
import type { AuditJobEvent, AuditJobKind } from '../shared/ipc/types';
import { AUDIT_TEXT as T } from '../shared/strings';
import { Announce, errorText, exportRefusal, exportResult, kinds, type Said, say, utcOf } from './text';

interface Props {
  /** The latest `audit_job` event (validated by the window), or null before any. */
  job: AuditJobEvent | null;
}

function backupRefusal(e: unknown): Said {
  if (kinds(e).kind === 'cancelled') return say('status', T.backup_cancelled);
  return say('alert', errorText(e));
}

const running = (job: AuditJobEvent | null, kind: AuditJobKind) =>
  job !== null && job.job === kind && (job.phase === 'started' || job.phase === 'progress');

/**
 * The compliance export and the full backup (spec 8.10, PD-161, PD-181). Rust shows the export
 * warning and every folder dialog itself; the page sends only the UTC range. An export reports
 * its rows per batch through `audit_job` (a progress bar and Cancel, which only asks: the
 * export's own answer, or the terminal `audit_job`, is the outcome); a backup (or a restore
 * Settings started) is indeterminate. The result is the manifest's SHA-256 with the recipient's
 * instructions, or a fixed sentence: a partial folder left behind is always named (T12 review
 * M-6), and an export left under its `.partial` name is complete and never retried.
 * One job at a time: both triggers are off while any runs (Rust answers `busy` otherwise).
 */
export function ExportBackup({ job }: Props) {
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [exporting, setExporting] = useState(false);
  const [backingUp, setBackingUp] = useState(false);
  // The latest thing a command of this window said (one live region for all of them).
  const [said, setSaid] = useState<Said | null>(null);
  // The job event current when this window's own call ended: a terminal event that never comes
  // must not keep the triggers off (the next event replaces it).
  const [ended, setEnded] = useState<AuditJobEvent | null>(null);
  const inFlight = useRef(false);
  const jobRef = useRef(job);
  useEffect(() => {
    jobRef.current = job;
  }, [job]);
  const ids = useId();

  const live = job === ended ? null : job;
  const exportActive = exporting || running(live, 'export');
  const backupActive = backingUp || running(live, 'backup');
  const restoreActive = running(live, 'restore');
  const busy = exportActive || backupActive || restoreActive;
  const progress =
    live !== null && live.job === 'export' && live.phase === 'progress' && live.done !== undefined && live.total !== undefined
      ? { done: live.done, total: live.total }
      : null;

  const claim = () => {
    if (inFlight.current || busy) return false;
    inFlight.current = true;
    return true;
  };
  /**
   * This window's own call ended: the job event then current is ignored when it is one of this
   * call's own kind (its terminal event may never come), unless the call was refused as `busy`:
   * then a job another window runs is what is current, and it must stay shown.
   */
  const release = (kind: AuditJobKind, failure?: unknown) => {
    inFlight.current = false;
    const current = jobRef.current;
    if (kinds(failure).kind === 'busy' || current === null || current.job !== kind) return;
    setEnded(current);
  };

  const startExport = () => {
    const fromUtc = utcOf(from);
    const toUtc = utcOf(to);
    if (fromUtc === undefined || toUtc === undefined) {
      setSaid(say('alert', T.export_errors['from_utc'] ?? ''));
      return;
    }
    if (fromUtc !== null && toUtc !== null && fromUtc > toUtc) {
      setSaid(say('alert', T.export_errors['to_utc'] ?? ''));
      return;
    }
    if (!claim()) return;
    setExporting(true);
    setSaid(null);
    exportTrigger(fromUtc, toUtc).then(
      (done) => {
        release('export');
        setExporting(false);
        setSaid(exportResult(done, true));
      },
      (e: unknown) => {
        release('export', e);
        setExporting(false);
        setSaid(exportRefusal(e));
      },
    );
  };

  const cancel = () => {
    exportCancel().then(
      (a) => setSaid(say('status', a.cancelled ? T.export_cancel_requested : T.export_cancel_none)),
      (e: unknown) => setSaid(say('alert', errorText(e))),
    );
  };

  const startBackup = () => {
    if (!claim()) return;
    setBackingUp(true);
    setSaid(null);
    backupTrigger().then(
      (a) => {
        release('backup');
        setBackingUp(false);
        setSaid(say('status', a.saved ? T.backup_saved : T.backup_not_saved));
      },
      (e: unknown) => {
        release('backup', e);
        setBackingUp(false);
        setSaid(backupRefusal(e));
      },
    );
  };

  return (
    <section className="audit-jobs" aria-label={T.jobs}>
      <h2>{T.jobs}</h2>
      <h3>{T.export}</h3>
      <p>{T.export_intro}</p>
      <div className="audit-fields">
        <div className="audit-field">
          <label htmlFor={`${ids}-from`}>{T.export_from}</label>
          <input
            id={`${ids}-from`}
            type="datetime-local"
            step="0.001"
            value={from}
            onChange={(e) => setFrom(e.currentTarget.value)}
          />
        </div>
        <div className="audit-field">
          <label htmlFor={`${ids}-to`}>{T.export_to}</label>
          <input
            id={`${ids}-to`}
            type="datetime-local"
            step="0.001"
            value={to}
            onChange={(e) => setTo(e.currentTarget.value)}
          />
        </div>
      </div>
      <button type="button" className="primary" disabled={busy} onClick={startExport}>
        {T.export_start}
      </button>
      {exportActive ? (
        <div className="audit-job">
          <span id={`${ids}-export`}>{T.export_running}</span>{' '}
          {progress === null ? (
            <>
              <progress aria-labelledby={`${ids}-export`} /> <span>{T.export_starting}</span>
            </>
          ) : (
            <>
              <progress aria-labelledby={`${ids}-export`} value={progress.done} max={progress.total} />{' '}
              <span>{T.export_progress(progress.done, progress.total)}</span>
            </>
          )}{' '}
          <button type="button" onClick={cancel}>
            {T.export_cancel}
          </button>
        </div>
      ) : null}

      <h3>{T.backup}</h3>
      <p>{T.backup_note}</p>
      <button type="button" className="primary" disabled={busy} onClick={startBackup}>
        {T.backup_start}
      </button>
      {backupActive ? (
        <div className="audit-job">
          <span id={`${ids}-backup`}>{T.backup_running}</span> <progress aria-labelledby={`${ids}-backup`} />
        </div>
      ) : null}
      {restoreActive ? (
        <div className="audit-job">
          <span id={`${ids}-restore`}>{T.restore_running}</span> <progress aria-labelledby={`${ids}-restore`} />
        </div>
      ) : null}
      <Announce said={said} />
    </section>
  );
}
