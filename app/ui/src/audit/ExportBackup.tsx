import { useEffect, useId, useRef, useState } from 'react';

import { backupTrigger, exportCancel, exportTrigger } from '../shared/ipc/invoke';
import type { AuditJobEvent, AuditJobKind, ExportDone } from '../shared/ipc/types';
import { AUDIT_TEXT as T } from '../shared/strings';
import { errorText, kinds, utcOf } from './text';

interface Props {
  /** The latest `audit_job` event (validated by the window), or null before any. */
  job: AuditJobEvent | null;
}

type Said = { text: string; role: 'status' | 'alert' };

/** How an export ended: complete (also when only the rename failed), or a sentence. */
type ExportOutcome =
  | { kind: 'done'; done: ExportDone }
  | { kind: 'not_renamed'; done: ExportDone }
  | ({ kind: 'said' } & Said);

function exportRefusal(e: unknown): ExportOutcome {
  const { kind, inner } = kinds(e);
  if (kind === 'cancelled') return { kind: 'said', text: T.export_cancelled, role: 'status' };
  if (kind === 'export' && typeof e === 'object' && e !== null) {
    const error = (e as { error: Record<string, unknown> }).error;
    const name = typeof error['dir_name'] === 'string' ? error['dir_name'] : '';
    if (inner === 'leftover') return { kind: 'said', text: T.export_leftover(name), role: 'alert' };
    if (inner === 'not_renamed' && typeof error['manifest_sha256'] === 'string' && typeof error['rows'] === 'number') {
      return {
        kind: 'not_renamed',
        done: { manifest_sha256: error['manifest_sha256'], dir_name: name, rows: error['rows'] },
      };
    }
  }
  return { kind: 'said', text: errorText(e), role: 'alert' };
}

function backupRefusal(e: unknown): Said {
  if (kinds(e).kind === 'cancelled') return { text: T.backup_cancelled, role: 'status' };
  return { text: errorText(e), role: 'alert' };
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
  const [exportOutcome, setExportOutcome] = useState<ExportOutcome | null>(null);
  const [backupOutcome, setBackupOutcome] = useState<Said | null>(null);
  const [cancelSaid, setCancelSaid] = useState<Said | null>(null);
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
  const release = () => {
    inFlight.current = false;
    setEnded(jobRef.current);
  };

  const startExport = () => {
    const fromUtc = utcOf(from);
    const toUtc = utcOf(to);
    if (fromUtc === undefined || toUtc === undefined) {
      setExportOutcome({ kind: 'said', text: T.export_errors['from_utc'] ?? '', role: 'alert' });
      return;
    }
    if (fromUtc !== null && toUtc !== null && fromUtc > toUtc) {
      setExportOutcome({ kind: 'said', text: T.export_errors['to_utc'] ?? '', role: 'alert' });
      return;
    }
    if (!claim()) return;
    setExporting(true);
    setExportOutcome(null);
    setCancelSaid(null);
    exportTrigger(fromUtc, toUtc).then(
      (done) => {
        release();
        setExporting(false);
        setExportOutcome({ kind: 'done', done });
      },
      (e: unknown) => {
        release();
        setExporting(false);
        setExportOutcome(exportRefusal(e));
      },
    );
  };

  const cancel = () => {
    exportCancel().then(
      (a) => setCancelSaid({ text: a.cancelled ? T.export_cancel_requested : T.export_cancel_none, role: 'status' }),
      (e: unknown) => setCancelSaid({ text: errorText(e), role: 'alert' }),
    );
  };

  const startBackup = () => {
    if (!claim()) return;
    setBackingUp(true);
    setBackupOutcome(null);
    backupTrigger().then(
      (a) => {
        release();
        setBackingUp(false);
        setBackupOutcome({ text: a.saved ? T.backup_saved : T.backup_not_saved, role: 'status' });
      },
      (e: unknown) => {
        release();
        setBackingUp(false);
        setBackupOutcome(backupRefusal(e));
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
      <button type="button" disabled={busy} onClick={startExport}>
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
          {cancelSaid === null ? null : <p role={cancelSaid.role}>{cancelSaid.text}</p>}
        </div>
      ) : null}
      {exportOutcome === null ? null : <ExportResult outcome={exportOutcome} />}

      <h3>{T.backup}</h3>
      <p>{T.backup_note}</p>
      <button type="button" disabled={busy} onClick={startBackup}>
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
      {backupOutcome === null ? null : <p role={backupOutcome.role}>{backupOutcome.text}</p>}
    </section>
  );
}

/** The export's result: the trust root to hand on, with the recipient's instructions (PD-161). */
function ExportResult({ outcome }: { outcome: ExportOutcome }) {
  if (outcome.kind === 'said') return <p role={outcome.role}>{outcome.text}</p>;
  const { manifest_sha256: hex, dir_name: name, rows } = outcome.done;
  return (
    <div role={outcome.kind === 'done' ? 'status' : 'alert'} className="audit-export-result">
      <p>{outcome.kind === 'done' ? T.export_done(name, rows) : T.export_not_renamed(name, rows)}</p>
      <p>{T.export_recipient(hex)}</p>
      <p>
        <code>{hex}</code>
      </p>
    </div>
  );
}
