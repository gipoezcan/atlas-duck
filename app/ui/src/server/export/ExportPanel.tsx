import { useCallback, useEffect, useRef, useState } from 'react';

import { useText } from '../../shared/i18n/context';
import { api } from '../http';

/**
 * The server export panel (M14 PD-254..PD-256), shared by `/audit` (the user's own chain,
 * `/api/me/audit/exports`) and `/auditor` (a selected user's chain,
 * `/api/auditor/users/<id>/exports`): start a job, follow it (every 2 s while the page is
 * visible, until it ends), then the download link with the manifest SHA-256, the anchor head and
 * the verify command, each with a copy button. The pin is the job's own anchor row (the `HEADS`
 * row it forced), not the chain's current head, which moves on. Nothing is kept in browser
 * storage.
 */

/** Browser pieces (replaced in tests). */
export const exportBrowser = {
  copy: (text: string): Promise<void> => navigator.clipboard.writeText(text),
  hidden: (): boolean => document.visibilityState === 'hidden',
  pollMs: 2000,
};

export interface ExportJob {
  job_id: string;
  state: 'running' | 'done' | 'failed' | 'downloaded';
  progress?: { done: number; total: number };
  manifest_sha256?: string;
  anchor_head?: { seq: number; hash: string };
  verify_command?: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX64 = /^[0-9a-f]{64}$/;

export function isExportJob(v: unknown): v is ExportJob {
  if (!isRecord(v) || typeof v.job_id !== 'string' || !/^[0-9a-f]{32}$/.test(v.job_id)) return false;
  if (v.state !== 'running' && v.state !== 'done' && v.state !== 'failed' && v.state !== 'downloaded') {
    return false;
  }
  const p = v.progress;
  if (p !== undefined && !(isRecord(p) && typeof p.done === 'number' && typeof p.total === 'number')) {
    return false;
  }
  if (v.manifest_sha256 !== undefined && !(typeof v.manifest_sha256 === 'string' && HEX64.test(v.manifest_sha256))) {
    return false;
  }
  const a = v.anchor_head;
  if (a !== undefined && !(isRecord(a) && typeof a.seq === 'number' && typeof a.hash === 'string' && HEX64.test(a.hash))) {
    return false;
  }
  return v.verify_command === undefined || typeof v.verify_command === 'string';
}

type View =
  | { kind: 'idle' }
  | { kind: 'starting' }
  | { kind: 'running'; job: ExportJob }
  | { kind: 'done'; job: ExportJob };

function CopyRow({ label, value }: { label: string; value: string }) {
  const t = useText();
  const [note, setNote] = useState<string | null>(null);
  return (
    <div className="export-copy">
      <dt>{label}</dt>
      <dd>
        <code>{value}</code>{' '}
        <button
          type="button"
          aria-label={`${t.admin.export.copy} ${label}`}
          onClick={() => {
            exportBrowser.copy(value).then(
              () => setNote(t.admin.export.copied),
              () => setNote(t.admin.export.copy_failed),
            );
          }}
        >
          {t.admin.export.copy}
        </button>
        {note !== null ? <span role="status"> {note}</span> : null}
      </dd>
    </div>
  );
}

export function ExportPanel({ base }: { base: string }) {
  const t = useText();
  const [view, setView] = useState<View>({ kind: 'idle' });
  const [notice, setNotice] = useState<string | null>(null);
  const [all, setAll] = useState(true);
  const [from, setFrom] = useState('');
  const timer = useRef<number | null>(null);

  const stop = useCallback(() => {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  const poll = useCallback(
    (jobId: string) => {
      stop();
      timer.current = window.setTimeout(() => {
        timer.current = null;
        if (exportBrowser.hidden()) return;
        void api('GET', `${base}/${jobId}`, isExportJob).then((r) => {
          if (!r.ok) {
            setView({ kind: 'idle' });
            setNotice(r.status === 410 ? t.admin.export.expired : t.admin.export.failed);
            return;
          }
          const job = r.value;
          if (job.state === 'running') {
            setView({ kind: 'running', job });
            poll(jobId);
          } else if (job.state === 'done') {
            setView({ kind: 'done', job });
          } else {
            setView({ kind: 'idle' });
            setNotice(job.state === 'failed' ? t.admin.export.failed : t.admin.export.expired);
          }
        });
      }, exportBrowser.pollMs);
    },
    [base, stop, t],
  );

  // Polling stops while the page is hidden and resumes when it is shown again.
  useEffect(() => {
    const onVisible = () => {
      if (!exportBrowser.hidden() && view.kind === 'running' && timer.current === null) {
        poll(view.job.job_id);
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, [poll, view]);
  useEffect(() => stop, [stop]);

  const start = async () => {
    setNotice(null);
    let body: Record<string, string> = {};
    if (!all) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(from)) {
        setNotice(t.admin.export.bad_date);
        return;
      }
      body = { from_utc: `${from}T00:00:00.000Z` };
    }
    setView({ kind: 'starting' });
    const r = await api('POST', base, isExportJob, body);
    if (!r.ok) {
      setView({ kind: 'idle' });
      setNotice(r.status === 409 ? t.admin.export.busy : t.admin.export.start_failed);
      return;
    }
    setView({ kind: 'running', job: r.value });
    poll(r.value.job_id);
  };

  const busy = view.kind === 'starting' || view.kind === 'running';
  return (
    <section aria-label={t.admin.export.title} className="export-panel">
      <h2>{t.admin.export.title}</h2>
      <p>{t.admin.export.intro}</p>
      <fieldset disabled={busy}>
        <label>
          <input type="radio" name="export-range" checked={all} onChange={() => setAll(true)} />{' '}
          {t.admin.export.range_all}
        </label>
        <label>
          <input type="radio" name="export-range" checked={!all} onChange={() => setAll(false)} />{' '}
          {t.admin.export.range_from}
        </label>
        {!all ? (
          <input
            type="date"
            aria-label={t.admin.export.range_from}
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        ) : null}
        <button type="button" onClick={() => void start()}>
          {view.kind === 'starting' ? t.admin.export.starting : t.admin.export.start}
        </button>
      </fieldset>
      {notice !== null ? (
        <p role="alert" className="notice notice-danger">
          {notice}
        </p>
      ) : null}
      {view.kind === 'running' ? (
        <p role="status">
          {t.admin.export.running(view.job.progress?.done ?? 0, view.job.progress?.total ?? 0)}
        </p>
      ) : null}
      {view.kind === 'done' ? (
        <div>
          <p role="status">{t.admin.export.done}</p>
          <p>
            <a href={`${base}/${view.job.job_id}/download`} download>
              {t.admin.export.download}
            </a>
          </p>
          <dl>
            {view.job.manifest_sha256 !== undefined ? (
              <CopyRow label={t.admin.export.manifest} value={view.job.manifest_sha256} />
            ) : null}
            {view.job.anchor_head !== undefined ? (
              <CopyRow
                label={t.admin.export.anchor}
                value={`${view.job.anchor_head.seq}:${view.job.anchor_head.hash}`}
              />
            ) : null}
            {view.job.verify_command !== undefined ? (
              <CopyRow label={t.admin.export.verify} value={view.job.verify_command} />
            ) : null}
          </dl>
          <p className="muted">{t.admin.export.out_of_band}</p>
        </div>
      ) : null}
    </section>
  );
}
