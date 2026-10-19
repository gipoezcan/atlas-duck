import { useCallback, useEffect, useRef, useState } from 'react';

import { on } from '../shared/ipc/events';
import { auditStatus, verifyNow } from '../shared/ipc/invoke';
import type { AuditFilter, AuditJobEvent, AuditStatus, EventHeader } from '../shared/ipc/types';
import { isAuditJobEvent } from '../shared/ipc/validate';
import { AUDIT_TEXT as T, WINDOW_TITLES } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';
import { EventList, Flags } from './EventList';
import { ExportBackup } from './ExportBackup';
import { Filters } from './Filters';
import { Incidents } from './Incidents';
import { PayloadView } from './PayloadView';
import { Val } from './text';
import { Trail } from './Trail';

type Result = keyof typeof T.results | 'refused';

/**
 * The Audit window (spec 8.7, 8.10; M6 shell PD-82, M10 T20): the open integrity incidents and
 * their acknowledgement, "Verify now", the records (typed filters, a windowed list newest first,
 * a record's columns, its request's trail and, on request, its decrypted payload in the sandboxed
 * frame), the compliance export and the full backup. Rust does every check, dialog and write; the
 * page shows its answers as text. It listens to `audit_changed` (ids and counts only: the
 * incidents are read again) and `audit_job` (checked with `isAuditJobEvent` before use).
 */
export function Audit() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [statusFailed, setStatusFailed] = useState(false);
  const [job, setJob] = useState<AuditJobEvent | null>(null);
  const [filter, setFilter] = useState<AuditFilter>({});
  const [listKey, setListKey] = useState(0);
  const [record, setRecord] = useState<EventHeader | null>(null);
  const inFlight = useRef(false);
  const live = useRef(true);
  const reading = useRef(false);
  const again = useRef(false);

  // One status read in flight at most; a trigger meanwhile schedules exactly one trailing read, so
  // the last read started after the last trigger.
  const readStatus = useCallback(() => {
    if (reading.current) {
      again.current = true;
      return;
    }
    const start = () => {
      reading.current = true;
      const settle = () => {
        reading.current = false;
        const rerun = again.current;
        again.current = false;
        if (rerun && live.current) start();
      };
      auditStatus().then(
        (s) => {
          if (live.current) {
            setStatus(s);
            setStatusFailed(false);
          }
          settle();
        },
        () => {
          if (live.current) setStatusFailed(true);
          settle();
        },
      );
    };
    start();
  }, []);

  useEffect(() => {
    live.current = true;
    const offJob = on<unknown>(
      'audit_job',
      (payload) => {
        if (isAuditJobEvent(payload)) setJob(payload);
      },
      { thisWindow: true },
    );
    const offChanged = on('audit_changed', readStatus, { thisWindow: true });
    // Read once the listeners are attached, so a change between the read and a listener is not lost.
    void Promise.allSettled([offJob, offChanged]).then(() => {
      if (live.current) readStatus();
    });
    return () => {
      live.current = false;
      for (const off of [offJob, offChanged]) void off.then((f) => f()).catch(() => undefined);
    };
  }, [readStatus]);

  const verify = () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRunning(true);
    setResult(null);
    verifyNow().then(
      (answer) => {
        inFlight.current = false;
        if (!live.current) return;
        setRunning(false);
        setResult(answer.result);
        if (answer.result === 'incident') readStatus();
      },
      () => {
        inFlight.current = false;
        if (!live.current) return;
        setRunning(false);
        setResult('refused');
      },
    );
  };

  const apply = (f: AuditFilter) => {
    setFilter(f);
    setListKey((k) => k + 1);
  };

  return (
    <main className="audit">
      <h1>{WINDOW_TITLES.audit}</h1>
      <Incidents status={status} failed={statusFailed} onRetry={readStatus} onChanged={readStatus} />
      <section aria-label={T.verification}>
        <h2>{T.verification}</h2>
        <button type="button" disabled={running} onClick={verify}>
          {running ? T.verifying : T.verify}
        </button>
        {result === null ? null : (
          <p role={result === 'verified' ? 'status' : 'alert'}>
            {result === 'refused' ? T.refused : T.results[result]}
          </p>
        )}
      </section>
      <ExportBackup job={job} />
      <section aria-label={T.records}>
        <h2>{T.records}</h2>
        <Filters onApply={apply} />
        <EventList key={listKey} filter={filter} selected={record?.seq ?? null} onOpen={setRecord} />
        {record === null ? null : (
          <RecordDetail key={record.seq} header={record} onOpen={setRecord} onClose={() => setRecord(null)} />
        )}
      </section>
    </main>
  );
}

const FIELDS = [
  'ts_utc',
  'epoch',
  'chain_id',
  'event_type',
  'request_id',
  'op_id',
  'op_class',
  'instance_id',
  'target',
  'decision',
  'agent_name_source',
  'client_kind',
  'connection_id',
  'peer_pid',
  'peer_exe',
  'peer_origin_exe',
  'os_user',
  'atlassian_user',
  'atlassian_user_key',
  'payload_len',
  'key_id',
] as const;

/**
 * One record: its plaintext columns as text (the agent's name behind the "unverified" badge, the
 * flags as labels), its request's trail, and its decrypted payload only once asked for. Focus
 * moves to its heading when it opens.
 */
function RecordDetail({
  header: h,
  onOpen,
  onClose,
}: {
  header: EventHeader;
  onOpen: (header: EventHeader) => void;
  onClose: () => void;
}) {
  const [payload, setPayload] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    heading.current?.focus();
  }, []);

  return (
    <section className="audit-record" aria-label={T.record(h.seq)}>
      <h3 ref={heading} tabIndex={-1}>
        {T.record(h.seq)}
      </h3>
      <dl>
        {FIELDS.map((key) => (
          <div key={key}>
            <dt>{T.field[key]}</dt>
            <dd>
              <Val value={h[key]} />
            </dd>
          </div>
        ))}
        <div>
          <dt>{T.field.agent_name}</dt>
          <dd>
            {h.agent_name === null ? T.no_value : <AgentText value={h.agent_name} unusual={unusual(h.agent_name)} />}
          </dd>
        </div>
        <div>
          <dt>{T.field.flags}</dt>
          <dd>{h.flags.length === 0 ? T.no_value : <Flags flags={h.flags} />}</dd>
        </div>
      </dl>
      {payload ? (
        <PayloadView seq={h.seq} />
      ) : (
        <button type="button" onClick={() => setPayload(true)}>
          {T.payload_show}
        </button>
      )}
      {h.request_id === null ? null : <Trail key={h.request_id} requestId={h.request_id} onOpen={onOpen} />}
      <button type="button" onClick={onClose}>
        {T.record_close}
      </button>
    </section>
  );
}
