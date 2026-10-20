import { useEffect, useId, useRef, useState } from 'react';

import { acknowledgeIncident } from '../shared/ipc/invoke';
import type { AuditIncident, AuditStatus } from '../shared/ipc/types';
import { AUDIT_TEXT as T } from '../shared/strings';
import { own } from '../shared/text/own';
import { Announce, errorText, kinds, type Said, Val } from './text';

/** plan text (PD-180): the note is at most 1 000 characters; Rust re-validates (`invalid_argument {note}`). */
const NOTE_MAX = 1_000;

interface Props {
  /** `audit_status`, or `null` before the first read. */
  status: AuditStatus | null;
  /** The last read failed. */
  failed: boolean;
  onRetry: () => void;
  /** The incidents changed (an acknowledgement, or one closed meanwhile): read them again. */
  onChanged: () => void;
}

function refusal(e: unknown): Said {
  const { kind, inner, field } = kinds(e);
  if (kind === 'cancelled') return { body: T.ack_cancelled, role: 'status' };
  const text =
    kind === 'not_found'
      ? own(T.ack_errors, 'not_found')
      : kind === 'invalid_argument' && field === 'note'
        ? own(T.ack_errors, 'note')
        : kind === 'audit' && inner === 'unreadable'
          ? own(T.ack_errors, 'unreadable')
          : undefined;
  return { body: text ?? errorText(e), role: 'alert' };
}

/**
 * The open integrity incidents (spec 8.7; count L134) and "Acknowledge integrity incident". The
 * note is typed here; the confirmation is Rust's own native dialog naming the incident from its
 * record (PD-180), so this page only shows the answer, or "cancelled". Rust then clears the red
 * banner (`status_banner`) and the window reads the incidents again. The anchor directory and its
 * failing appends (spec 8.5) are shown with them, display only.
 */
export function Incidents({ status, failed, onRetry, onChanged }: Props) {
  const [open, setOpen] = useState<number | null>(null);
  const [note, setNote] = useState('');
  const [sending, setSending] = useState(false);
  const [outcome, setOutcome] = useState<Said | null>(null);
  const inFlight = useRef(false);
  const live = useRef(true);
  const field = useRef<HTMLTextAreaElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const triggers = useRef(new Map<number, HTMLButtonElement>());
  const ids = useId();

  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);

  useEffect(() => {
    if (open !== null) field.current?.focus();
  }, [open]);

  const start = (seq: number) => {
    setOpen(seq);
    setNote('');
    setOutcome(null);
  };

  /** The note closes: focus goes back to the button that opened it (it would fall to the page). */
  const close = (seq: number) => {
    setOpen(null);
    triggers.current.get(seq)?.focus();
  };

  const send = (seq: number) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setSending(true);
    setOutcome(null);
    acknowledgeIncident(seq, note).then(
      (ack) => {
        inFlight.current = false;
        if (!live.current) return;
        setSending(false);
        setOpen(null);
        // The incident drops out of the list: focus goes to the section, which stays.
        heading.current?.focus();
        setOutcome({ body: T.ack_done(ack.verify_seq, ack.ack_seq), role: 'status' });
        onChanged();
      },
      (e: unknown) => {
        inFlight.current = false;
        if (!live.current) return;
        setSending(false);
        setOutcome(refusal(e));
        if (kinds(e).kind === 'not_found') onChanged();
      },
    );
  };

  const item = (incident: AuditIncident) => {
    const seq = incident.verify_seq;
    const unreadable = incident.result === null || incident.detected_at === null;
    return (
      <li key={seq}>
        <span>{T.incident_label(seq)}</span>
        {unreadable ? (
          <>: {T.incident_unreadable}</>
        ) : (
          <>
            {' '}
            ({T.incident_result}: <code><Val value={incident.result} /></code>, {T.incident_detected}:{' '}
            <Val value={incident.detected_at} />)
          </>
        )}{' '}
        <button
          type="button"
          ref={(el) => {
            if (el === null) triggers.current.delete(seq);
            else triggers.current.set(seq, el);
          }}
          aria-label={T.acknowledge_label(seq)}
          aria-expanded={open === seq}
          disabled={sending}
          onClick={() => start(seq)}
        >
          {T.acknowledge}
        </button>
        {open === seq ? (
          <div className="audit-ack" role="group" aria-label={T.acknowledge_label(seq)}>
            <label htmlFor={`${ids}-note`}>{T.ack_note}</label>
            <textarea
              id={`${ids}-note`}
              ref={field}
              value={note}
              maxLength={NOTE_MAX}
              aria-describedby={`${ids}-hint`}
              onChange={(e) => setNote(e.currentTarget.value)}
            />
            <p id={`${ids}-hint`}>{T.ack_hint}</p>
            <button type="button" disabled={sending} onClick={() => send(seq)}>
              {T.ack_send}
            </button>{' '}
            <button type="button" disabled={sending} onClick={() => close(seq)}>
              {T.ack_close}
            </button>
          </div>
        ) : null}
      </li>
    );
  };

  return (
    <section className="audit-incidents" aria-label={T.incidents}>
      <h2 ref={heading} tabIndex={-1}>
        {T.incidents}
      </h2>
      {status === null ? (
        failed ? (
          <p role="alert">
            {T.incidents_failed}{' '}
            <button type="button" onClick={onRetry}>
              {T.retry}
            </button>
          </p>
        ) : (
          <p>{T.loading}</p>
        )
      ) : (
        <>
          <p>{T.incident_count(status.incident_count)}</p>
          {status.open_incidents.length < status.incident_count ? (
            <p>{T.incidents_listed(status.open_incidents.length, status.incident_count)}</p>
          ) : null}
          {status.open_incidents.length === 0 ? null : <ul>{status.open_incidents.map(item)}</ul>}
          <p>
            {T.anchor_dir}:{' '}
            {status.anchor_dir === null ? <span>{T.anchor_dir_none}</span> : <Val value={status.anchor_dir} />}
          </p>
          {status.health.anchor_dir_write_failing ? (
            <p>{T.anchor_dir_failing(status.health.anchor_dir_lines_pending)}</p>
          ) : null}
        </>
      )}
      <Announce said={outcome} />
    </section>
  );
}
