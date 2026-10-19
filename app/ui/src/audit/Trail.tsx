import { useEffect, useState } from 'react';

import { auditTrail } from '../shared/ipc/invoke';
import type { AuditTrail, EventHeader } from '../shared/ipc/types';
import { AUDIT_TEXT as T } from '../shared/strings';
import { Badge } from '../shared/text/Badge';
import { Flags } from './EventList';
import { Val } from './text';

interface Props {
  requestId: string;
  /** Shows another record of the trail in the detail. */
  onOpen: (header: EventHeader) => void;
}

/** Why the trail is not shown: an unreadable record of the request names its seq (T10 decision 3). */
function failureText(e: unknown): string {
  if (typeof e === 'object' && e !== null) {
    const r = e as { kind?: unknown; error?: { kind?: unknown; seq?: unknown } };
    if (r.kind === 'audit' && r.error?.kind === 'unreadable' && typeof r.error.seq === 'number') {
      return T.trail_unreadable(r.error.seq);
    }
  }
  return T.trail_failed;
}

/**
 * A request's full event trail (spec 8.10): its retained records oldest first, with its
 * deliveries. "Delivered more than once" and "delivered to a different program" (Rust compares
 * the origin program and its start time, spec 3.1) are text labels with the advisory sentence,
 * never colour alone. The records are text; each can be opened in the detail.
 */
export function Trail({ requestId, onOpen }: Props) {
  const [trail, setTrail] = useState<AuditTrail | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setTrail(null);
    setFailed(null);
    auditTrail(requestId).then(
      (t) => {
        if (live) setTrail(t);
      },
      (e: unknown) => {
        if (live) setFailed(failureText(e));
      },
    );
    return () => {
      live = false;
    };
  }, [requestId]);

  const marked = trail !== null && (trail.deliveries.count > 1 || trail.deliveries.to_other_peer);
  return (
    <section className="audit-trail" aria-label={T.trail}>
      <h3>{T.trail}</h3>
      {failed === null ? null : <p role="alert">{failed}</p>}
      {trail === null ? (
        failed === null ? (
          <p role="status">{T.trail_loading}</p>
        ) : null
      ) : (
        <>
          <p>
            <span>{T.deliveries(trail.deliveries.count)}</span>{' '}
            {trail.deliveries.count > 1 ? <Badge label={T.delivered_more_than_once} tone="caution" /> : null}
            {trail.deliveries.to_other_peer ? (
              <Badge label={T.delivered_to_other_program} tone="caution" />
            ) : null}
          </p>
          {marked ? <p>{T.deliveries_advisory}</p> : null}
          <ol>
            {trail.headers.map((h) => (
              <li key={h.seq}>
                <button type="button" onClick={() => onOpen(h)}>
                  {T.open_record(h.seq)}
                </button>{' '}
                <span>{h.ts_utc}</span>{' '}
                <code>
                  <Val value={h.event_type} />
                </code>
                {h.decision === null ? null : (
                  <>
                    {' '}
                    <Val value={h.decision} />
                  </>
                )}{' '}
                <Flags flags={h.flags} />
                {h.peer_origin_exe === null ? null : (
                  <>
                    {' '}
                    {T.field.peer_origin_exe}: <Val value={h.peer_origin_exe} />
                  </>
                )}
              </li>
            ))}
          </ol>
        </>
      )}
    </section>
  );
}
