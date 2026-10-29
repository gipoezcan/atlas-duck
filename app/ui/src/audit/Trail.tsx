import { useEffect, useState } from 'react';
import { useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';
import { en } from '../shared/i18n/dict';

import { auditTrail } from '../shared/ipc/invoke';
import type { AuditTrail, EventHeader } from '../shared/ipc/types';
import { Badge } from '../shared/text/Badge';
import { Flags } from './EventList';
import { Val } from './text';

interface Props {
  requestId: string;
  /** Shows another record of the trail in the detail. */
  onOpen: (header: EventHeader) => void;
}

/** Why the trail is not shown: an unreadable record of the request names its seq (T10 decision 3). */
function failureText(e: unknown, t: Dict = en): string {
  if (typeof e === 'object' && e !== null) {
    const r = e as { kind?: unknown; error?: { kind?: unknown; seq?: unknown } };
    if (r.kind === 'audit' && r.error?.kind === 'unreadable' && typeof r.error.seq === 'number') {
      return t.audit.trail_unreadable(r.error.seq);
    }
  }
  return t.audit.trail_failed;
}

/**
 * A request's full event trail (spec 8.10): its retained records oldest first, with its
 * deliveries. "Delivered more than once" and "delivered to a different program" (Rust compares
 * the origin program and its start time, spec 3.1) are text labels with the advisory sentence,
 * never colour alone. The records are text; each can be opened in the detail.
 */
export function Trail({ requestId, onOpen }: Props) {
  const t = useText();
  const [trail, setTrail] = useState<AuditTrail | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  // False until the read is asked for: the status region is in the page empty first, then filled.
  const [asked, setAsked] = useState(false);

  useEffect(() => {
    let live = true;
    setTrail(null);
    setFailed(null);
    setAsked(true);
    auditTrail(requestId).then(
      (t) => {
        if (live) setTrail(t);
      },
      (e: unknown) => {
        if (live) setFailed(failureText(e, t));
      },
    );
    return () => {
      live = false;
    };
  }, [requestId]);

  const marked = trail !== null && (trail.deliveries.count > 1 || trail.deliveries.to_other_peer);
  return (
    <section className="audit-trail" aria-label={t.audit.trail}>
      <h3>{t.audit.trail}</h3>
      <p role="status">{asked && trail === null && failed === null ? t.audit.trail_loading : null}</p>
      {failed === null ? null : <p role="alert">{failed}</p>}
      {trail === null ? null : (
        <>
          <p>
            <span>{t.audit.deliveries(trail.deliveries.count)}</span>{' '}
            {trail.deliveries.count > 1 ? <Badge label={t.audit.delivered_more_than_once} tone="caution" /> : null}
            {trail.deliveries.to_other_peer ? (
              <Badge label={t.audit.delivered_to_other_program} tone="caution" />
            ) : null}
          </p>
          {marked ? <p>{t.audit.deliveries_advisory}</p> : null}
          <ol>
            {trail.headers.map((h) => (
              <li key={h.seq}>
                <button type="button" onClick={() => onOpen(h)}>
                  {t.audit.open_record(h.seq)}
                </button>{' '}
                <Val value={h.ts_utc} time />{' '}
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
                    {t.audit.field.peer_origin_exe}: <Val value={h.peer_origin_exe} />
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
