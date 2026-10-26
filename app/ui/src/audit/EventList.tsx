import { useCallback, useEffect, useRef, useState } from 'react';

import { auditQuery } from '../shared/ipc/invoke';
import type { AuditCursor, AuditFilter, EventHeader } from '../shared/ipc/types';
import { Windowed } from '../shared/list/Windowed';
import { AUDIT_TEXT as T } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { Badge } from '../shared/text/Badge';
import { own } from '../shared/text/own';
import { unusual } from '../shared/text/unusual';
import { errorText, Val } from './text';

/**
 * Calls one "Load more" (or the first read) makes at most while the pages come back empty. Each
 * call examines at most the store's row budget (20 000 rows, `QUERY_ROW_BUDGET`), so a filter that
 * matches little needs many: the list goes on only when asked, never in an unbounded loop.
 */
export const FOLLOW_LIMIT = 10;

/** A row is two one-line rows (2 rem each), see app.css. */
const ROW_REM = 4.25;

function rowHeightPx(): number {
  const root = parseFloat(getComputedStyle(document.documentElement).fontSize);
  return ROW_REM * (Number.isFinite(root) && root > 0 ? root : 16);
}

interface Props {
  filter: AuditFilter;
  /** The seq of the record shown in the detail, marked in the list. */
  selected: number | null;
  onOpen: (header: EventHeader) => void;
}

/**
 * The Audit window's list (spec 8.10, PD-74 `Windowed`): matching records newest first, read a
 * page at a time with `audit_query`. Rust's `next` is followed until it is null, also over an
 * empty page (the store's row budget ended that call's scan, not the log), and sent back exactly
 * as it came. The parent remounts the list for a new filter. Every column is a text node; the
 * agent's name sits behind the "unverified" badge; flags are text labels.
 */
export function EventList({ filter, selected, onOpen }: Props) {
  const [rows, setRows] = useState<EventHeader[]>([]);
  const [next, setNext] = useState<AuditCursor | null>(null);
  const [examined, setExamined] = useState(0);
  const [started, setStarted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = useRef(true);
  const inFlight = useRef(false);
  const cursor = useRef<AuditCursor | null>(null);
  const [rowHeight] = useState(rowHeightPx);

  const load = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    setError(null);
    try {
      for (let call = 0; call < FOLLOW_LIMIT; call++) {
        const at = cursor.current;
        const page = await (at === null ? auditQuery(filter) : auditQuery(filter, at));
        if (!live.current) return;
        cursor.current = page.next;
        setStarted(true);
        setRows((r) => (page.rows.length === 0 ? r : [...r, ...page.rows]));
        setNext(page.next);
        setExamined((n) => n + page.scanned);
        if (page.rows.length > 0 || page.next === null) break;
      }
    } catch (e) {
      if (live.current) setError(errorText(e));
    } finally {
      inFlight.current = false;
      if (live.current) setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    live.current = true;
    void load();
    return () => {
      live.current = false;
    };
  }, [load]);

  const more = () => {
    void load();
  };

  const nothing = started && rows.length === 0 && next === null;
  return (
    <div className="audit-list">
      <p role="status">
        {started ? (
          <>
            <span>{T.list_summary(rows.length, examined)}</span>
            {next === null ? (
              <>
                {' '}
                <span>{T.list_end}</span>
              </>
            ) : null}
          </>
        ) : null}
      </p>
      {loading && !started ? <p>{T.list_loading}</p> : null}
      {error === null ? null : (
        <p role="alert">
          {T.list_failed}: {error}
        </p>
      )}
      {nothing ? <p className="empty-state">{T.list_empty}</p> : null}
      {rows.length === 0 ? null : (
        <Windowed
          label={T.list_label}
          rows={rows}
          rowHeight={rowHeight}
          height={Math.min(480, rows.length * rowHeight)}
          rowKey={(row) => row.seq}
          render={(row) => <Row header={row} current={row.seq === selected} onOpen={onOpen} />}
        />
      )}
      {next !== null && started && rows.length === 0 && !loading && error === null ? (
        <p>{T.list_partial}</p>
      ) : null}
      {/* More to read, or a first read that failed and can be tried again. */}
      {next !== null || (error !== null && !started) ? (
        <button type="button" disabled={loading} onClick={more}>
          {T.list_more}
        </button>
      ) : null}
    </div>
  );
}

/** The flags of a record as text labels (the 8.2 names are closed; `own` keeps it so). */
export function Flags({ flags }: { flags: readonly string[] }) {
  return (
    <>
      {flags.map((f) => (
        <Badge key={f} label={own(T.flag_labels, f) ?? T.unknown_name} tone={f === 'integrity_incident' ? 'caution' : 'neutral'} />
      ))}
    </>
  );
}

function Row({
  header: h,
  current,
  onOpen,
}: {
  header: EventHeader;
  current: boolean;
  onOpen: (header: EventHeader) => void;
}) {
  return (
    <div className="audit-row">
      <div className="audit-line">
        <button type="button" aria-current={current ? 'true' : undefined} onClick={() => onOpen(h)}>
          {T.open_record(h.seq)}
        </button>
        {/* The flags come first: a narrow row cuts the end of its line, and a caution flag must stay in view. */}
        <Flags flags={h.flags} />
        <span>
          <Val value={h.ts_utc} />
        </span>
        <code>
          <Val value={h.event_type} />
        </code>
        {h.decision === null ? null : (
          <span>
            <Val value={h.decision} />
          </span>
        )}
      </div>
      <div className="audit-line">
        {h.op_id === null ? null : (
          <code>
            <Val value={h.op_id} />
          </code>
        )}
        {h.target === null ? null : (
          <span className="target">
            <Val value={h.target} />
          </span>
        )}
        {h.agent_name === null ? null : <AgentText value={h.agent_name} unusual={unusual(h.agent_name)} />}
      </div>
    </div>
  );
}
