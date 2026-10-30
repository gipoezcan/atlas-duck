import { useEffect, useMemo, useRef, useState } from 'react';

import { own } from '../shared/text/own';
import { Windowed } from '../shared/list/Windowed';
import type { QueueItem } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { Badge } from '../shared/text/Badge';
import { useText } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';
import type { Dict } from '../shared/i18n';

/** A row is two one-line rows (2 rem each) and a flags line of up to two lines (3.5 rem), see app.css. */
export const QUEUE_ROW_REM = 7.5;

/** The row height in px at the current root font size, so OS font scaling grows rows with their lines. */
function rowHeightPx(): number {
  const root = parseFloat(getComputedStyle(document.documentElement).fontSize);
  return QUEUE_ROW_REM * (Number.isFinite(root) && root > 0 ? root : 16);
}

type Row =
  | { kind: 'group'; sessionId: string; head: QueueItem; unusual: boolean; ids: string[] }
  | { kind: 'item'; item: QueueItem };

/**
 * Items grouped by session (spec 5.6). The core lists oldest first; a group keeps that order, and
 * a group holding a stale item (a stale return to review) is pinned above the others.
 */
export function buildRows(items: readonly QueueItem[]): Row[] {
  const groups = new Map<string, QueueItem[]>();
  for (const item of items) {
    const g = groups.get(item.session_id);
    if (g) g.push(item);
    else groups.set(item.session_id, [item]);
  }
  const ordered = [...groups.values()].sort(
    (a, b) => Number(b.some((i) => i.stale)) - Number(a.some((i) => i.stale)),
  );
  return ordered.flatMap((members) => {
    const [head] = members;
    if (head === undefined) return [];
    const sorted = [...members].sort((a, b) => Number(b.stale) - Number(a.stale));
    return [
      {
        kind: 'group' as const,
        sessionId: head.session_id,
        head,
        // `unusual` is about an agent's name or reason, not the label: a group may be flagged for
        // another member's text. That over-flags, which is harmless.
        unusual: members.some((i) => i.unusual),
        ids: members.map((i) => i.request_id),
      },
      ...sorted.map((item) => ({ kind: 'item' as const, item })),
    ];
  });
}

/** A session as the queue shows it: the agent's name (the UI's words when it sent none) and the cwd. */
export function sessionLabel(item: QueueItem, t: Dict = en): string {
  return `${item.session_agent_name ?? t.approvals.queue.no_agent_name} · ${item.session_cwd}`;
}

/** The request ids in the order the queue shows them (next/prev follows it). */
export function queueOrder(items: readonly QueueItem[]): string[] {
  return buildRows(items).flatMap((row) => (row.kind === 'item' ? [row.item.request_id] : []));
}

/** A row's candidate revision as one comparable string. */
function revKey(item: QueueItem): string {
  return `${item.candidate_rev.counter}:${item.candidate_rev.candidate_hash}`;
}

export function formatAge(seconds: number, t: Dict = en): string {
  return t.approvals.queue.age(seconds);
}

interface QueueProps {
  items: readonly QueueItem[];
  /** Called with the selected request ids whenever the selection changes. */
  onSelectionChange?: (ids: string[]) => void;
  /** The explicit open action of a row (spec 5.6 "Opened"): the only thing that may fetch a preview. */
  onOpen?: (requestId: string) => void;
  /** The row whose detail is shown. */
  selectedId?: string | null;
}

export function Queue({ items, onSelectionChange, onOpen, selectedId = null }: QueueProps) {
  const t = useText();
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const rows = useMemo(() => buildRows(items), [items]);
  const byId = useMemo(() => new Map(items.map((i) => [i.request_id, i])), [items]);

  // The revision each selected row had when it was ticked: batch decisions carry the revision the
  // user saw, so a row whose revision moved leaves the selection (it must be selected again).
  const tickedRev = useRef(new Map<string, string>());
  // An item that left the queue, or changed revision, leaves the selection.
  useEffect(() => {
    setSelected((prev) => {
      const kept = [...prev].filter((id) => {
        const item = byId.get(id);
        return item !== undefined && revKey(item) === tickedRev.current.get(id);
      });
      return kept.length === prev.size ? prev : new Set(kept);
    });
  }, [byId]);

  // The callback sits in a ref: an inline callback that sets parent state must not re-fire the
  // notification below on every render.
  const notify = useRef(onSelectionChange);
  useEffect(() => {
    notify.current = onSelectionChange;
  });
  useEffect(() => {
    notify.current?.([...selected]);
  }, [selected]);
  const rowHeight = useMemo(rowHeightPx, []);

  const toggle = (ids: readonly string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        const item = byId.get(id);
        if (on && item !== undefined) {
          next.add(id);
          tickedRev.current.set(id, revKey(item));
        } else {
          next.delete(id);
          tickedRev.current.delete(id);
        }
      }
      return next;
    });

  if (items.length === 0) {
    return <p className="empty empty-state">{t.approvals.queue.empty}</p>;
  }

  return (
    <Windowed
      label={t.approvals.queue.heading}
      rows={rows}
      rowHeight={rowHeight}
      rowKey={(row) => (row.kind === 'group' ? `group-${row.sessionId}` : row.item.request_id)}
      render={(row) =>
        row.kind === 'group' ? (
          <GroupRow
            row={row}
            checked={row.ids.every((id) => selected.has(id))}
            onToggle={(on) => toggle(row.ids, on)}
          />
        ) : (
          <ItemRow
            item={row.item}
            other={row.item.possible_duplicate_of === null ? undefined : byId.get(row.item.possible_duplicate_of)}
            checked={selected.has(row.item.request_id)}
            onToggle={(on) => toggle([row.item.request_id], on)}
            current={row.item.request_id === selectedId}
            onOpen={onOpen}
          />
        )
      }
    />
  );
}

function GroupRow({
  row,
  checked,
  onToggle,
}: {
  row: Extract<Row, { kind: 'group' }>;
  checked: boolean;
  onToggle: (on: boolean) => void;
}) {
  const t = useText();
  const labelId = `session-${row.sessionId}`;
  const selectId = `select-${labelId}`;
  return (
    <div className="queue-group">
      <input
        type="checkbox"
        aria-labelledby={`${selectId} ${labelId}`}
        checked={checked}
        onChange={(e) => onToggle(e.currentTarget.checked)}
      />
      <span id={selectId}>{t.approvals.queue.select_session}</span>{' '}
      <span id={labelId}>
        <AgentText value={sessionLabel(row.head, t)} unusual={row.unusual} />
      </span>
    </div>
  );
}

function ItemRow({
  item,
  other,
  checked,
  onToggle,
  current,
  onOpen,
}: {
  item: QueueItem;
  other: QueueItem | undefined;
  checked: boolean;
  onToggle: (on: boolean) => void;
  current: boolean;
  onOpen: ((requestId: string) => void) | undefined;
}) {
  const t = useText();
  return (
    <div className="queue-item" aria-current={current ? 'true' : undefined}>
      <input
        type="checkbox"
        aria-label={`${t.approvals.queue.select_item} ${item.op_id} ${item.target_display}`}
        checked={checked}
        onChange={(e) => onToggle(e.currentTarget.checked)}
      />
      <div className="queue-lines">
      <div className="queue-line">
        <span className="op-id">{item.op_id}</span>
        <span className="class">{own(t.approvals.class_labels, item.class) ?? item.class}</span>
        <span className="alias">{item.instance_alias}</span>
        <span className="target">{item.target_display}</span>
        <span className="age">{formatAge(item.age_s, t)}</span>
      </div>
      <div className="queue-line">
        <AgentText value={item.agent_name ?? t.approvals.queue.no_agent_name} unusual={item.unusual} />
        {item.reason_excerpt === null || item.reason_excerpt === '' ? (
          <Badge label={t.approvals.queue.no_reason} />
        ) : (
          <AgentText value={item.reason_excerpt} unusual={item.unusual} />
        )}
      </div>
      <div className="queue-line queue-flags">
        {item.stale ? <Badge label={t.approvals.queue.stale} tone="caution" /> : null}
        {item.caution_count > 0 ? (
          <Badge label={t.approvals.queue.caution} count={item.caution_count} tone="caution" />
        ) : null}
        {item.possible_duplicate_of === null ? null : (
          <span className="flag">
            <Badge label={t.approvals.queue.possible_duplicate} tone="caution" />{' '}
            <span className="flag-ref">{item.possible_duplicate_of}</span>
            {other === undefined ? null : (
              <>
                {' '}
                {t.approvals.queue.of_session} <AgentText value={sessionLabel(other, t)} unusual={other.unusual} />
              </>
            )}
          </span>
        )}
        {item.similar_to === null ? null : (
          <span className="flag">
            <Badge label={t.approvals.queue.similar_request} tone="caution" />{' '}
            <span className="flag-ref">{item.similar_to}</span>
          </span>
        )}
      </div>
      </div>
      {onOpen === undefined ? null : (
        <button
          type="button"
          className="queue-open"
          aria-label={`${t.approvals.queue.open} ${item.op_id} ${item.target_display}`}
          onClick={() => onOpen(item.request_id)}
        >
          {t.approvals.queue.open}
          <svg aria-hidden="true" focusable="false" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 6l6 6-6 6" />
          </svg>
        </button>
      )}
    </div>
  );
}
