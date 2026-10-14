import { useEffect, useMemo, useRef, useState } from 'react';

import { Windowed } from '../shared/list/Windowed';
import type { QueueItem } from '../shared/ipc/types';
import { CLASS_LABELS, QUEUE_TEXT } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { Badge } from '../shared/text/Badge';

/** A row is two one-line rows (2 rem each) and a flags line of up to two lines (3.5 rem), see app.css. */
export const QUEUE_ROW_REM = 7.5;

/** The row height in px at the current root font size, so OS font scaling grows rows with their lines. */
function rowHeightPx(): number {
  const root = parseFloat(getComputedStyle(document.documentElement).fontSize);
  return QUEUE_ROW_REM * (Number.isFinite(root) && root > 0 ? root : 16);
}

type Row =
  | { kind: 'group'; sessionId: string; label: string; unusual: boolean; ids: string[] }
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
        label: head.session_label,
        // `unusual` is about an agent's name or reason, not the label: a group may be flagged for
        // another member's text. That over-flags, which is harmless.
        unusual: members.some((i) => i.unusual),
        ids: members.map((i) => i.request_id),
      },
      ...sorted.map((item) => ({ kind: 'item' as const, item })),
    ];
  });
}

export function formatAge(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  return `${Math.floor(seconds / 3600)} h`;
}

interface QueueProps {
  items: readonly QueueItem[];
  /** Called with the selected request ids whenever the selection changes. */
  onSelectionChange?: (ids: string[]) => void;
}

export function Queue({ items, onSelectionChange }: QueueProps) {
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const rows = useMemo(() => buildRows(items), [items]);
  const byId = useMemo(() => new Map(items.map((i) => [i.request_id, i])), [items]);

  // An item that left the queue leaves the selection.
  useEffect(() => {
    setSelected((prev) => {
      const kept = [...prev].filter((id) => byId.has(id));
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
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    });

  if (items.length === 0) {
    return <p className="empty">{QUEUE_TEXT.empty}</p>;
  }

  return (
    <Windowed
      label={QUEUE_TEXT.heading}
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
      <span id={selectId}>{QUEUE_TEXT.select_session}</span>{' '}
      <span id={labelId}>
        <AgentText value={row.label} unusual={row.unusual} />
      </span>
    </div>
  );
}

function ItemRow({
  item,
  other,
  checked,
  onToggle,
}: {
  item: QueueItem;
  other: QueueItem | undefined;
  checked: boolean;
  onToggle: (on: boolean) => void;
}) {
  return (
    <div className="queue-item">
      <div className="queue-line">
        <input
          type="checkbox"
          aria-label={`${QUEUE_TEXT.select_item} ${item.op_id} ${item.target_display}`}
          checked={checked}
          onChange={(e) => onToggle(e.currentTarget.checked)}
        />
        <AgentText value={item.agent_name ?? QUEUE_TEXT.no_agent_name} unusual={item.unusual} />
        <span className="op-id">{item.op_id}</span>
        <span className="alias">{item.instance_alias}</span>
        <span className="target">{item.target_display}</span>
        <span className="class">{CLASS_LABELS[item.class] ?? item.class}</span>
      </div>
      <div className="queue-line">
        {item.reason_excerpt === null || item.reason_excerpt === '' ? (
          <Badge label={QUEUE_TEXT.no_reason} />
        ) : (
          <AgentText value={item.reason_excerpt} unusual={item.unusual} />
        )}
        <span className="age">{formatAge(item.age_s)}</span>
      </div>
      <div className="queue-line queue-flags">
        {item.stale ? <Badge label={QUEUE_TEXT.stale} tone="caution" /> : null}
        {item.caution_count > 0 ? (
          <Badge label={QUEUE_TEXT.caution} count={item.caution_count} tone="caution" />
        ) : null}
        {item.possible_duplicate_of === null ? null : (
          <span className="flag">
            <Badge label={QUEUE_TEXT.possible_duplicate} tone="caution" />{' '}
            <span className="flag-ref">{item.possible_duplicate_of}</span>
            {other === undefined ? null : (
              <>
                {' '}
                {QUEUE_TEXT.of_session} <AgentText value={other.session_label} unusual={other.unusual} />
              </>
            )}
          </span>
        )}
        {item.similar_to === null ? null : (
          <span className="flag">
            <Badge label={QUEUE_TEXT.similar_request} tone="caution" />{' '}
            <span className="flag-ref">{item.similar_to}</span>
          </span>
        )}
      </div>
    </div>
  );
}