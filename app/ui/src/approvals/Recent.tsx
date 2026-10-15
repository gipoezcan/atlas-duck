import type { RecentItem } from '../shared/ipc/types';
import { own } from '../shared/text/own';
import { CLASS_LABELS, RECENT_TEXT, STATUS_LABELS } from '../shared/strings';
import { Badge } from '../shared/text/Badge';

/** "2026-10-14T09:30:00.000Z" as "2026-10-14 09:30 UTC": no locale, so it reads the same everywhere. */
export function formatDecidedAt(rfc3339: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(rfc3339);
  return m ? `${m[1]} ${m[2]} UTC` : rfc3339;
}

interface RecentProps {
  items: readonly RecentItem[];
  onAcknowledge: (requestIds: string[]) => void;
}

/**
 * "Recently decided (24 h) / Needs attention" (spec 5.6). Unacknowledged post-approval failures
 * and unknown outcomes are pinned above the rest until acknowledged.
 */
export function Recent({ items, onAcknowledge }: RecentProps) {
  const pinned = items.filter((i) => i.needs_attention && !i.acknowledged);
  const rest = items.filter((i) => !(i.needs_attention && !i.acknowledged));
  return (
    <section className="recent" aria-label={RECENT_TEXT.heading}>
      {pinned.length > 0 ? (
        <section aria-label={RECENT_TEXT.needs_attention}>
          <h2>
            {RECENT_TEXT.needs_attention} ({pinned.length})
          </h2>
          <button type="button" onClick={() => onAcknowledge(pinned.map((i) => i.request_id))}>
            {RECENT_TEXT.acknowledge_all}
          </button>
          <ul>
            {pinned.map((i) => (
              <RecentRow key={i.request_id} item={i} onAcknowledge={onAcknowledge} />
            ))}
          </ul>
        </section>
      ) : null}
      <h2>{RECENT_TEXT.heading}</h2>
      {rest.length === 0 ? (
        <p className="empty">{RECENT_TEXT.empty}</p>
      ) : (
        <ul>
          {rest.map((i) => (
            <RecentRow key={i.request_id} item={i} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RecentRow({
  item,
  onAcknowledge,
}: {
  item: RecentItem;
  onAcknowledge?: (requestIds: string[]) => void;
}) {
  return (
    <li className="recent-item">
      <span className="op-id">{item.op_id}</span>
      <span className="alias">{item.instance_alias}</span>
      <span className="target">{item.target_display}</span>
      <span className="class">{own(CLASS_LABELS, item.class) ?? item.class}</span>
      <Badge
        label={own(STATUS_LABELS, item.status) ?? item.status}
        tone={item.needs_attention ? 'caution' : 'neutral'}
      />
      {item.status === 'outcome_unknown' ? <Badge label={RECENT_TEXT.check_target} tone="caution" /> : null}
      <time dateTime={item.decided_at}>{formatDecidedAt(item.decided_at)}</time>
      {item.error_text === null ? null : <bdi className="error-text">{item.error_text}</bdi>}
      {onAcknowledge ? (
        <button type="button" onClick={() => onAcknowledge([item.request_id])}>
          {RECENT_TEXT.acknowledge}
        </button>
      ) : null}
    </li>
  );
}