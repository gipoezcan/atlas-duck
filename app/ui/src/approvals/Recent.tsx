import type { RecentItem } from '../shared/ipc/types';
import { own } from '../shared/text/own';
import { Badge } from '../shared/text/Badge';
import { useLang, useText } from '../shared/i18n/context';
import { formatTimestamp } from '../shared/i18n/format';

interface RecentProps {
  items: readonly RecentItem[];
  onAcknowledge: (requestIds: string[]) => void;
}

/**
 * "Recently decided (24 h) / Needs attention" (spec 5.6). Unacknowledged post-approval failures
 * and unknown outcomes are pinned above the rest until acknowledged.
 */
export function Recent({ items, onAcknowledge }: RecentProps) {
  const t = useText();
  const pinned = items.filter((i) => i.needs_attention && !i.acknowledged);
  const rest = items.filter((i) => !(i.needs_attention && !i.acknowledged));
  return (
    <section className="recent" aria-label={t.approvals.recent.heading}>
      {pinned.length > 0 ? (
        <section aria-label={t.approvals.recent.needs_attention}>
          <h2>
            {t.approvals.recent.needs_attention} ({pinned.length})
          </h2>
          <button type="button" onClick={() => onAcknowledge(pinned.map((i) => i.request_id))}>
            {t.approvals.recent.acknowledge_all}
          </button>
          <ul>
            {pinned.map((i) => (
              <RecentRow key={i.request_id} item={i} onAcknowledge={onAcknowledge} />
            ))}
          </ul>
        </section>
      ) : null}
      <h2>{t.approvals.recent.heading}</h2>
      {rest.length === 0 ? (
        <p className="empty empty-state">{t.approvals.recent.empty}</p>
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
  const t = useText();
  const lang = useLang();
  return (
    <li className="recent-item">
      <span className="op-id">{item.op_id}</span>
      <span className="alias">{item.instance_alias}</span>
      <span className="target">{item.target_display}</span>
      <span className="class">{own(t.approvals.class_labels, item.class) ?? item.class}</span>
      <Badge
        label={own(t.approvals.status_labels, item.status) ?? item.status}
        tone={item.needs_attention ? 'caution' : 'neutral'}
      />
      {item.status === 'outcome_unknown' ? <Badge label={t.approvals.recent.check_target} tone="caution" /> : null}
      <time dateTime={item.decided_at}>{formatTimestamp(lang, item.decided_at)}</time>
      {item.error_text === null ? null : <bdi className="error-text">{item.error_text}</bdi>}
      {onAcknowledge ? (
        <button type="button" onClick={() => onAcknowledge([item.request_id])}>
          {t.approvals.recent.acknowledge}
        </button>
      ) : null}
    </li>
  );
}