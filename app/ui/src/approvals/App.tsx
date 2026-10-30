import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { Header } from '../shared/Header';
import {
  acknowledgeAttention,
  appStatus,
  queueList,
  recentList,
} from '../shared/ipc/invoke';
import { on } from '../shared/ipc/events';
import type { QueueItem, RecentItem, StatusLine } from '../shared/ipc/types';
import { Batch } from './Batch';
import { Detail, type DetailHandle } from './Detail';
import { useWindowInert, WindowInertContext } from './inert';
import { useChords } from './keyboard';
import { Queue, queueOrder } from './Queue';
import { Recent } from './Recent';
import { useText } from '../shared/i18n/context';

/**
 * Re-reads `load` on mount and on each of `events`. Event payloads are ids and counts only; the
 * window re-reads through the command rather than trusting a payload as the new state.
 */
function useReloaded<T>(
  load: () => Promise<T>,
  events: readonly string[],
): { value: T | null; failed: boolean; reload: () => void } {
  const [value, setValue] = useState<T | null>(null);
  const [failed, setFailed] = useState(false);
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  useEffect(() => {
    let live = true;
    // Only the newest read may write: an older read that resolves late is dropped.
    let latest = 0;
    const refresh = () => {
      const mine = ++latest;
      load().then(
        (v) => {
          if (live && mine === latest) {
            setValue(v);
            setFailed(false);
          }
        },
        () => {
          if (live && mine === latest) setFailed(true);
        },
      );
    };
    const unlistens = events.map((name) => on(name, refresh));
    // Read once the listeners are attached, so an event between a read and a listener is not lost.
    void Promise.allSettled(unlistens).then(() => {
      if (live) refresh();
    });
    return () => {
      live = false;
      for (const u of unlistens) void u.then((off) => off()).catch(() => undefined);
    };
  }, [load, events, nonce]);
  return { value, failed, reload };
}

const QUEUE_EVENTS = ['queue_changed'] as const;
const RECENT_EVENTS = ['queue_changed', 'recent_changed', 'needs_attention_changed'] as const;
const STATUS_EVENTS = ['status_banner', 'needs_attention_changed'] as const;

/**
 * The Approvals window. Auto-display of a new request renders the queue only: nothing here calls
 * `preview_fetch` (spec 5.6 "Opened"); a preview opens on explicit user navigation (a row's Open
 * button or the next/prev chord). The window owns the keyboard (`useChords`) and the focus inert
 * periods (`useWindowInert`); a decision never moves the selection (no auto-advance).
 */
export interface AppProps {
  /** Replaces the desktop header (server mode passes its own, PD-219). */
  header?: ReactNode;
  /** Opens this request once the queue holds it (the server's `?item=` deep link, SM-5.3). */
  openId?: string | null;
}

export function App({ header, openId = null }: AppProps = {}) {
  const t = useText();
  const queue = useReloaded<QueueItem[]>(queueList, QUEUE_EVENTS);
  const recent = useReloaded<RecentItem[]>(recentList, RECENT_EVENTS);
  const status = useReloaded<StatusLine[]>(appStatus, STATUS_EVENTS);
  const { reload: reloadRecent } = recent;
  const { reload: reloadStatus } = status;
  const acknowledge = useCallback(
    (ids: string[]) => {
      const done = () => {
        reloadRecent();
        reloadStatus();
      };
      void acknowledgeAttention(ids).then(done, done);
    },
    [reloadRecent, reloadStatus],
  );

  // The open action is the only thing that bumps `token`; a queue re-read never does.
  const [selected, setSelected] = useState<{ item: QueueItem; token: number } | null>(null);
  const tokens = useRef(0);
  const byId = useMemo(
    () => new Map((queue.value ?? []).map((i) => [i.request_id, i])),
    [queue.value],
  );
  const order = useMemo(() => queueOrder(queue.value ?? []), [queue.value]);
  const onOpen = useCallback(
    (id: string) => {
      const item = byId.get(id);
      if (item !== undefined) setSelected({ item, token: ++tokens.current });
    },
    [byId],
  );
  // A deep link opens its item once, the first time the queue holds it.
  const linked = useRef<string | null>(null);
  useEffect(() => {
    if (openId === null || linked.current === openId || !byId.has(openId)) return;
    linked.current = openId;
    onOpen(openId);
  }, [openId, byId, onOpen]);
  const current = selected === null ? undefined : byId.get(selected.item.request_id);
  // Keep the last known row of a request that left the queue (a decided item stays selected).
  const shownItem = current ?? selected?.item;

  // Next/prev is an explicit navigation: it opens the neighbour in the queue's display order,
  // which fetches its preview and starts its inert period (spec 5.6).
  const step = (delta: 1 | -1) => {
    if (order.length === 0) return;
    const at = selected === null ? -1 : order.indexOf(selected.item.request_id);
    const to = at === -1 ? (delta === 1 ? 0 : order.length - 1) : at + delta;
    const id = order[to];
    if (id !== undefined) onOpen(id);
  };

  const heading = useRef<HTMLHeadingElement>(null);
  const inert = useWindowInert(heading);
  const { ends } = inert;
  const allInertNow = useCallback(() => performance.now() < ends.current.all, [ends]);
  const detail = useRef<DetailHandle>(null);
  // A batch panel (its confirmation or reason field) or call in progress: the approve chord of the
  // open item must not fire from there (a chord typed in the reason field, a call in flight).
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const batchEngaged = useRef(false);
  const onBatchEngaged = useCallback((engaged: boolean) => {
    batchEngaged.current = engaged;
  }, []);
  // The open request whose card holds unsent edits or redactions; a batch must not decide it.
  const [unsentId, setUnsentId] = useState<string | null>(null);
  const onUnsentChange = useCallback((id: string, unsent: boolean) => {
    setUnsentId((cur) => (unsent ? id : cur === id ? null : cur));
  }, []);
  useChords(
    {
      approve: () => {
        if (!batchEngaged.current) detail.current?.approve();
      },
      deny: () => detail.current?.deny(),
      next: () => step(1),
      prev: () => step(-1),
    },
    allInertNow,
  );

  return (
    <WindowInertContext.Provider value={inert}>
      {header ?? <Header lines={status.value ?? []} />}
      <main id="main" tabIndex={-1} className="window window-approvals">
        <h1 ref={heading} tabIndex={-1}>
          {t.approvals.window_titles.approvals}
        </h1>
        {queue.failed ? <p role="alert">{t.approvals.queue.load_failed}</p> : null}
        {queue.value !== null ? (
          <Queue
            items={queue.value}
            onSelectionChange={setSelectedIds}
            onOpen={onOpen}
            selectedId={selected?.item.request_id ?? null}
          />
        ) : queue.failed ? null : (
          <p role="status">{t.approvals.queue.loading}</p>
        )}
        {queue.value !== null ? (
          <Batch
            items={queue.value}
            selectedIds={selectedIds}
            unsentId={unsentId}
            onEngagedChange={onBatchEngaged}
          />
        ) : null}
        {selected === null || shownItem === undefined ? (
          <p>{t.approvals.detail.select_prompt}</p>
        ) : (
          <Detail
            key={selected.item.request_id}
            ref={detail}
            item={shownItem}
            openToken={selected.token}
            gone={current === undefined}
            onUnsentChange={onUnsentChange}
          />
        )}
        {recent.failed ? <p role="alert">{t.approvals.recent.load_failed}</p> : null}
        {recent.value !== null ? (
          <Recent items={recent.value} onAcknowledge={acknowledge} />
        ) : recent.failed ? null : (
          <p role="status">{t.approvals.recent.loading}</p>
        )}
      </main>
    </WindowInertContext.Provider>
  );
}