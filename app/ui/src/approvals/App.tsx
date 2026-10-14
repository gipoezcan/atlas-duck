import { useCallback, useEffect, useState } from 'react';

import { Header } from '../shared/Header';
import {
  acknowledgeAttention,
  appStatus,
  queueList,
  recentList,
} from '../shared/ipc/invoke';
import { on } from '../shared/ipc/events';
import type { QueueItem, RecentItem, StatusLine } from '../shared/ipc/types';
import { QUEUE_TEXT, RECENT_TEXT, WINDOW_TITLES } from '../shared/strings';
import { Queue } from './Queue';
import { Recent } from './Recent';

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
    const refresh = () => {
      load().then(
        (v) => {
          if (live) {
            setValue(v);
            setFailed(false);
          }
        },
        () => {
          if (live) setFailed(true);
        },
      );
    };
    refresh();
    const unlistens = events.map((name) => on(name, refresh));
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
 * `preview_fetch` (spec 5.6 "Opened"); a preview opens on explicit user navigation (Task 14).
 */
export function App() {
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

  return (
    <>
      <Header lines={status.value ?? []} />
      <main>
        <h1>{WINDOW_TITLES.approvals}</h1>
        {queue.failed ? <p role="alert">{QUEUE_TEXT.load_failed}</p> : null}
        <Queue items={queue.value ?? []} />
        {recent.failed ? <p role="alert">{RECENT_TEXT.load_failed}</p> : null}
        <Recent items={recent.value ?? []} onAcknowledge={acknowledge} />
      </main>
    </>
  );
}