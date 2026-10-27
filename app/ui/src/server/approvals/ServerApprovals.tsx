import { useEffect, useMemo, useState } from 'react';

import { App } from '../../approvals/App';
import { on } from '../../shared/ipc/events';
import { queueList } from '../../shared/ipc/invoke';
import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { browserEnv, NOTIFY_TEXT, Notifier, type NotifyEnv } from './notify';

/** "Enable notifications": asks only from this click (PD-207). */
function NotifyButton({ env }: { env: NotifyEnv }) {
  const [perm, setPerm] = useState(env.permission());
  if (perm === 'unsupported') return null;
  if (perm === 'granted') return <p role="status">{NOTIFY_TEXT.enabled}</p>;
  if (perm === 'denied') return <p role="status">{NOTIFY_TEXT.denied}</p>;
  return (
    <button type="button" onClick={() => void env.request().then(setPerm, () => undefined)}>
      {NOTIFY_TEXT.enable}
    </button>
  );
}

function Page({ item, env }: { item: string | null; env: NotifyEnv }) {
  const [openId, setOpenId] = useState<string | null>(item);
  const notifier = useMemo(() => new Notifier(env, setOpenId), [env]);
  useEffect(() => {
    let live = true;
    const reload = () => {
      void queueList().then(
        (q) => {
          if (live) notifier.queue(q);
        },
        () => undefined,
      );
    };
    reload();
    const off = on('queue_changed', reload);
    return () => {
      live = false;
      void off.then((f) => f());
    };
  }, [notifier]);
  return (
    <App
      openId={openId}
      header={
        <>
          <ServerHeader />
          <NotifyButton env={env} />
        </>
      }
    />
  );
}

/**
 * The server approvals page (PD-219, SM-5.2, SM-5.3): the desktop approvals UI with the server
 * header, `?item=<id>` opening that request once it is queued, and browser notifications for new
 * requests while the tab is hidden (a click focuses the tab and opens the request).
 */
export function ServerApprovals({ item, env = browserEnv }: { item: string | null; env?: NotifyEnv }) {
  return (
    <RequireSession>
      <Page item={item} env={env} />
    </RequireSession>
  );
}
