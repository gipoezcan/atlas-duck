import { useEffect, useMemo, useRef, useState } from 'react';

import { App } from '../../approvals/App';
import { useText } from '../../shared/i18n/context';
import { on } from '../../shared/ipc/events';
import { queueList } from '../../shared/ipc/invoke';
import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { browserEnv, Notifier, type NotifyEnv } from './notify';

/** "Enable notifications": asks only from this click (PD-207). */
function NotifyButton({ env }: { env: NotifyEnv }) {
  const t = useText();
  const [perm, setPerm] = useState(env.permission());
  if (perm === 'unsupported') return null;
  if (perm === 'granted') return <p role="status">{t.server.approvals.enabled}</p>;
  if (perm === 'denied') return <p role="status">{t.server.approvals.denied}</p>;
  return (
    <button type="button" onClick={() => void env.request().then(setPerm, () => undefined)}>
      {t.server.approvals.enable}
    </button>
  );
}

function Page({ item, env }: { item: string | null; env: NotifyEnv }) {
  const t = useText();
  const [openId, setOpenId] = useState<string | null>(item);
  // The title is read at the moment of a notification, so a language switch applies to the next one.
  const title = useRef(t.server.notify.title);
  title.current = t.server.notify.title;
  const notifier = useMemo(() => new Notifier(env, setOpenId, () => title.current), [env]);
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
          <div className="server-notify">
            <NotifyButton env={env} />
          </div>
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
