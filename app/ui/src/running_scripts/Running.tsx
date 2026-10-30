import { useCallback, useEffect, useRef, useState } from 'react';
import { HelpButton } from '../shared/HelpLink';
import { useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';
import { useLang } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';
import { formatBytes, formatTimestamp } from '../shared/i18n/format';

import { on } from '../shared/ipc/events';
import { runningKill, runningList } from '../shared/ipc/invoke';
import type { KillAnswer, RunningScriptView } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';

type Notice = KillAnswer['answer'] | 'kill_failed';

/** Elapsed time as text, from Rust's whole milliseconds (formatting only, nothing is computed). */
function elapsedText(ms: number, t: Dict = en): string {
  const total = Math.floor(ms / 1000);
  if (total < 60) return t.running.elapsed.seconds(total);
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return t.running.elapsed.minutes(minutes, total % 60);
  return t.running.elapsed.hours(Math.floor(minutes / 60), minutes % 60);
}

/**
 * The Running scripts window (spec 9.6, PD-81, PD-142, PD-143): the live list and one kill button
 * per run. Columns: request, agent, instances, started, elapsed, host calls, bytes fetched. It
 * reads `running_list` on mount, on every `running_scripts_changed` (never trusting an event
 * payload as state; the latest read wins) and once per second while the window is visible; the
 * values are Rust's, only their text form is made here. The kill asks Rust, which asks the run's
 * worker to die; the run's own audited path then records it and turns the request into an item to
 * review, so the row is not removed here: the next read says whether the run is gone. The answer
 * is one of three texts. One kill at a time: every button is off while one is in flight and a
 * second click in the same tick is dropped. The agent's name is agent text (`AgentText`: the
 * "unverified" badge, then the name bidi-isolated); the request id, aliases and times are text
 * nodes.
 */
export function Running() {
  const t = useText();
  const lang = useLang();
  const [rows, setRows] = useState<RunningScriptView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [killing, setKilling] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [nonce, setNonce] = useState(0);
  const listing = useRef(false);
  const again = useRef(false);
  const inFlight = useRef(false);
  const live = useRef(true);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  // One list in flight at most (a stalled backend must not pile up calls). A trigger that arrives
  // meanwhile schedules exactly one trailing read after the running one settles, so the last
  // read always started after the last trigger and its result is the one shown.
  const refresh = useCallback(() => {
    if (listing.current) {
      again.current = true;
      return;
    }
    const start = () => {
      listing.current = true;
      const settle = () => {
        listing.current = false;
        const rerun = again.current;
        again.current = false;
        if (rerun && live.current) start();
      };
      runningList().then(
        (list) => {
          if (live.current) {
            setRows(list);
            setFailed(false);
          }
          settle();
        },
        () => {
          if (live.current) setFailed(true);
          settle();
        },
      );
    };
    start();
  }, []);

  useEffect(() => {
    live.current = true;
    const unlisten = on('running_scripts_changed', refresh, { thisWindow: true });
    // Read once the listener is attached, so an event between a read and a listener is not lost.
    void Promise.allSettled([unlisten]).then(() => {
      if (live.current) refresh();
    });
    return () => {
      live.current = false;
      void unlisten.then((off) => off()).catch(() => undefined);
    };
  }, [refresh, nonce]);

  // The once-a-second read, only while the window is visible, and one read when it becomes visible.
  useEffect(() => {
    const tick = () => {
      if (document.visibilityState === 'visible') refresh();
    };
    const timer = setInterval(tick, 1000);
    document.addEventListener('visibilitychange', tick);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [refresh]);

  const kill = (requestId: string) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setKilling(requestId);
    setNotice(null);
    runningKill(requestId).then(
      (answer) => {
        inFlight.current = false;
        if (!live.current) return;
        setKilling(null);
        setNotice(answer.answer);
        refresh();
      },
      () => {
        inFlight.current = false;
        if (!live.current) return;
        setKilling(null);
        setNotice('kill_failed');
        refresh();
      },
    );
  };

  if (rows === null) {
    return (
      <main className="window window-running">
        <h1>{t.approvals.window_titles.running_scripts}</h1>
        <HelpButton window="running_scripts" />
        {failed ? (
          <p role="alert">
            {t.running.load_failed}{' '}
            <button type="button" onClick={reload}>
              {t.running.retry}
            </button>
          </p>
        ) : (
          <p role="status">{t.running.loading}</p>
        )}
      </main>
    );
  }

  return (
    <main className="window window-running">
      <h1>{t.approvals.window_titles.running_scripts}</h1>
      <HelpButton window="running_scripts" />
      {failed ? (
        <p role="alert">
          {t.running.load_failed}{' '}
          <button type="button" onClick={reload}>
            {t.running.retry}
          </button>
        </p>
      ) : null}
      {notice === null ? null : (
        <p role={notice === 'kill_failed' ? 'alert' : 'status'}>
          {notice === 'kill_failed' ? t.running.kill_failed : t.running.kill_answer[notice]}
        </p>
      )}
      {rows.length === 0 ? (
        <p className="empty-state">{t.running.empty}</p>
      ) : (
        <div className="table-scroll">
<table aria-label={t.running.list_label}>
          <thead>
            <tr>
              <th scope="col">{t.running.col_request}</th>
              <th scope="col">{t.running.col_agent}</th>
              <th scope="col">{t.running.col_instances}</th>
              <th scope="col">{t.running.col_started}</th>
              <th scope="col">{t.running.col_elapsed}</th>
              <th scope="col">{t.running.col_calls}</th>
              <th scope="col">{t.running.col_bytes}</th>
              <th scope="col">
                <span className="visually-hidden">{t.running.col_actions}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.request_id}>
                <td>
                  <code>{r.request_id}</code>
                </td>
                <td>
                  {r.agent_name === null ? (
                    t.running.no_agent
                  ) : (
                    <AgentText value={r.agent_name} unusual={unusual(r.agent_name)} />
                  )}
                </td>
                <td>{r.instances.length === 0 ? t.running.no_instances : r.instances.join(', ')}</td>
                <td>{formatTimestamp(lang, r.started_at)}</td>
                <td>{elapsedText(r.elapsed_ms, t)}</td>
                <td>{r.host_calls}</td>
                <td>{formatBytes(lang, r.bytes_fetched, { table: true })}</td>
                <td>
                  <button
                    type="button"
                    className="danger"
                    aria-label={t.running.kill_label(r.request_id)}
                    disabled={killing !== null}
                    aria-busy={killing === r.request_id}
                    onClick={() => kill(r.request_id)}
                  >
                    {killing === r.request_id ? t.running.killing : t.running.kill}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
</div>
      )}
    </main>
  );
}
