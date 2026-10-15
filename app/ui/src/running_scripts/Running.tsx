import { useCallback, useEffect, useRef, useState } from 'react';

import { on } from '../shared/ipc/events';
import { runningKill, runningList } from '../shared/ipc/invoke';
import type { RunningScriptView } from '../shared/ipc/types';
import { RUNNING_TEXT as T, WINDOW_TITLES } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';

type Notice = 'stop_requested' | 'already_ended' | 'kill_failed';

/**
 * The Running scripts window's M6 shell (spec 9.6, PD-81): the live list and one kill button per
 * run. It reads `running_list` on mount and on every `running_scripts_changed` (never trusting an
 * event payload as state; the latest read wins). The kill asks Rust, which asks the run's worker to
 * die; the run's own audited path then records it and turns the request into an item to review,
 * so the row is not removed here: the next read says whether the run is gone. One kill at a time:
 * every button is off while one is in flight and a second click in the same tick is dropped.
 * The agent's name is agent text (`AgentText`); the request id and the times are text nodes.
 * Columns and the rest of X-11 are M8's.
 */
export function Running() {
  const [rows, setRows] = useState<RunningScriptView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [killing, setKilling] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [nonce, setNonce] = useState(0);
  const latest = useRef(0);
  const inFlight = useRef(false);
  const live = useRef(true);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  const refresh = useCallback(() => {
    const mine = ++latest.current;
    runningList().then(
      (list) => {
        if (live.current && mine === latest.current) {
          setRows(list);
          setFailed(false);
        }
      },
      () => {
        if (live.current && mine === latest.current) setFailed(true);
      },
    );
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
        setNotice(answer.killed ? 'stop_requested' : 'already_ended');
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
      <main>
        <h1>{WINDOW_TITLES.running_scripts}</h1>
        {failed ? (
          <p role="alert">
            {T.load_failed}{' '}
            <button type="button" onClick={reload}>
              {T.retry}
            </button>
          </p>
        ) : (
          <p role="status">{T.loading}</p>
        )}
      </main>
    );
  }

  return (
    <main>
      <h1>{WINDOW_TITLES.running_scripts}</h1>
      {failed ? (
        <p role="alert">
          {T.load_failed}{' '}
          <button type="button" onClick={reload}>
            {T.retry}
          </button>
        </p>
      ) : null}
      {notice === null ? null : (
        <p role={notice === 'kill_failed' ? 'alert' : 'status'}>{T[notice]}</p>
      )}
      {rows.length === 0 ? (
        <p>{T.empty}</p>
      ) : (
        <table aria-label={T.list_label}>
          <thead>
            <tr>
              <th scope="col">{T.col_request}</th>
              <th scope="col">{T.col_agent}</th>
              <th scope="col">{T.col_started}</th>
              <th scope="col">{T.col_calls}</th>
              <th scope="col">
                <span className="visually-hidden">{T.col_actions}</span>
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
                    T.no_agent
                  ) : (
                    <AgentText value={r.agent_name} unusual={unusual(r.agent_name)} />
                  )}
                </td>
                <td>{r.started_at}</td>
                <td>{r.host_calls}</td>
                <td>
                  <button
                    type="button"
                    aria-label={T.kill_label(r.request_id)}
                    disabled={killing !== null}
                    aria-busy={killing === r.request_id}
                    onClick={() => kill(r.request_id)}
                  >
                    {killing === r.request_id ? T.killing : T.kill}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
