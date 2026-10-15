import { useCallback, useEffect, useRef, useState } from 'react';

import {
  removalBackup,
  removalBegin,
  removalFinish,
  removalMark,
  removalState,
} from '../shared/ipc/invoke';
import type {
  RemovalChoice,
  RemovalFinishAnswer,
  RemovalItem,
  RemovalState,
} from '../shared/ipc/types';
import { SETTINGS_TEXT as T } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';
import { Cfg } from './text';
import { useAction } from './useAction';

/**
 * "Prepare for removal" (spec 12.5, PD-88): the page of Rust's step machine. Rust decides every
 * step and draws every confirmation itself; this page only shows `removal_state` and sends the
 * four answers (backup, delete the tokens, tick or skip an instance, finish). Nothing it sends is a
 * path, an origin or a token. The checklist is whatever Rust answered last: a refusal changes
 * nothing but the refusal text, then the page reads the state again, and the Finish button is only
 * a mirror of Rust's gate.
 * Every string is a fixed text or a text node (aliases from the config file, token identities from
 * the server through `AgentText`).
 */
export function Removal({ onChanged }: { onChanged: () => void }) {
  const action = useAction();
  const [state, setState] = useState<RemovalState | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [backup, setBackup] = useState<boolean | null>(null);
  const [finished, setFinished] = useState<RemovalFinishAnswer | null>(null);
  const live = useRef(true);

  const load = useCallback(() => {
    removalState().then(
      (s) => {
        if (live.current) {
          setState(s);
          setLoadFailed(false);
        }
      },
      () => {
        if (live.current) setLoadFailed(true);
      },
    );
  }, []);

  useEffect(() => {
    live.current = true;
    load();
    return () => {
      live.current = false;
    };
  }, [load]);

  const take = (next: RemovalState | undefined) => {
    if (next === undefined) return;
    setState(next);
    onChanged();
  };

  if (state === null) {
    return (
      <section aria-label={T.removal}>
        <h2>{T.removal}</h2>
        {loadFailed ? (
          <p role="alert">
            {T.load_failed}{' '}
            <button type="button" onClick={load}>
              {T.retry}
            </button>
          </p>
        ) : (
          <p role="status">{T.loading}</p>
        )}
      </section>
    );
  }

  const unanswered = state.instances.some((i) => !i.token_deleted || i.choice === 'pending');
  const undeleted = state.instances.some((i) => !i.token_deleted);

  const doBackup = () =>
    void action.run(() => removalBackup()).then((a) => {
      if (a !== undefined) setBackup(a.saved);
      load();
    });
  // A refusal or a failure (`undefined`) says Rust's state may differ from the page's (a token
  // stored again, a recorded procedure, a tick taken back): read it again, so the ticks, the retry
  // button and Finish show what Rust holds. The refusal text stays.
  const doBegin = () =>
    void action.run(() => removalBegin()).then((next) => (next === undefined ? load() : take(next)));
  const doMark = (alias: string, choice: RemovalChoice) =>
    void action
      .run(() => removalMark(alias, choice))
      .then((next) => (next === undefined ? load() : take(next)));
  const doFinish = () =>
    void action.run(() => removalFinish()).then((answer) => {
      if (answer === undefined) {
        load();
        return;
      }
      setFinished(answer);
      onChanged();
      load();
    });

  return (
    <section aria-label={T.removal}>
      <h2>{T.removal}</h2>
      {finished === null ? null : (
        <div role="status">
          <p>{T.removal_autostart[finished.autostart]}</p>
          <p>{T.removal_cli[finished.cli]}</p>
          {finished.cli_reason === null ? null : (
            <p>
              {T.removal_cli_reasons[finished.cli_reason] ?? T.removal_cli_reasons['other']}
            </p>
          )}
          <p>{finished.cli === 'not_removed' ? T.removal_incomplete : T.removal_complete}</p>
        </div>
      )}
      {finished !== null ? null : (
        <>
          <p>{T.removal_intro}</p>
          <p>{T.removal_retention(state.retention_days, state.legal_hold)}</p>
          <p>{T.removal_backup_note}</p>
          <button type="button" disabled={action.pending} onClick={doBackup}>
            {T.removal_backup}
          </button>
          {backup === null ? null : (
            <p role="status">{backup ? T.removal_backup_saved : T.removal_backup_cancelled}</p>
          )}
          {state.backup_made && backup === null ? <p>{T.removal_backup_made}</p> : null}
          {state.active ? null : (
            <p>
              <button type="button" disabled={action.pending} onClick={doBegin}>
                {T.removal_begin}
              </button>
            </p>
          )}
          {state.active ? (
            <>
              <h3>{T.removal_checklist}</h3>
              <ul>
                {state.instances.map((item) => (
                  <Item key={item.alias} item={item} pending={action.pending} onMark={doMark} />
                ))}
              </ul>
              {undeleted ? (
                <p>
                  <button type="button" disabled={action.pending} onClick={doBegin}>
                    {T.removal_retry}
                  </button>
                </p>
              ) : null}
              <p>{T.removal_finish_hint}</p>
              <button type="button" disabled={action.pending || unanswered} onClick={doFinish}>
                {T.removal_finish}
              </button>
            </>
          ) : null}
        </>
      )}
      {action.error === null ? null : <p role="alert">{action.error}</p>}
    </section>
  );
}

function Item({
  item,
  pending,
  onMark,
}: {
  item: RemovalItem;
  pending: boolean;
  onMark: (alias: string, choice: RemovalChoice) => void;
}) {
  const choiceText =
    item.choice === 'done'
      ? T.removal_choice_done
      : item.choice === 'skipped'
        ? T.removal_choice_skipped
        : T.removal_choice_pending;
  return (
    <li>
      <p>{T.removal_revoke_step}</p>
      <p>
        {T.removal_alias}: <Cfg value={item.alias} /> ({T.product[item.product]}
        {item.origin === null ? null : (
          <>
            , <Cfg value={item.origin} />
          </>
        )}
        )
      </p>
      <p>
        {T.removal_identity}:{' '}
        {item.identity === null ? (
          T.removal_identity_unknown
        ) : (
          <AgentText value={item.identity} unusual={unusual(item.identity)} />
        )}
      </p>
      {item.token_deleted ? (
        <>
          <button
            type="button"
            aria-pressed={item.choice === 'done'}
            disabled={pending}
            onClick={() => onMark(item.alias, 'done')}
          >
            {T.removal_done}
          </button>{' '}
          <button
            type="button"
            aria-pressed={item.choice === 'skipped'}
            disabled={pending}
            onClick={() => onMark(item.alias, 'skipped')}
          >
            {T.removal_skip}
          </button>{' '}
          {item.choice === 'pending' ? null : (
            <button type="button" disabled={pending} onClick={() => onMark(item.alias, 'pending')}>
              {T.removal_undo}
            </button>
          )}
          <p role="status">{choiceText}</p>
        </>
      ) : (
        <p role="alert">{item.error === null ? T.removal_token_back : T.removal_not_deleted}</p>
      )}
    </li>
  );
}
