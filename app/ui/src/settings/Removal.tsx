import { useCallback, useEffect, useRef, useState } from 'react';
import { useText } from '../shared/i18n/context';

import { Announce, exportRefusal, exportResult, type Said, say } from '../audit/text';
import {
  exportCancel,
  removalBackup,
  removalBegin,
  removalExport,
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
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';
import { Cfg, errorText, own } from './text';
import { useAction } from './useAction';
import { running, useAuditJob } from './useAuditJob';

/**
 * "Prepare for removal" (spec 12.5, PD-88, PD-176): the page of Rust's step machine. Rust decides
 * every step and draws every confirmation and folder dialog itself; this page only shows
 * `removal_state` and sends the answers (backup, export, delete the tokens, tick or skip an
 * instance, finish). Nothing it sends is a path, an origin or a token. The checklist is whatever
 * Rust answered last: a refusal changes nothing but the refusal text, then the page reads the state
 * again, and the Finish button is only a mirror of Rust's gate. A procedure whose answers are
 * recorded (`recorded`, also after a restart) is final: the answers can no longer be changed and
 * it ends only with Finish.
 * What a command answered is said in one polite live region that is in the page before the first
 * result (an inserted region is not announced); a refusal is an alert. Every string is a fixed text
 * or a text node (aliases from the config file, token identities from the server through
 * `AgentText`).
 */
export function Removal({ onChanged }: { onChanged: () => void }) {
  const t = useText();
  const action = useAction();
  const job = useAuditJob();
  const [state, setState] = useState<RemovalState | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [backup, setBackup] = useState<boolean | null>(null);
  const [finished, setFinished] = useState<RemovalFinishAnswer | null>(null);
  const [said, setSaid] = useState<Said | null>(null);
  const [exporting, setExporting] = useState(false);
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
      <section id="settings-removal" aria-label={t.settings.removal}>
        <h2 tabIndex={-1}>{t.settings.removal}</h2>
        {loadFailed ? (
          <p role="alert">
            {t.settings.load_failed}{' '}
            <button type="button" onClick={load}>
              {t.settings.retry}
            </button>
          </p>
        ) : (
          <p role="status">{t.settings.loading}</p>
        )}
      </section>
    );
  }

  const unanswered = state.instances.some((i) => !i.token_deleted || i.choice === 'pending');
  const undeleted = state.instances.some((i) => !i.token_deleted);
  const failure = (e: unknown) => setSaid(say('alert', errorText(e, t)));

  const doBackup = () => {
    setSaid(null);
    void action.run(() => removalBackup(), failure).then((a) => {
      if (a !== undefined) {
        setBackup(a.saved);
        setSaid(say('status', a.saved ? t.settings.removal_backup_saved : t.settings.removal_backup_cancelled));
      }
      load();
    });
  };
  const doExport = () => {
    setSaid(null);
    setExporting(true);
    void action
      .run(
        () => removalExport(),
        (e) => setSaid(exportRefusal(e, t)),
      )
      .then((done) => {
        if (done !== undefined) setSaid(exportResult(done, true, t));
        if (live.current) setExporting(false);
      });
  };
  // The cancel only asks (Rust ends the export, or it already ended): the export's own answer is
  // the outcome. It does not go through `action`, which is busy for as long as the export runs.
  const cancelExport = () =>
    exportCancel().then(
      (a) =>
        setSaid(
          say('status', a.cancelled ? t.settings.removal_export_cancel_requested : t.settings.removal_export_cancel_none),
        ),
      (e: unknown) => failure(e),
    );
  // A refusal or a failure (`undefined`) says Rust's state may differ from the page's (a token
  // stored again, a recorded procedure, a tick taken back): read it again, so the ticks, the retry
  // button and Finish show what Rust holds. The refusal text stays.
  const doBegin = () => {
    setSaid(null);
    void action.run(() => removalBegin(), failure).then((next) => (next === undefined ? load() : take(next)));
  };
  const doMark = (alias: string, choice: RemovalChoice) => {
    setSaid(null);
    void action
      .run(() => removalMark(alias, choice), failure)
      .then((next) => (next === undefined ? load() : take(next)));
  };
  const doFinish = () => {
    setSaid(null);
    void action.run(() => removalFinish(), failure).then((answer) => {
      if (answer === undefined) {
        load();
        return;
      }
      setFinished(answer);
      setSaid({ role: 'status', body: <Finished answer={answer} /> });
      onChanged();
      load();
    });
  };

  const retention =
    state.retention_left_days !== null
      ? t.settings.removal_retention_left(state.retention_left_days)
      : state.legal_hold
        ? t.settings.removal_retention_hold
        : t.settings.removal_retention(state.retention_days, false);
  const exportJob = exporting && job !== null && job.job === 'export' && running(job, 'export') ? job : null;
  const progress =
    exportJob !== null && exportJob.phase === 'progress' && exportJob.done !== undefined && exportJob.total !== undefined
      ? { done: exportJob.done, total: exportJob.total }
      : null;

  return (
    <section id="settings-removal" aria-label={t.settings.removal}>
      <h2 tabIndex={-1}>{t.settings.removal}</h2>
      <Announce said={said} />
      {/* Present from the start and empty until a command runs, so the line is announced. */}
      <p role="status">{action.pending ? t.settings.working : null}</p>
      {finished !== null ? null : (
        <>
          <p>{t.settings.removal_intro}</p>
          <p>{retention}</p>
          {state.recorded ? <p>{t.settings.removal_recorded}</p> : null}
          <p>{t.settings.removal_backup_note}</p>
          <button type="button" disabled={action.pending} onClick={doBackup}>
            {t.settings.removal_backup}
          </button>
          {state.backup_made && backup === null ? <p>{t.settings.removal_backup_made}</p> : null}
          <p>{t.settings.removal_export_note}</p>
          <button type="button" disabled={action.pending} onClick={doExport}>
            {t.settings.removal_export}
          </button>
          {exporting ? (
            <div className="audit-job">
              <span id="removal-export-running">{t.settings.removal_export_running}</span>{' '}
              {progress === null ? (
                <>
                  <progress aria-labelledby="removal-export-running" /> <span>{t.settings.removal_export_starting}</span>
                </>
              ) : (
                <>
                  <progress aria-labelledby="removal-export-running" value={progress.done} max={progress.total} />{' '}
                  <span>{t.audit.export_progress(progress.done, progress.total)}</span>
                </>
              )}{' '}
              <button type="button" onClick={() => void cancelExport()}>
                {t.settings.removal_export_cancel}
              </button>
            </div>
          ) : null}
          {state.active ? null : (
            <p>
              <button type="button" disabled={action.pending} onClick={doBegin}>
                {t.settings.removal_begin}
              </button>
            </p>
          )}
          {state.active ? (
            <>
              <h3>{t.settings.removal_checklist}</h3>
              <ul>
                {state.instances.map((item) => (
                  <Item
                    key={item.alias}
                    item={item}
                    pending={action.pending}
                    final={state.recorded}
                    onMark={doMark}
                  />
                ))}
              </ul>
              {undeleted ? (
                <p>
                  <button type="button" disabled={action.pending} onClick={doBegin}>
                    {t.settings.removal_retry}
                  </button>
                </p>
              ) : null}
              <p>{t.settings.removal_finish_hint}</p>
              <button type="button" className="danger" disabled={action.pending || unanswered} onClick={doFinish}>
                {t.settings.removal_finish}
              </button>
            </>
          ) : null}
        </>
      )}
      {action.error === null ? null : <p role="alert">{action.error}</p>}
    </section>
  );
}

/** What `removal_finish` removed, as fixed words; "Done" only when every step succeeded. */
function Finished({ answer }: { answer: RemovalFinishAnswer }) {
  const t = useText();
  return (
    <>
      <p>{t.settings.removal_autostart[answer.autostart]}</p>
      <p>{t.settings.removal_cli[answer.cli]}</p>
      {answer.cli_reason === null ? null : (
        <p>{own(t.settings.removal_cli_reasons, answer.cli_reason) ?? t.settings.removal_cli_reasons['other']}</p>
      )}
      <p>{answer.cli === 'not_removed' ? t.settings.removal_incomplete : t.settings.removal_complete}</p>
    </>
  );
}

function Item({
  item,
  pending,
  final,
  onMark,
}: {
  item: RemovalItem;
  pending: boolean;
  /** The answers are recorded: they cannot be changed any more. */
  final: boolean;
  onMark: (alias: string, choice: RemovalChoice) => void;
}) {
  const t = useText();
  const choiceText =
    item.choice === 'done'
      ? t.settings.removal_choice_done
      : item.choice === 'skipped'
        ? t.settings.removal_choice_skipped
        : t.settings.removal_choice_pending;
  const off = pending || final;
  return (
    <li>
      <p>{t.settings.removal_revoke_step}</p>
      <p>
        {t.settings.removal_alias}: <Cfg value={item.alias} /> ({t.settings.product[item.product]}
        {item.origin === null ? null : (
          <>
            , <Cfg value={item.origin} />
          </>
        )}
        )
      </p>
      <p>
        {t.settings.removal_identity}:{' '}
        {item.identity === null ? (
          t.settings.removal_identity_unknown
        ) : (
          <AgentText value={item.identity} unusual={unusual(item.identity)} />
        )}
      </p>
      {item.token_deleted ? (
        <>
          <button
            type="button"
            aria-pressed={item.choice === 'done'}
            disabled={off}
            onClick={() => onMark(item.alias, 'done')}
          >
            {t.settings.removal_done}
          </button>{' '}
          <button
            type="button"
            aria-pressed={item.choice === 'skipped'}
            disabled={off}
            onClick={() => onMark(item.alias, 'skipped')}
          >
            {t.settings.removal_skip}
          </button>{' '}
          {item.choice === 'pending' ? null : (
            <button type="button" disabled={off} onClick={() => onMark(item.alias, 'pending')}>
              {t.settings.removal_undo}
            </button>
          )}
          <p role="status">{choiceText}</p>
        </>
      ) : (
        <p role="alert">{item.error === null ? t.settings.removal_token_back : t.settings.removal_not_deleted}</p>
      )}
    </li>
  );
}
