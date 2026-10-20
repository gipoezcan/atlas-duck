import { useCallback, useEffect, useRef, useState } from 'react';

import { Announce, kinds, type Said, say } from '../audit/text';
import {
  backupTrigger,
  forgetInstall,
  orphanInstalls,
  recoveryPassphraseChange,
  restoreBegin,
  restoreCancel,
} from '../shared/ipc/invoke';
import type { OrphanInstall, RestoreDone } from '../shared/ipc/types';
import { RECOVERY_TEXT as T, SETTINGS_TEXT } from '../shared/strings';
import { Cfg, errorText } from './text';
import { useAction } from './useAction';
import { running, useAuditJob } from './useAuditJob';

/**
 * Recovery and backup (spec 5.7, 8.6, 8.10, 8.11, 8.13, L27). Rust asks every question itself (the
 * confirmations, every folder and file dialog, the recovery passphrase in the credential window);
 * the calls carry no argument. This page shows the lines around those dialogs: the backup text
 * (L27: no tokens), the pre-upgrade advice, an indeterminate progress bar for a backup or a
 * restore (a restore has no row count), the "Requests wait while the restore runs" banner from
 * the restore job's `started` event, and what each command answered, in one live region that is in
 * the page before the first answer. "Cancel restore" is shown for as long as the restore call runs:
 * Rust cancels it while its own dialogs are up and answers `busy` once the store call began, which
 * the page says. A restore that answered `committed_incomplete` (the restore is complete only after
 * the next start) is no longer offered again, and a restore whose follow-up failed asks for a
 * restart too.
 */
export function Recovery({ onChanged }: { onChanged: () => void }) {
  const action = useAction();
  const job = useAuditJob();
  const [said, setSaid] = useState<Said | null>(null);
  const [backingUp, setBackingUp] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [restartNeeded, setRestartNeeded] = useState(false);
  const restoreButton = useRef<HTMLButtonElement>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const focusBack = useRef(false);
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  // The cancel button appears with the restore; when the restore ends the focus goes back to the
  // button that started it (as soon as it is enabled again).
  useEffect(() => {
    if (restoring) cancelButton.current?.focus();
  }, [restoring]);
  useEffect(() => {
    if (focusBack.current && !restoring && !action.pending) {
      focusBack.current = false;
      restoreButton.current?.focus();
    }
  });

  const failure = (e: unknown) => setSaid(say('alert', errorText(e)));

  const backup = () => {
    setSaid(null);
    setBackingUp(true);
    void action.run(() => backupTrigger(), failure).then((a) => {
      if (live.current) setBackingUp(false);
      if (a !== undefined) setSaid(say('status', a.saved ? T.backup_saved : T.backup_not_saved));
    });
  };

  const restore = () => {
    setSaid(null);
    setRestoring(true);
    void action
      .run(
        () => restoreBegin(),
        (e) => {
          failure(e);
          const { kind, inner } = kinds(e);
          if (kind === 'restore' && inner === 'committed_incomplete') setRestartNeeded(true);
        },
      )
      .then((done) => {
        if (!live.current) return;
        focusBack.current = true;
        setRestoring(false);
        if (done === undefined) return;
        setSaid(say('status', <Restored done={done} />));
        onChanged();
      });
  };

  const cancelRestore = () =>
    restoreCancel().then(
      (a) => setSaid(say('status', a.cancelled ? T.restore_cancel_requested : T.restore_cancel_none)),
      (e: unknown) => setSaid(say('alert', kinds(e).kind === 'busy' ? T.restore_cancel_too_late : errorText(e))),
    );

  const changePassphrase = () => {
    setSaid(null);
    void action.run(() => recoveryPassphraseChange(), failure).then((r) => {
      if (r !== undefined) setSaid(say('status', T.passphrase_opened));
    });
  };

  const waiting = restoring && running(job, 'restore');
  return (
    <section aria-label={T.recovery}>
      <h2>{T.recovery}</h2>
      <p>{T.backup_tokens}</p>
      <p>{T.backup_retention}</p>
      <p>{T.upgrade_backup}</p>
      <button type="button" disabled={action.pending} onClick={backup}>
        {T.backup_start}
      </button>
      {backingUp ? (
        <div>
          <span id="recovery-backup-running">{T.backup_running}</span>{' '}
          <progress aria-labelledby="recovery-backup-running" />
        </div>
      ) : null}
      <p>{T.restore_note}</p>
      <button
        type="button"
        ref={restoreButton}
        disabled={action.pending || restartNeeded}
        onClick={restore}
      >
        {T.restore_start}
      </button>
      {restoring ? (
        <div>
          <span id="recovery-restore-running">{waiting ? T.restore_running : T.restore_starting}</span>{' '}
          <progress aria-labelledby="recovery-restore-running" />{' '}
          <button type="button" ref={cancelButton} onClick={() => void cancelRestore()}>
            {T.restore_cancel}
          </button>
        </div>
      ) : null}
      {/* In the page from the start and empty until the restore job starts, so the banner is announced. */}
      <p role="status">{waiting ? T.restore_wait : null}</p>
      <p>{T.passphrase_note}</p>
      <button type="button" disabled={action.pending} onClick={changePassphrase}>
        {T.passphrase_change}
      </button>
      <Announce said={said} />
    </section>
  );
}

/** What a completed restore says: counts only (Rust sends no text), the restart prompt, the passphrase offer. */
function Restored({ done }: { done: RestoreDone }) {
  return (
    <>
      <p>{T.restore_done}</p>
      <p>{T.restore_records_lost(done.records_lost)}</p>
      <p>{T.restore_tokens(done.tokens_deleted)}</p>
      {done.after_restore_failed ? <p>{T.restore_follow_up_failed}</p> : null}
      {done.offer_passphrase_change ? <p>{T.restore_passphrase_offer}</p> : null}
    </>
  );
}

/**
 * Old installs (spec 8.6, M10 T14, PD-170): installs only archived logs name, with their archived
 * files and the keychain entries they left. "Forget" sends the install id from the listing and
 * nothing else; Rust confirms in two native dialogs (the token entries, then separately the keys that
 * open the archived log), so the page only lists and shows the answer. The list is read again after
 * each attempt; a partial failure names what was and was not deleted. Every string is Rust's
 * display-escaped text and is shown as data.
 */
export function OldInstalls() {
  const action = useAction();
  const [list, setList] = useState<OrphanInstall[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [said, setSaid] = useState<Said | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const live = useRef(true);

  const load = useCallback(() => {
    orphanInstalls().then(
      (l) => {
        if (live.current) {
          setList(l);
          setFailed(false);
        }
      },
      () => {
        if (live.current) setFailed(true);
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

  const forget = (id: string) => {
    setSaid(null);
    void action
      .run(
        () => forgetInstall(id),
        (e) => {
          setSaid(forgetRefusal(e));
          load();
        },
      )
      .then((done) => {
        if (done === undefined) return;
        setSaid(say('status', T.forgotten(done.keys_deleted)));
        load();
        // The row is gone: the focus stays in the section.
        heading.current?.focus();
      });
  };

  return (
    <section aria-label={T.orphans}>
      <h2 tabIndex={-1} ref={heading}>
        {T.orphans}
      </h2>
      <p>{T.orphans_intro}</p>
      {failed ? (
        <p role="alert">
          {T.orphans_load_failed}{' '}
          <button type="button" onClick={load}>
            {SETTINGS_TEXT.retry}
          </button>
        </p>
      ) : list === null ? null : list.length === 0 ? (
        <p>{T.orphans_none}</p>
      ) : (
        <ul>
          {list.map((o) => (
            <li key={o.install_id}>
              <p>
                {T.orphan_install}: <Cfg value={o.install_id} />
              </p>
              <Names label={T.orphan_files} names={o.archived_files} />
              <Names label={T.orphan_entries} names={o.entries} />
              <button
                type="button"
                aria-label={T.orphan_forget_label(o.install_id)}
                disabled={action.pending}
                onClick={() => forget(o.install_id)}
              >
                {T.orphan_forget}
              </button>
            </li>
          ))}
        </ul>
      )}
      <Announce said={said} />
    </section>
  );
}

function Names({ label, names }: { label: string; names: string[] }) {
  if (names.length === 0) return null;
  return (
    <>
      <p>{label}:</p>
      <ul>
        {names.map((n, i) => (
          <li key={`${n}-${i}`}>
            <Cfg value={n} />
          </li>
        ))}
      </ul>
    </>
  );
}

/** A refused forget: the fixed text, and for a partial keychain failure the names deleted and kept. */
function forgetRefusal(e: unknown): Said {
  const text = errorText(e);
  const { kind, inner } = kinds(e);
  const error = typeof e === 'object' && e !== null ? (e as { error?: Record<string, unknown> }).error : undefined;
  const strings = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  if (kind !== 'forget' || inner !== 'keychain' || error === undefined) return say('alert', text);
  const deleted = strings(error['deleted']);
  const kept = strings(error['not_deleted']);
  return say(
    'alert',
    <>
      <p>{text}</p>
      <Names label={T.forget_deleted} names={deleted} />
      <Names label={T.forget_not_deleted} names={kept} />
    </>,
  );
}
