import { useRef, useState } from 'react';
import { useText } from '../shared/i18n/context';

import { Announce, type Said, say } from '../audit/text';
import { anchorDirRemove, anchorDirSet, reAnchor } from '../shared/ipc/invoke';
import type { SettingsView } from '../shared/ipc/types';
import { Cfg, errorText, own } from './text';
import { useAction } from './useAction';

interface Props {
  view: SettingsView;
  onChanged: () => void;
}

/**
 * The external anchor directory and the keychain anchors (spec 8.5, 8.7; M10 T14, PD-166, PD-170).
 * Rust asks every question itself: the folder dialog, the confirmation that names the folder and
 * the directory in force (after the pick), and the confirmation of a re-anchor. This page sends no
 * argument, so there is no path to type; it shows what the store reports (the directory, a failing
 * or waiting anchor write, a missing keychain entry) and what each command answered, in one live
 * region that is in the page before the first answer. A failing anchor-directory write is a line,
 * never an incident (8.5). "Re-anchor" is offered only while Rust says so (an entry is missing and
 * no barrier holds the anchors), and its text says that both anchors are written again and that
 * it is recorded as an integrity incident. The anchor directory is audit state, not config.toml,
 * so a read-only config does not turn these controls off.
 */
export function AnchorDir({ view, onChanged }: Props) {
  const t = useText();
  const action = useAction();
  const [said, setSaid] = useState<Said | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const { health } = view;
  const failure = (e: unknown) => setSaid(say('alert', errorText(e, t)));

  const change = (remove: boolean) => {
    setSaid(null);
    void action
      .run(() => (remove ? anchorDirRemove() : anchorDirSet()), failure)
      .then((a) => {
        if (a === undefined) return;
        setSaid(say('status', a.anchor_dir === null ? t.settings.recovery.anchor_dir_removed : t.settings.recovery.anchor_dir_changed));
        onChanged();
      });
  };
  const doReAnchor = () => {
    setSaid(null);
    void action.run(() => reAnchor(), failure).then((a) => {
      if (a === undefined) {
        onChanged();
        return;
      }
      setSaid(say('status', t.settings.recovery.reanchor_done));
      onChanged();
      // The button goes away once Rust no longer offers it: the focus stays in the section.
      heading.current?.focus();
    });
  };

  const missing = health.anchors_missing === null ? null : own(t.settings.recovery.anchors_missing, health.anchors_missing);
  return (
    <section id="settings-anchor-dir" aria-label={t.settings.recovery.anchor_dir}>
      <h2 tabIndex={-1}>{t.settings.recovery.anchor_dir}</h2>
      <p>
        {t.settings.recovery.anchor_dir}: {view.anchor_dir === null ? t.settings.recovery.anchor_dir_none : <Cfg value={view.anchor_dir} />}
      </p>
      <p>{t.settings.recovery.anchor_dir_note}</p>
      {health.anchor_dir_write_failing ? (
        <p>{t.audit.anchor_dir_failing(health.anchor_dir_lines_pending)}</p>
      ) : health.anchor_dir_lines_pending > 0 ? (
        <p>{t.settings.recovery.anchor_dir_pending(health.anchor_dir_lines_pending)}</p>
      ) : null}
      <button type="button" className="primary" disabled={action.pending} onClick={() => change(false)}>
        {view.anchor_dir === null ? t.settings.recovery.anchor_dir_set : t.settings.recovery.anchor_dir_change}
      </button>
      {view.anchor_dir === null ? null : (
        <>
          {' '}
          <button type="button" disabled={action.pending} onClick={() => change(true)}>
            {t.settings.recovery.anchor_dir_remove}
          </button>
        </>
      )}
      <h3 tabIndex={-1} ref={heading}>
        {t.settings.recovery.reanchor_heading}
      </h3>
      {missing === null ? null : <p>{missing}</p>}
      {health.re_anchor_offered ? (
        <>
          <p>{t.settings.recovery.reanchor_note}</p>
          <button type="button" disabled={action.pending} onClick={doReAnchor}>
            {t.settings.recovery.reanchor}
          </button>
        </>
      ) : null}
      <Announce said={said} />
    </section>
  );
}
