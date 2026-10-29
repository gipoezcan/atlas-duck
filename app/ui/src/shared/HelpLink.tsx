import { createContext, useContext } from 'react';

import { helpOpen } from './ipc/invoke';
import { useText } from './i18n/context';
import uiLinks from '../../../../docs/user-guide/ui-links.json';

/** The windows whose header carries a Help button (the credential window has none). */
type HelpWindow = Exclude<keyof typeof uiLinks.desktop, 'credential'>;

/**
 * Where the page runs. The Audit and Approvals components are shared with the server pages, which
 * have their own help links (`server/shell/ServerHelp`): under the server root these two render
 * nothing, because `help_open` exists only in the desktop app.
 */
export const HelpMode = createContext<'desktop' | 'server'>('desktop');

function open(target: string): void {
  const [page, anchor] = target.split('#');
  if (page) void helpOpen(page, anchor).catch(ignore);
}

/** "Help" for a whole window: the guide page `docs/user-guide/ui-links.json` names for it. */
export function HelpButton({ window }: { window: HelpWindow }) {
  const t = useText();
  if (useContext(HelpMode) === 'server') return null;
  return (
    <button type="button" className="help-button" onClick={() => open(uiLinks.desktop[window])}>
      {t.common.help}
    </button>
  );
}

/** The "?" next to a section: `section` is a `desktop_sections` key of `ui-links.json`. */
export function HelpLink({ section }: { section: keyof typeof uiLinks.desktop_sections }) {
  const t = useText();
  if (useContext(HelpMode) === 'server') return null;
  return (
    <button
      type="button"
      className="help-link"
      aria-label={t.common.help_section}
      onClick={() => open(uiLinks.desktop_sections[section])}
    >
      ?
    </button>
  );
}

/** A failed call is not surfaced: the window either opens or it does not (as the header's). */
function ignore(): void {}