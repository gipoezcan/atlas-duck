import { openWindow, quit, type OpenableWindow } from './ipc/invoke';
import type { StatusLine } from './ipc/types';
import { HelpButton } from './HelpLink';
import { useText } from './i18n/context';

const BUTTONS = ['settings', 'audit', 'running_scripts', 'onboarding'] as const satisfies readonly OpenableWindow[];

interface HeaderProps {
  /** The `app_status` lines: app-generated text only (spec 5.6). */
  lines: readonly StatusLine[];
}

/**
 * The Approvals header (spec 5.6): the four window buttons, Quit, and the status banner that
 * mirrors the tray lines. Each line starts with its level as text so colour is never the signal.
 * A failed call is not surfaced here: the window either opens or it does not.
 */
export function Header({ lines }: HeaderProps) {
  const t = useText();
  return (
    <header className="app-header">
      <nav aria-label={t.approvals.header.windows_label}>
        {BUTTONS.map((w) => (
          <button key={w} type="button" onClick={() => void openWindow(w).catch(ignore)}>
            {t.approvals.header[w]}
          </button>
        ))}
        <HelpButton window="approvals" />
        <button type="button" onClick={() => void quit().catch(ignore)}>
          {t.approvals.header.quit}
        </button>
      </nav>
      {lines.length > 0 ? (
        <ul className="banner" aria-label={t.approvals.header.banner_label}>
          {lines.map((l) => (
            <li key={l.id} className={`banner-${l.level}`}>
              <strong>{l.level === 'caution' ? t.approvals.header.caution_prefix : t.approvals.header.info_prefix}</strong>{' '}
              {l.text}
            </li>
          ))}
        </ul>
      ) : null}
    </header>
  );
}

function ignore(): void {}