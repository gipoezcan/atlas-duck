import { openWindow, quit, type OpenableWindow } from './ipc/invoke';
import type { StatusLine } from './ipc/types';
import { HEADER_TEXT } from './strings';

const BUTTONS: readonly { window: OpenableWindow; label: string }[] = [
  { window: 'settings', label: HEADER_TEXT.settings },
  { window: 'audit', label: HEADER_TEXT.audit },
  { window: 'running_scripts', label: HEADER_TEXT.running_scripts },
  { window: 'onboarding', label: HEADER_TEXT.onboarding },
];

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
  return (
    <header className="app-header">
      <nav aria-label="Windows">
        {BUTTONS.map((b) => (
          <button key={b.window} type="button" onClick={() => void openWindow(b.window).catch(ignore)}>
            {b.label}
          </button>
        ))}
        <button type="button" onClick={() => void quit().catch(ignore)}>
          {HEADER_TEXT.quit}
        </button>
      </nav>
      {lines.length > 0 ? (
        <ul className="banner" aria-label={HEADER_TEXT.banner_label}>
          {lines.map((l) => (
            <li key={l.id} className={`banner-${l.level}`}>
              <strong>{l.level === 'caution' ? HEADER_TEXT.caution_prefix : HEADER_TEXT.info_prefix}</strong>{' '}
              {l.text}
            </li>
          ))}
        </ul>
      ) : null}
    </header>
  );
}

function ignore(): void {}