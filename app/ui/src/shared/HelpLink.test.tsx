import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { HelpButton, HelpLink } from './HelpLink';
import { LangProvider } from './i18n/context';
import { helpOpen } from './ipc/invoke';
import uiLinks from '../../../../docs/user-guide/ui-links.json';

vi.mock('./ipc/invoke', () => ({ helpOpen: vi.fn() }));

beforeEach(() => {
  vi.mocked(helpOpen).mockReset().mockResolvedValue(null);
});

describe('HelpLink', () => {
  it('help_link_calls_help_open_with_page_and_anchor_from_ui_links', () => {
    expect(uiLinks.desktop_sections['settings/language']).toBe('settings#language');
    render(<HelpLink section="settings/language" label="Language" />);
    fireEvent.click(screen.getByRole('button', { name: 'Help: Language' }));
    expect(helpOpen).toHaveBeenCalledWith('settings', 'language');
  });

  it('help_button_opens_the_windows_page', () => {
    render(<HelpButton window="audit" />);
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    const [page, anchor] = uiLinks.desktop.audit.split('#');
    expect(helpOpen).toHaveBeenCalledWith(page, anchor);
  });

  it('every_desktop_window_with_a_link_has_a_button_target', () => {
    for (const w of ['approvals', 'settings', 'audit', 'running_scripts', 'onboarding', 'setup'] as const) {
      const { unmount } = render(<HelpButton window={w} />);
      fireEvent.click(screen.getByRole('button', { name: 'Help' }));
      expect(helpOpen).toHaveBeenLastCalledWith(...uiLinks.desktop[w].split('#'));
      unmount();
    }
  });

  it('shows_hilfe_in_german', () => {
    render(
      <LangProvider lang="de">
        <HelpButton window="approvals" />
        <HelpLink section="settings/language" label="Sprache" />
      </LangProvider>,
    );
    expect(screen.getByRole('button', { name: 'Hilfe' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Hilfe: Sprache' })).toBeTruthy();
  });

  // An unhandled rejection would fail the whole vitest run, so reaching the assertions is the proof
  // that the rejection is handled; what the user sees is nothing, and the button keeps working.
  it('a_rejected_help_open_is_handled_and_leaves_the_button_usable', async () => {
    vi.mocked(helpOpen).mockRejectedValue(new Error('refused'));
    render(<HelpButton window="audit" />);
    const button = screen.getByRole('button', { name: 'Help' });
    fireEvent.click(button);
    await act(async () => {
      for (let i = 0; i < 10; i++) await Promise.resolve();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('button', { name: 'Help' })).toBe(button);
    fireEvent.click(button);
    expect(helpOpen).toHaveBeenCalledTimes(2);
  });
  it('each_question_mark_names_its_section', () => {
    render(
      <>
        <HelpLink section="settings/language" label="Language" />
        <HelpLink section="settings/cli" label="Command line" />
      </>,
    );
    expect(screen.getByRole('button', { name: 'Help: Language' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Help: Command line' })).toBeTruthy();
  });
});