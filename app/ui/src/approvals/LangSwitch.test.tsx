import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { previewFetch, uiLangGet } from '../shared/ipc/invoke';
import { DesktopLangRoot } from '../shared/i18n/DesktopLangRoot';
import { Detail } from './Detail';
import { emit, flush, mockWindow, previewOf, WRITE } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
  uiLangGet: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mockWindow();
  vi.mocked(uiLangGet).mockResolvedValue({ pref: 'auto', lang: 'en' });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  document.documentElement.lang = '';
});

describe('a language switch (M15 T3, Review Focus 2)', () => {
  it('lang_change_keeps_open_deny_draft', async () => {
    vi.mocked(previewFetch).mockResolvedValue(previewOf(WRITE, 'transition', { deny_offers: [] }));
    render(
      <DesktopLangRoot>
        <Detail item={WRITE} openToken={1} />
      </DesktopLangRoot>,
    );
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    const reason = screen.getByRole('textbox', { name: /Reason/ }) as HTMLTextAreaElement;
    fireEvent.change(reason, { target: { value: 'not this sprint' } });

    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'de', lang: 'de' });
    emit('lang_changed', { lang: 'de', pref: 'de' });
    await flush();

    expect(document.documentElement.lang).toBe('de');
    // The same field, still open, with the typed reason: the switch re-rendered, nothing remounted.
    const after = screen.getByRole('textbox', { name: /Reason/ }) as HTMLTextAreaElement;
    expect(after).toBe(reason);
    expect(after.value).toBe('not this sprint');
  });
});
