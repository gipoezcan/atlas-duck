import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../ipc/events';
import { uiLangGet } from '../ipc/invoke';
import { useText } from './context';
import { DesktopLangRoot } from './DesktopLangRoot';

vi.mock('../ipc/invoke', () => ({ uiLangGet: vi.fn() }));
vi.mock('../ipc/events', () => ({ on: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

function Probe() {
  return <p>{useText().common.language}</p>;
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(uiLangGet).mockResolvedValue({ pref: 'auto', lang: 'en' });
});

afterEach(() => {
  cleanup();
  document.documentElement.lang = '';
});

describe('DesktopLangRoot (M15 T3)', () => {
  // Review I-1: the Onboarding window holds no event grant, so `on` is refused there; it follows a
  // change when it gets the focus again (and when it becomes visible).
  it('a_window_without_event_grant_rereads_on_focus', async () => {
    vi.mocked(on).mockRejectedValue('event.listen not allowed');
    render(
      <DesktopLangRoot>
        <Probe />
      </DesktopLangRoot>,
    );
    await flush();
    expect(screen.getByText('Language')).toBeTruthy();
    expect(uiLangGet).toHaveBeenCalledTimes(1);

    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'de', lang: 'de' });
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await flush();
    expect(uiLangGet).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Sprache')).toBeTruthy();
    expect(document.documentElement.lang).toBe('de');

    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'en', lang: 'en' });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    await flush();
    expect(uiLangGet).toHaveBeenCalledTimes(3);
    expect(screen.getByText('Language')).toBeTruthy();
  });

  it('stops listening on unmount', async () => {
    vi.mocked(on).mockResolvedValue(() => undefined);
    const view = render(
      <DesktopLangRoot>
        <Probe />
      </DesktopLangRoot>,
    );
    await flush();
    view.unmount();
    act(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await flush();
    expect(uiLangGet).toHaveBeenCalledTimes(1);
  });
});
