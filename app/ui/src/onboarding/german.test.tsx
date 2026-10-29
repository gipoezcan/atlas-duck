import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { onboardingText } from '../shared/ipc/invoke';
import { Onboarding } from './Onboarding';

vi.mock('../shared/ipc/invoke', () => ({ onboardingText: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  vi.mocked(onboardingText).mockReset();
  writeText.mockReset().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
});

afterEach(() => {
  cleanup();
  Reflect.deleteProperty(navigator, 'clipboard');
});

describe('the onboarding window in German (M15 T6)', () => {
  it('onboarding_panel_in_german: the frame is German, the generated sections are shown as they are', async () => {
    vi.mocked(onboardingText).mockResolvedValue({ sections: [{ id: 'commands', title: 'Commands', text: 'atlas-duck ops list' }] });
    render(
      <LangProvider lang="de">
        <Onboarding />
      </LangProvider>,
    );
    expect(screen.getByRole('status').textContent).toBe(de.onboarding.loading);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.approvals.window_titles.onboarding);
    expect(screen.getByText(de.onboarding.intro)).toBeTruthy();
    expect(screen.queryByText(en.onboarding.intro)).toBeNull();
    const copy = screen.getByRole('button', { name: de.onboarding.copy_label('Commands') });
    expect(copy.textContent).toBe(de.onboarding.copy_button);
    await act(async () => {
      fireEvent.click(copy);
    });
    await flush();
    expect(writeText).toHaveBeenCalledWith('atlas-duck ops list');
    expect(screen.getByRole('status').textContent).toBe(de.onboarding.copied('Commands'));
  });

  it('load_failure_in_german', async () => {
    vi.mocked(onboardingText).mockRejectedValue(new Error('x'));
    render(
      <LangProvider lang="de">
        <Onboarding />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('alert').textContent).toContain(de.onboarding.load_failed);
    expect(screen.getByRole('button', { name: de.onboarding.retry })).toBeTruthy();
  });
});