import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { on } from '../shared/ipc/events';
import wizardFixture from '../shared/ipc/fixtures/wizard_state.json';
import { wizardState } from '../shared/ipc/invoke';
import type { WizardState } from '../shared/ipc/types';
import { Wizard } from './Wizard';

vi.mock('../shared/ipc/invoke', () => ({
  cliInstall: vi.fn(),
  onboardingText: vi.fn(),
  quit: vi.fn(),
  instanceAdd: vi.fn(),
  instanceConfirmConfig: vi.fn(),
  instanceAcceptUrlChange: vi.fn(),
  wizardState: vi.fn(),
  wizardUseDefaultDir: vi.fn(),
  wizardChooseDir: vi.fn(),
  wizardBegin: vi.fn(),
  wizardSkipInstances: vi.fn(),
  wizardFinish: vi.fn(),
  wizardAnchorDir: vi.fn(),
  wizardAnchorDirClear: vi.fn(),
  wizardRestore: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const [DATA_DIR] = wizardFixture as unknown as [WizardState];

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

beforeEach(() => {
  vi.mocked(on).mockReset().mockResolvedValue(() => undefined);
  vi.mocked(wizardState).mockReset().mockResolvedValue({ ...DATA_DIR, step: 'data_dir', data_dir: 'C:\\data' });
});

afterEach(() => {
  cleanup();
});

describe('the setup wizard in German (M15 T6)', () => {
  it('wizard_first_step_in_german', async () => {
    render(
      <LangProvider lang="de">
        <Wizard />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.approvals.window_titles.setup);
    expect(screen.getAllByRole('heading', { level: 2 })[0]?.textContent).toBe(de.setup.data_dir_heading);
    expect(screen.getByText(de.setup.data_dir_intro)).toBeTruthy();
    expect(screen.queryByText(en.setup.data_dir_intro)).toBeNull();
    expect(screen.getByRole('button', { name: de.setup.data_dir_use_default })).toBeTruthy();
    expect(screen.getByRole('button', { name: de.setup.quit })).toBeTruthy();
  });

  it('counts_and_errors_are_german', () => {
    expect(de.setup.required(1)).toBe('Einrichtung erforderlich \u2014 1 Anfrage zurückgewiesen');
    expect(de.setup.required(1234)).toBe('Einrichtung erforderlich \u2014 1.234 Anfragen zurückgewiesen');
    expect(de.setup.step_announce('Befehlszeile')).toBe('Schritt: Befehlszeile');
  });
});