import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import {
  cliInstall,
  instanceAcceptUrlChange,
  instanceAdd,
  instanceConfirmConfig,
  onboardingText,
  quit,
  wizardBegin,
  wizardChooseDir,
  wizardFinish,
  wizardSkipInstances,
  wizardState,
  wizardUseDefaultDir,
} from '../shared/ipc/invoke';
import wizardFixture from '../shared/ipc/fixtures/wizard_state.json';
import type { InstanceView, WizardState, WizardStep } from '../shared/ipc/types';
import { SETUP_TEXT as T } from './text';
import { REREAD_DEBOUNCE_MS, STEP0_ERROR_DELAY_MS, STEP_COOLDOWN_MS, Wizard } from './Wizard';

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
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const [DATA_DIR, DATA_DIR_REFUSED, PASSPHRASE, INSTANCES, STOPPED] = wizardFixture as unknown as [
  WizardState,
  WizardState,
  WizardState,
  WizardState,
  WizardState,
];
const WORK = INSTANCES.instances[0] as InstanceView;

const at = (step: WizardStep, over: Partial<WizardState> = {}): WizardState => ({
  ...DATA_DIR,
  data_dir: 'C:\\data',
  step,
  ...over,
});

let handlers: Record<string, ((payload: unknown) => void)[]> = {};

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

async function show(s: WizardState) {
  vi.mocked(wizardState).mockResolvedValue(s);
  const view = render(<Wizard />);
  await flush();
  return view;
}

async function emit(name: string): Promise<void> {
  act(() => {
    for (const h of handlers[name] ?? []) h(null);
  });
  await flush();
}

/** The panel heading: the first h2 (the add form has its own). */
const heading = () => screen.getAllByRole('heading', { level: 2 })[0]?.textContent;

/** Rust answers a command with the next state and keeps answering it to the re-read. */
function answer(cmd: (...a: never[]) => Promise<WizardState>, next: WizardState): void {
  vi.mocked(cmd as () => Promise<WizardState>).mockResolvedValue(next);
  vi.mocked(wizardState).mockResolvedValue(next);
}

const click = async (name: string | RegExp) => {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
  await flush();
};

const mocks = [
  cliInstall,
  onboardingText,
  quit,
  instanceAdd,
  instanceConfirmConfig,
  instanceAcceptUrlChange,
  wizardState,
  wizardUseDefaultDir,
  wizardChooseDir,
  wizardBegin,
  wizardSkipInstances,
  wizardFinish,
];

beforeEach(() => {
  handlers = {};
  vi.mocked(on)
    .mockReset()
    .mockImplementation((name, handler) => {
      (handlers[name] ??= []).push(handler as (payload: unknown) => void);
      return Promise.resolve(() => undefined);
    });
  for (const f of mocks) vi.mocked(f as (...a: unknown[]) => Promise<unknown>).mockReset();
  // The onboarding step reads the snippet from Rust; most tests do not look at it.
  vi.mocked(onboardingText).mockResolvedValue({ text: 'snippet' });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Wizard', () => {
  it('listens to wizard_changed and settings_changed for this window only', async () => {
    await show(DATA_DIR);
    const names = vi.mocked(on).mock.calls.map((c) => c[0]);
    expect(names).toEqual(['wizard_changed', 'settings_changed']);
    for (const c of vi.mocked(on).mock.calls) expect(c[2]).toEqual({ thisWindow: true });
  });

  it('steps_follow_rust_state', async () => {
    const panels: [WizardState, string][] = [
      [at('data_dir', { data_dir: null }), T.data_dir_heading],
      [at('existing_store', { existing_store: true }), T.existing_heading],
      [PASSPHRASE, T.passphrase_heading],
      [at('genesis'), T.genesis_heading],
      [at('recovery_note'), T.note_heading],
      [INSTANCES, T.instances_heading],
      [at('cli'), T.cli_heading],
      [at('onboarding'), T.onboarding_heading],
      [at('done'), T.done_heading],
      [STOPPED, T.stopped_heading],
    ];
    for (const [state, expected] of panels) {
      const view = await show(state);
      expect(heading()).toBe(expected);
      view.unmount();
    }
  });

  it('does not skip a step the Rust answer did not skip', async () => {
    await show(at('recovery_note'));
    answer(wizardFinish, at('recovery_note'));
    await click(T.continue);
    expect(heading()).toBe(T.note_heading);
    // Rust moves on: the page follows, whatever step it names.
    vi.mocked(wizardState).mockResolvedValue(at('onboarding'));
    await emit('wizard_changed');
    await waitFor(() =>
      expect(heading()).toBe(T.onboarding_heading),
    );
  });

  it('data_dir_default_and_choose_buttons', async () => {
    await show(DATA_DIR);
    expect(screen.getByText(/C:\\Users\\alice\\AppData\\Local\\atlas-duck/)).toBeTruthy();
    answer(wizardUseDefaultDir, PASSPHRASE);
    await click(T.data_dir_use_default);
    expect(wizardUseDefaultDir).toHaveBeenCalledTimes(1);
    expect(heading()).toBe(T.passphrase_heading);

    await show(DATA_DIR);
    answer(wizardChooseDir, PASSPHRASE);
    await click(T.data_dir_choose);
    expect(wizardChooseDir).toHaveBeenCalledTimes(1);
    // No client-side path: the commands carry nothing.
    expect(vi.mocked(wizardChooseDir).mock.calls[0]).toEqual([]);
  });

  it('a step 0 call whose window goes away shows no error', async () => {
    await show(DATA_DIR);
    // The window is destroyed: the invoke rejects (or never answers) while the page is torn down.
    vi.mocked(wizardUseDefaultDir).mockRejectedValue('window closed');
    await click(T.data_dir_use_default);
    expect(screen.queryByRole('alert')).toBeNull();
    // The error is held back by STEP0_ERROR_DELAY_MS: a window that is destroyed meanwhile never shows it.
  });

  it('a step 0 refusal shows once the window is still there after the delay', async () => {
    await show(DATA_DIR);
    vi.mocked(wizardUseDefaultDir).mockRejectedValue({ kind: 'not_ready' });
    await click(T.data_dir_use_default);
    expect(screen.queryByRole('alert')).toBeNull();
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy(), {
      timeout: STEP0_ERROR_DELAY_MS + 1500,
    });
  });

  it('a step 0 call whose answer never arrives leaves no error', async () => {
    await show(DATA_DIR);
    vi.mocked(wizardChooseDir).mockReturnValue(new Promise(() => undefined));
    await click(T.data_dir_choose);
    await new Promise((r) => setTimeout(r, STEP0_ERROR_DELAY_MS + 100));
    await flush();
    expect(screen.queryByRole('alert')).toBeNull();
    // One command at a time: the other button is off while this one is in flight.
    expect((screen.getByRole('button', { name: T.data_dir_use_default }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it('shows the refused folder with Rust text as plain text and never echoes an unknown class', async () => {
    await show(DATA_DIR_REFUSED);
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(T.errors.not_local);
    expect(alert.textContent).toContain('\\\\nas\\home\\atlas');
    cleanup();
    await show({
      ...DATA_DIR,
      error: { class: '<img src=x onerror=alert(1)>', text: null },
    });
    const unknown = screen.getByRole('alert');
    expect(unknown.textContent).toBe(T.errors.other);
    expect(document.querySelector('img')).toBeNull();
  });

  it('setup_required_count_in_header', async () => {
    await show(PASSPHRASE);
    expect(screen.getByText('Setup required \u2014 3 requests refused')).toBeTruthy();
    cleanup();
    await show(at('data_dir', { refused_count: 0 }));
    expect(screen.getByText('Setup required \u2014 0 requests refused')).toBeTruthy();
    cleanup();
    await show(DATA_DIR);
    expect(screen.queryByText(/Setup required/)).toBeNull();
  });

  it('stopped_state_shows_text_and_quit_only', async () => {
    await show(STOPPED);
    expect(screen.getByRole('alert').textContent).toBe(STOPPED.stopped_text);
    const buttons = screen.getAllByRole('button');
    expect(buttons.map((b) => b.textContent)).toEqual([T.quit]);
    vi.mocked(quit).mockResolvedValue(null);
    await click(T.quit);
    expect(quit).toHaveBeenCalledTimes(1);
  });

  it('passphrase step offers Begin until the credentials window waits', async () => {
    await show(at('passphrase', { passphrase_window: false }));
    answer(wizardBegin, at('passphrase', { passphrase_window: true }));
    await click(T.passphrase_begin);
    expect(wizardBegin).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: T.passphrase_begin })).toBeNull();
    expect(screen.getByText(T.passphrase_waiting)).toBeTruthy();
    // The wizard collects no secret itself.
    expect(document.querySelector('input[type="password"]')).toBeNull();
  });

  it('existing store step renders on the step, not on existing_store', async () => {
    // After an archive Rust keeps existing_store true while the step is back at the passphrase.
    await show(at('passphrase', { existing_store: true }));
    expect(heading()).toBe(T.passphrase_heading);
  });

  it('double click on a finish button calls wizard_finish once, also right after it answered', async () => {
    await show(at('cli'));
    answer(wizardFinish, at('onboarding'));
    const button = screen.getByRole('button', { name: T.cli_continue });
    await act(async () => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
    await flush();
    expect(wizardFinish).toHaveBeenCalledTimes(1);
    // The page names the step it rendered: Rust refuses any other (`wrong_step`).
    expect(wizardFinish).toHaveBeenCalledWith('cli');
    // A second click that lands after the answer, on the next step's button (a different step
    // that Rust would accept), is still a double click: the button is visibly off for the cooldown.
    const next = screen.getByRole('button', { name: T.onboarding_finish }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    await click(T.onboarding_finish);
    expect(wizardFinish).toHaveBeenCalledTimes(1);
    expect(heading()).toBe(T.onboarding_heading);
  });

  it('a deliberate click after the cooldown finishes the next step', async () => {
    await show(at('cli'));
    vi.mocked(wizardFinish).mockResolvedValueOnce(at('onboarding')).mockResolvedValueOnce(at('done'));
    vi.mocked(wizardState).mockResolvedValueOnce(at('onboarding')).mockResolvedValue(at('done'));
    await click(T.cli_continue);
    const next = screen.getByRole('button', { name: T.onboarding_finish }) as HTMLButtonElement;
    expect(next.disabled).toBe(true);
    await waitFor(() => expect(next.disabled).toBe(false), { timeout: STEP_COOLDOWN_MS + 1500 });
    await click(T.onboarding_finish);
    expect(wizardFinish).toHaveBeenCalledTimes(2);
    expect(wizardFinish).toHaveBeenLastCalledWith('onboarding');
    expect(heading()).toBe(T.done_heading);
  });

  it('wrong_step answer: the page takes the step Rust names, shows no error and moves nothing', async () => {
    // A stale page: it still shows the CLI step while Rust is at the onboarding step.
    await show(at('cli'));
    const stale = at('onboarding', { error: { class: 'wrong_step', text: null } });
    answer(wizardFinish, stale);
    await click(T.cli_continue);
    expect(wizardFinish).toHaveBeenCalledWith('cli');
    expect(wizardFinish).toHaveBeenCalledTimes(1);
    expect(heading()).toBe(T.onboarding_heading);
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('a step change moves focus to the new heading and announces it', async () => {
    await show(at('cli'));
    const live = () => document.querySelector('[aria-live="polite"]')?.textContent;
    expect(live()).toBe(T.step_announce(T.cli_heading));
    // The first render does not take focus from anything.
    expect(document.activeElement).toBe(document.body);
    answer(wizardFinish, at('onboarding'));
    await click(T.cli_continue);
    expect(live()).toBe(T.step_announce(T.onboarding_heading));
    expect(document.activeElement?.tagName).toBe('H2');
    expect(document.activeElement?.textContent).toBe(T.onboarding_heading);
  });

  it('the loading and failed views offer Quit', async () => {
    vi.mocked(wizardState).mockRejectedValue({ kind: 'not_ready' });
    render(<Wizard />);
    await flush();
    expect(screen.getByRole('alert').textContent).toContain(T.load_failed);
    vi.mocked(quit).mockResolvedValue(null);
    await click(T.quit);
    expect(quit).toHaveBeenCalledTimes(1);
  });

  it('the add form sits under the panel heading and says tokens are added in Settings', async () => {
    await show(at('instances'));
    // The form's heading is one level below the panel's (no h2 inside the panel's h2 section).
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual([
      T.instances_heading,
    ]);
    expect(screen.getByRole('heading', { level: 3, name: 'Add an instance' })).toBeTruthy();
    vi.mocked(instanceAdd).mockResolvedValue({ ...WORK, state: 'needs_token' });
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'work' } });
    fireEvent.change(screen.getByLabelText(/Base URL/), { target: { value: 'https://jira.example' } });
    await click('Add instance');
    const done = screen.getByText(T.instance_added);
    expect(done.textContent).not.toMatch(/next/i);
  });

  it('a needs_token row says the token is added in Settings after setup', async () => {
    const waiting: InstanceView = { ...WORK, state: 'needs_token' };
    const ok: InstanceView = { ...WORK, alias: 'other', state: 'ok' };
    await show(at('instances', { instances: [waiting, ok] }));
    expect(screen.getAllByText(T.token_in_settings)).toHaveLength(1);
  });

  it('coalesces a burst of wizard_changed into one re-read', async () => {
    await show(DATA_DIR);
    expect(wizardState).toHaveBeenCalledTimes(1);
    for (let i = 0; i < 5; i++) await emit('wizard_changed');
    await waitFor(() => expect(wizardState).toHaveBeenCalledTimes(2), {
      timeout: REREAD_DEBOUNCE_MS + 1500,
    });
    await new Promise((r) => setTimeout(r, REREAD_DEBOUNCE_MS + 100));
    expect(wizardState).toHaveBeenCalledTimes(2);
  });

  it('ignores a stale re-read that answers after a newer one', async () => {
    await show(DATA_DIR);
    let slow: (s: WizardState) => void = () => undefined;
    vi.mocked(wizardState).mockImplementationOnce(
      () => new Promise<WizardState>((resolve) => (slow = resolve)),
    );
    vi.mocked(wizardState).mockResolvedValueOnce(at('cli'));
    await emit('wizard_changed');
    await waitFor(() => expect(wizardState).toHaveBeenCalledTimes(2), { timeout: 1500 });
    await emit('settings_changed');
    await waitFor(() => expect(wizardState).toHaveBeenCalledTimes(3), { timeout: 1500 });
    await waitFor(() =>
      expect(heading()).toBe(T.cli_heading),
    );
    await act(async () => {
      slow(at('data_dir', { data_dir: null }));
      await Promise.resolve();
    });
    await flush();
    expect(heading()).toBe(T.cli_heading);
  });

  it('instances step: list, skip or continue, add form re-reads', async () => {
    await show(at('instances'));
    expect(screen.getByText(T.instances_none)).toBeTruthy();
    answer(wizardSkipInstances, at('cli'));
    await click(T.instances_skip);
    expect(wizardSkipInstances).toHaveBeenCalledTimes(1);
    expect(heading()).toBe(T.cli_heading);
  });

  it('instances step with entries says Continue and renders Rust strings as text', async () => {
    const hostile: InstanceView = {
      ...WORK,
      alias: 'w\u202Eork',
      note: '<img src=x onerror=alert(1)>',
      state: 'instance_unconfirmed',
      pending_url_change: 'https://evil.example/<b>x</b>',
    };
    await show(at('instances', { instances: [hostile] }));
    expect(screen.getByRole('button', { name: T.instances_continue })).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('b')).toBeNull();
    // The bidi override in the alias is flagged, the note is quoted and marked unverified.
    expect(screen.getAllByText('unusual characters').length).toBeGreaterThan(0);
    expect(screen.getByText('unverified')).toBeTruthy();
    vi.mocked(instanceConfirmConfig).mockResolvedValue({ ...hostile, state: 'ok' });
    await click(T.confirm);
    expect(instanceConfirmConfig).toHaveBeenCalledWith('w\u202Eork');
    vi.mocked(instanceAcceptUrlChange).mockResolvedValue({ ...hostile, pending_url_change: null });
    await click(T.url_change_accept);
    expect(instanceAcceptUrlChange).toHaveBeenCalledTimes(1);
  });

  it('adding an instance re-reads the wizard state', async () => {
    await show(at('instances'));
    vi.mocked(instanceAdd).mockResolvedValue({ ...WORK, state: 'needs_token' });
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'work' } });
    fireEvent.change(screen.getByLabelText(/Base URL/), { target: { value: 'https://jira.example' } });
    vi.mocked(wizardState).mockResolvedValue(INSTANCES);
    await click('Add instance');
    expect(instanceAdd).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByRole('rowheader', { name: /work/ })).toBeTruthy());
  });

  it('cli step installs, shows the fixed outcome text and continues one step', async () => {
    await show(at('cli'));
    vi.mocked(cliInstall).mockResolvedValue({ outcome: 'installed' });
    await click(T.cli_install);
    expect(screen.getByText(/Open a new terminal/)).toBeTruthy();
    answer(wizardFinish, at('onboarding'));
    await click(T.cli_continue);
    expect(wizardFinish).toHaveBeenCalledTimes(1);
  });

  it('onboarding_text_rendered_as_text: the step shows the snippet as one text node, never markup', async () => {
    const hostile = '# atlas-duck\n<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>';
    vi.mocked(onboardingText).mockResolvedValue({ text: hostile });
    await show(at('onboarding'));
    const section = screen.getByRole('region', { name: T.onboarding_heading });
    const pre = within(section).getByLabelText('Instructions for your agents');
    expect(pre.tagName).toBe('PRE');
    expect(pre.textContent).toBe(hostile);
    expect(pre.childElementCount).toBe(0);
    expect(section.querySelector('img, script')).toBeNull();
    expect(onboardingText).toHaveBeenCalledTimes(1);
    // The finish button is still there beside it.
    expect(within(section).getByRole('button', { name: T.onboarding_finish })).toBeTruthy();
  });

  it('onboarding step: a failed load is a fixed alert with a retry, and finishing stays possible', async () => {
    vi.mocked(onboardingText).mockRejectedValueOnce({ kind: 'internal' });
    await show(at('onboarding'));
    const section = screen.getByRole('region', { name: T.onboarding_heading });
    expect(within(section).getByRole('alert').textContent).toContain('Could not load the instructions');
    expect(within(section).getByRole('button', { name: T.onboarding_finish })).toBeTruthy();
    vi.mocked(onboardingText).mockResolvedValueOnce({ text: 'second try' });
    await click('Try again');
    expect(within(section).getByLabelText('Instructions for your agents').textContent).toBe('second try');
  });
});
