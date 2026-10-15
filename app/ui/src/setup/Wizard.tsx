import { useCallback, useEffect, useRef, useState } from 'react';

import { on } from '../shared/ipc/events';
import {
  cliInstall,
  quit,
  wizardBegin,
  wizardChooseDir,
  wizardFinish,
  wizardSkipInstances,
  wizardState,
  wizardUseDefaultDir,
} from '../shared/ipc/invoke';
import type { CliInstallAnswer, WizardError, WizardState } from '../shared/ipc/types';
import { SETTINGS_TEXT, WINDOW_TITLES } from '../shared/strings';
import { InstanceForm } from '../settings/InstanceForm';
import { Cfg, own } from '../settings/text';
import { useAction, useWindowBusy, WindowBusyContext } from '../settings/useAction';
import { SetupInstances } from './SetupInstances';
import { SETUP_TEXT as T } from './text';

/** `wizard_changed` fires on every refused request: bursts are coalesced into one re-read. */
export const REREAD_DEBOUNCE_MS = 150;
/** Steps 0 destroys the calling window; a failure shows only if the window is still there after this. */
export const STEP0_ERROR_DELAY_MS = 400;
/** A second click this soon after a step ended is a double click, not a decision (T23 m-3). */
export const STEP_COOLDOWN_MS = 700;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * The first-run wizard window (spec 2.5, PD-77). Rust owns the step: the page renders
 * `wizard_state.step` and never skips, repeats or infers one. It re-reads on `wizard_changed` and
 * `settings_changed` (debounced, newest read wins) and never trusts an event payload as state.
 * Passphrases are not collected here: the credential window does that.
 */
export function Wizard() {
  // One command at a time per window, shared by the step buttons, the instance form and Quit.
  const busy = useWindowBusy();
  return (
    <WindowBusyContext.Provider value={busy}>
      <WizardWindow />
    </WindowBusyContext.Provider>
  );
}

function WizardWindow() {
  const [state, setState] = useState<WizardState | null>(null);
  const [failed, setFailed] = useState(false);
  const [nonce, setNonce] = useState(0);
  const latest = useRef(0);
  const read = useRef<() => void>(() => undefined);
  const cooldown = useRef(0);
  const action = useAction();

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const refresh = () => {
      const mine = ++latest.current;
      wizardState().then(
        (v) => {
          if (live && mine === latest.current) {
            setState(v);
            setFailed(false);
          }
        },
        () => {
          if (live && mine === latest.current) setFailed(true);
        },
      );
    };
    read.current = refresh;
    // The first event of a burst starts the timer; later ones ride on it (no starvation).
    const schedule = () => {
      if (timer !== null) return;
      timer = setTimeout(() => {
        timer = null;
        if (live) refresh();
      }, REREAD_DEBOUNCE_MS);
    };
    const listeners = [
      on('wizard_changed', schedule, { thisWindow: true }),
      on('settings_changed', schedule, { thisWindow: true }),
    ];
    // Read once the listeners are attached, so an event between a read and a listener is not lost.
    void Promise.allSettled(listeners).then(() => {
      if (live) refresh();
    });
    return () => {
      live = false;
      if (timer !== null) clearTimeout(timer);
      for (const l of listeners) void l.then((off) => off()).catch(() => undefined);
    };
  }, [nonce]);

  const reread = useCallback(() => read.current(), []);
  const retry = useCallback(() => setNonce((n) => n + 1), []);

  /** Runs one wizard command; its answer is the new state, and a re-read follows either way. */
  const step = (cmd: () => Promise<WizardState>, opts: { destroysWindow?: boolean; settle?: boolean } = {}) => {
    if (opts.settle === true && Date.now() < cooldown.current) return;
    void action
      .run(async () => {
        try {
          return await cmd();
        } catch (e) {
          // Step 0 destroys this window: an error that arrives while it goes is not shown. A window
          // that is still here after the delay shows it.
          if (opts.destroysWindow === true) await sleep(STEP0_ERROR_DELAY_MS);
          throw e;
        }
      })
      .then((v) => {
        if (v !== undefined) {
          if (opts.settle === true) cooldown.current = Date.now() + STEP_COOLDOWN_MS;
          setState(v);
        }
        reread();
      });
  };

  if (state === null) {
    return (
      <main>
        <h1>{WINDOW_TITLES.setup}</h1>
        {failed ? (
          <p role="alert">
            {T.load_failed}{' '}
            <button type="button" onClick={retry}>
              {T.retry}
            </button>
          </p>
        ) : (
          <p role="status">{T.loading}</p>
        )}
      </main>
    );
  }

  return (
    <>
      <main>
        <header>
          <h1>{WINDOW_TITLES.setup}</h1>
          {state.refused_count === null ? null : <p role="status">{T.required(state.refused_count)}</p>}
        </header>
        {failed ? (
          <p role="alert">
            {T.load_failed}{' '}
            <button type="button" onClick={retry}>
              {T.retry}
            </button>
          </p>
        ) : null}
        <Panel state={state} step={step} pending={action.pending} onChanged={reread} />
        {action.error === null ? null : <p role="alert">{action.error}</p>}
        <Quit />
      </main>
    </>
  );
}

type Step = (
  cmd: () => Promise<WizardState>,
  opts?: { destroysWindow?: boolean; settle?: boolean },
) => void;

/** One panel per `WizardStep`, chosen only by what Rust reported. */
function Panel({
  state,
  step,
  pending,
  onChanged,
}: {
  state: WizardState;
  step: Step;
  pending: boolean;
  onChanged: () => void;
}) {
  switch (state.step) {
    case 'data_dir':
      return (
        <section aria-label={T.data_dir_heading}>
          <h2>{T.data_dir_heading}</h2>
          <p>{T.data_dir_intro}</p>
          <p>
            {T.data_dir_default}: <Cfg value={state.default_dir} />
          </p>
          <StepError error={state.error} />
          <button
            type="button"
            disabled={pending}
            onClick={() => step(wizardUseDefaultDir, { destroysWindow: true })}
          >
            {T.data_dir_use_default}
          </button>{' '}
          <button
            type="button"
            disabled={pending}
            onClick={() => step(wizardChooseDir, { destroysWindow: true })}
          >
            {T.data_dir_choose}
          </button>
          <p>{T.data_dir_choose_note}</p>
        </section>
      );
    case 'existing_store':
      return (
        <section aria-label={T.existing_heading}>
          <h2>{T.existing_heading}</h2>
          <p>{T.existing_intro}</p>
          {state.data_dir === null ? null : (
            <p>
              {T.existing_data_dir}: <Cfg value={state.data_dir} />
            </p>
          )}
          <StepError error={state.error} />
          <button type="button" disabled={pending} onClick={() => step(wizardBegin)}>
            {T.existing_continue}
          </button>
        </section>
      );
    case 'passphrase':
      return (
        <section aria-label={T.passphrase_heading}>
          <h2>{T.passphrase_heading}</h2>
          <p>{T.passphrase_intro}</p>
          <StepError error={state.error} />
          {state.passphrase_window ? (
            <p role="status">{T.passphrase_waiting}</p>
          ) : (
            <button type="button" disabled={pending} onClick={() => step(wizardBegin)}>
              {T.passphrase_begin}
            </button>
          )}
        </section>
      );
    case 'genesis':
      return (
        <section aria-label={T.genesis_heading}>
          <h2>{T.genesis_heading}</h2>
          <p role="status">{T.genesis_working}</p>
        </section>
      );
    case 'recovery_note':
      return (
        <section aria-label={T.note_heading}>
          <h2>{T.note_heading}</h2>
          <p>{T.note_intro}</p>
          <button type="button" disabled={pending} onClick={() => step(wizardFinish, { settle: true })}>
            {T.continue}
          </button>
        </section>
      );
    case 'instances':
      return (
        <section aria-label={T.instances_heading}>
          <h2>{T.instances_heading}</h2>
          <p>{T.instances_intro}</p>
          <SetupInstances instances={state.instances} onChanged={onChanged} />
          <InstanceForm onAdded={onChanged} readOnly={false} />
          <button
            type="button"
            disabled={pending}
            onClick={() => step(wizardSkipInstances, { settle: true })}
          >
            {state.instances.length === 0 ? T.instances_skip : T.instances_continue}
          </button>
        </section>
      );
    case 'cli':
      return <CliStep pending={pending} step={step} />;
    case 'onboarding':
      return (
        <section aria-label={T.onboarding_heading}>
          <h2>{T.onboarding_heading}</h2>
          <p>{T.onboarding_placeholder}</p>
          <button type="button" disabled={pending} onClick={() => step(wizardFinish, { settle: true })}>
            {T.onboarding_finish}
          </button>
        </section>
      );
    case 'done':
      return (
        <section aria-label={T.done_heading}>
          <h2>{T.done_heading}</h2>
          <p role="status">{T.done_text}</p>
        </section>
      );
    case 'stopped':
      return (
        <section aria-label={T.stopped_heading}>
          <h2>{T.stopped_heading}</h2>
          {/* Rust's fixed text (spec 8.6 for the keyring), shown as a plain text node. */}
          <p role="alert">{state.stopped_text ?? T.errors.other}</p>
        </section>
      );
  }
}

function CliStep({ pending, step }: { pending: boolean; step: Step }) {
  const install = useAction();
  const [outcome, setOutcome] = useState<CliInstallAnswer['outcome'] | null>(null);
  return (
    <section aria-label={T.cli_heading}>
      <h2>{T.cli_heading}</h2>
      <p>{T.cli_intro}</p>
      <button
        type="button"
        disabled={pending || install.pending}
        onClick={() =>
          void install.run(() => cliInstall()).then((answer) => {
            if (answer !== undefined) setOutcome(answer.outcome);
          })
        }
      >
        {T.cli_install}
      </button>
      {install.error === null ? null : <p role="alert">{install.error}</p>}
      {outcome === null ? null : <p role="status">{SETTINGS_TEXT.cli_outcomes[outcome]}</p>}
      <p>
        <button
          type="button"
          disabled={pending || install.pending}
          onClick={() => step(wizardFinish, { settle: true })}
        >
          {T.cli_continue}
        </button>
      </p>
    </section>
  );
}

/** The last refused step: a fixed sentence by class (an unknown class is never echoed) and Rust's own text. */
function StepError({ error }: { error: WizardError | null }) {
  if (error === null) return null;
  const known = own(T.errors, error.class) ?? T.errors.other;
  return (
    <p role="alert">
      {known}
      {error.text === null ? null : (
        <>
          {' '}
          <Cfg value={error.text} />
        </>
      )}
    </p>
  );
}

function Quit() {
  const action = useAction();
  return (
    <footer>
      <button type="button" disabled={action.pending} onClick={() => void action.run(() => quit())}>
        {T.quit}
      </button>
      {action.error === null ? null : <p role="alert">{action.error}</p>}
    </footer>
  );
}
