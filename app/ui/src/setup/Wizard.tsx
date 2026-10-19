import { useCallback, useEffect, useRef, useState } from 'react';

import { on } from '../shared/ipc/events';
import {
  cliInstall,
  quit,
  wizardAnchorDir,
  wizardAnchorDirClear,
  wizardBegin,
  wizardChooseDir,
  wizardFinish,
  wizardRestore,
  wizardSkipInstances,
  wizardState,
  wizardUseDefaultDir,
} from '../shared/ipc/invoke';
import type { CliInstallAnswer, WizardError, WizardState, WizardStep } from '../shared/ipc/types';
import { SETTINGS_TEXT, WINDOW_TITLES } from '../shared/strings';
import { InstanceForm } from '../settings/InstanceForm';
import { OnboardingText } from '../onboarding/OnboardingText';
import { Cfg, own } from '../settings/text';
import { useAction, useWindowBusy, WindowBusyContext } from '../settings/useAction';
import { SetupInstances } from './SetupInstances';
import { SETUP_TEXT as T } from './text';

/** `wizard_changed` fires on every refused request: bursts are coalesced into one re-read. */
export const REREAD_DEBOUNCE_MS = 150;
/** Steps 0 destroys the calling window; a failure shows only if the window is still there after this. */
export const STEP0_ERROR_DELAY_MS = 400;
/**
 * After a step ended, the next step's buttons stay off this long: a second click of a double click
 * would otherwise land on the next panel's button (Rust refuses a request for another step than the
 * page rendered, `wrong_step`, but this click names the step it hit). The buttons look disabled, so
 * a click is never swallowed without a cue (T24 review I-1, M-3).
 */
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
  const [settling, setSettling] = useState(false);
  const settleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const panel = useRef<HTMLDivElement>(null);
  const shown = useRef<WizardStep | null>(null);
  const action = useAction();
  const stepName = state === null ? null : state.step;

  // A step change moves focus to the new step's heading (the live region below says it too).
  useEffect(() => {
    if (stepName === null) return;
    if (shown.current !== null && shown.current !== stepName) {
      panel.current?.querySelector<HTMLElement>('h2')?.focus();
    }
    shown.current = stepName;
  }, [stepName]);

  useEffect(
    () => () => {
      if (settleTimer.current !== null) clearTimeout(settleTimer.current);
    },
    [],
  );

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

  /**
   * Runs one wizard command with the step this page rendered (the commands that move on send it;
   * Rust refuses another one); its answer is the new state, and a re-read follows either way.
   */
  const step: Step = (cmd, opts = {}) => {
    if (state === null) return;
    const rendered = state.step;
    void action
      .run(async () => {
        try {
          return await cmd(rendered);
        } catch (e) {
          // Step 0 destroys this window: an error that arrives while it goes is not shown. A window
          // that is still here after the delay shows it.
          if (opts.destroysWindow === true) await sleep(STEP0_ERROR_DELAY_MS);
          throw e;
        }
      })
      .then((v) => {
        if (v !== undefined) {
          if (opts.settle === true) {
            setSettling(true);
            if (settleTimer.current !== null) clearTimeout(settleTimer.current);
            settleTimer.current = setTimeout(() => setSettling(false), STEP_COOLDOWN_MS);
          }
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
        <Quit />
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
        <p className="visually-hidden" aria-live="polite">
          {T.step_announce(headingOf(state))}
        </p>
        {/* Rust's fixed text once GENESIS recorded a previous chain (PD-167), as a plain text node. */}
        {state.notice === null ? null : <p role="status">{state.notice}</p>}
        <div ref={panel}>
          <Panel state={state} step={step} pending={action.pending || settling} onChanged={reread} />
        </div>
        {action.error === null ? null : <p role="alert">{action.error}</p>}
        <Quit />
      </main>
    </>
  );
}

type Step = (
  cmd: (rendered: WizardStep) => Promise<WizardState>,
  opts?: { destroysWindow?: boolean; settle?: boolean },
) => void;

/** The heading of the step's panel. */
function headingOf(state: WizardState): string {
  switch (state.step) {
    case 'data_dir':
      return T.data_dir_heading;
    case 'existing_store':
      return T.existing_heading;
    case 'anchor_dir':
      return T.anchor_heading;
    case 'restore':
      return T.restore_heading;
    case 'passphrase':
      return T.passphrase_heading;
    case 'genesis':
      return T.genesis_heading;
    case 'pin_retry':
      return T.pin_heading;
    case 'recovery_note':
      return T.note_heading;
    case 'instances':
      return T.instances_heading;
    case 'cli':
      return T.cli_heading;
    case 'onboarding':
      return T.onboarding_heading;
    case 'done':
      return T.done_heading;
    case 'stopped':
      return T.stopped_heading;
  }
}

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
          <h2 tabIndex={-1}>{T.data_dir_heading}</h2>
          <p>{T.data_dir_intro}</p>
          <p>
            {T.data_dir_default}: <Cfg value={state.default_dir} />
          </p>
          <StepError error={state.error} />
          <button
            type="button"
            disabled={pending}
            onClick={() => step(() => wizardUseDefaultDir(), { destroysWindow: true })}
          >
            {T.data_dir_use_default}
          </button>{' '}
          <button
            type="button"
            disabled={pending}
            onClick={() => step(() => wizardChooseDir(), { destroysWindow: true })}
          >
            {T.data_dir_choose}
          </button>
          <p>{T.data_dir_choose_note}</p>
        </section>
      );
    case 'existing_store':
      return (
        <section aria-label={T.existing_heading}>
          <h2 tabIndex={-1}>{T.existing_heading}</h2>
          <p>{T.existing_intro}</p>
          {state.data_dir === null ? null : (
            <p>
              {T.existing_data_dir}: <Cfg value={state.data_dir} />
            </p>
          )}
          <StepError error={state.error} />
          <button type="button" disabled={pending} onClick={() => step(() => wizardBegin())}>
            {T.existing_continue}
          </button>
        </section>
      );
    // M10 T15: placeholder panels so the (1b) steps can be walked; Task 22 owns their UI.
    case 'anchor_dir':
      return (
        <section aria-label={T.anchor_heading}>
          <h2 tabIndex={-1}>{T.anchor_heading}</h2>
          <p>{T.anchor_intro}</p>
          {state.anchor_dir === null ? null : (
            <p>
              {T.anchor_dir}: <Cfg value={state.anchor_dir} />
            </p>
          )}
          <StepError error={state.error} />
          <button type="button" disabled={pending} onClick={() => step(() => wizardAnchorDir())}>
            {T.anchor_choose}
          </button>{' '}
          {state.anchor_dir === null ? null : (
            <>
              <button type="button" disabled={pending} onClick={() => step(() => wizardAnchorDirClear())}>
                {T.anchor_clear}
              </button>{' '}
            </>
          )}
          <button type="button" disabled={pending} onClick={() => step(() => wizardRestore())}>
            {T.restore_offer}
          </button>
          <p>
            <button type="button" disabled={pending} onClick={() => step(() => wizardBegin())}>
              {T.passphrase_begin}
            </button>
          </p>
        </section>
      );
    case 'restore':
      return (
        <section aria-label={T.restore_heading}>
          <h2 tabIndex={-1}>{T.restore_heading}</h2>
          <p role="status">{T.restore_working}</p>
        </section>
      );
    case 'pin_retry':
      return (
        <section aria-label={T.pin_heading}>
          <h2 tabIndex={-1}>{T.pin_heading}</h2>
          {/* Rust's fixed text, shown as a plain text node. */}
          <p role="alert">{state.step_text ?? T.errors.other}</p>
          <button type="button" disabled={pending} onClick={() => step(() => wizardBegin())}>
            {T.pin_retry}
          </button>
        </section>
      );
    case 'passphrase':
      return (
        <section aria-label={T.passphrase_heading}>
          <h2 tabIndex={-1}>{T.passphrase_heading}</h2>
          <p>{T.passphrase_intro}</p>
          <StepError error={state.error} />
          {state.passphrase_window ? (
            <p role="status">{T.passphrase_waiting}</p>
          ) : (
            <button type="button" disabled={pending} onClick={() => step(() => wizardBegin())}>
              {T.passphrase_begin}
            </button>
          )}
        </section>
      );
    case 'genesis':
      return (
        <section aria-label={T.genesis_heading}>
          <h2 tabIndex={-1}>{T.genesis_heading}</h2>
          <p role="status">{T.genesis_working}</p>
        </section>
      );
    case 'recovery_note':
      return (
        <section aria-label={T.note_heading}>
          <h2 tabIndex={-1}>{T.note_heading}</h2>
          <p>{T.note_intro}</p>
          <button type="button" disabled={pending} onClick={() => step((rendered) => wizardFinish(rendered), { settle: true })}>
            {T.continue}
          </button>
        </section>
      );
    case 'instances':
      return (
        <section aria-label={T.instances_heading}>
          <h2 tabIndex={-1}>{T.instances_heading}</h2>
          <p>{T.instances_intro}</p>
          <SetupInstances instances={state.instances} onChanged={onChanged} />
          <InstanceForm
            onAdded={onChanged}
            readOnly={false}
            headingLevel={3}
            addedNeedsToken={T.instance_added}
          />
          <button
            type="button"
            disabled={pending}
            onClick={() => step((rendered) => wizardSkipInstances(rendered), { settle: true })}
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
          <h2 tabIndex={-1}>{T.onboarding_heading}</h2>
          <OnboardingText />
          <button type="button" disabled={pending} onClick={() => step((rendered) => wizardFinish(rendered), { settle: true })}>
            {T.onboarding_finish}
          </button>
        </section>
      );
    case 'done':
      return (
        <section aria-label={T.done_heading}>
          <h2 tabIndex={-1}>{T.done_heading}</h2>
          <p role="status">{T.done_text}</p>
        </section>
      );
    case 'stopped':
      return (
        <section aria-label={T.stopped_heading}>
          <h2 tabIndex={-1}>{T.stopped_heading}</h2>
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
      <h2 tabIndex={-1}>{T.cli_heading}</h2>
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
          onClick={() => step((rendered) => wizardFinish(rendered), { settle: true })}
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
