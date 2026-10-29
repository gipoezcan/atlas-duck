import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import {
  anchorDirRemove,
  anchorDirSet,
  backupTrigger,
  cliInstall,
  cliUninstall,
  credentialWindowOpen,
  exportCancel,
  forgetInstall,
  instanceAcceptUrlChange,
  instanceAdd,
  instanceChangeUrl,
  instanceConfirmConfig,
  instanceSetProxy,
  orphanInstalls,
  pruneBacklogNow,
  reAnchor,
  recoveryPassphraseChange,
  removalBackup,
  removalBegin,
  removalExport,
  removalFinish,
  removalMark,
  removalState,
  restoreBegin,
  restoreCancel,
  retestToken,
  settingsApply,
  settingsGet,
} from '../shared/ipc/invoke';
import commandErrorFixtures from '../shared/ipc/fixtures/command_error.json';
import settingsFixture from '../shared/ipc/fixtures/settings_get.json';
import type { InstanceView, SettingsGet } from '../shared/ipc/types';
import { Settings } from './Settings';
import { errorText, expiryWarningText } from './text';

vi.mock('../shared/ipc/invoke', () => ({
  cliInstall: vi.fn(),
  cliUninstall: vi.fn(),
  settingsGet: vi.fn(),
  settingsApply: vi.fn(),
  instanceAdd: vi.fn(),
  instanceChangeUrl: vi.fn(),
  instanceConfirmConfig: vi.fn(),
  instanceAcceptUrlChange: vi.fn(),
  instanceSetProxy: vi.fn(),
  credentialWindowOpen: vi.fn(),
  retestToken: vi.fn(),
  pruneBacklogNow: vi.fn(),
  removalBackup: vi.fn(),
  removalBegin: vi.fn(),
  removalExport: vi.fn(),
  removalFinish: vi.fn(),
  removalMark: vi.fn(),
  removalState: vi.fn(),
  exportCancel: vi.fn(),
  backupTrigger: vi.fn(),
  restoreBegin: vi.fn(),
  restoreCancel: vi.fn(),
  recoveryPassphraseChange: vi.fn(),
  anchorDirSet: vi.fn(),
  anchorDirRemove: vi.fn(),
  reAnchor: vi.fn(),
  orphanInstalls: vi.fn(),
  forgetInstall: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const [FULL, BARE] = settingsFixture as unknown as [SettingsGet, SettingsGet, SettingsGet];
const WORK = FULL.instances[0] as InstanceView;

/** `base` with its first instance replaced and no read-only banner, unless `over` says. */
function plain(inst: Partial<InstanceView>, over: Partial<SettingsGet> = {}): SettingsGet {
  return {
    ...FULL,
    settings: { ...FULL.settings, config_read_only: null, restart_pending: [] },
    instances: [{ ...WORK, pending_url_change: null, note: null, ...inst }],
    ...over,
  };
}

let handlers: ((payload: unknown) => void)[] = [];
/** The handlers by event name (`handlers` holds them all, for `settings_changed`). */
let named = new Map<string, ((payload: unknown) => void)[]>();

async function emitEvent(name: string, payload: unknown): Promise<void> {
  act(() => {
    for (const h of named.get(name) ?? []) h(payload);
  });
  await flush();
}

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

async function show(data: SettingsGet) {
  vi.mocked(settingsGet).mockResolvedValue(data);
  const view = render(<Settings />);
  await flush();
  return view;
}

async function emitChanged(): Promise<void> {
  act(() => {
    for (const h of handlers) h(null);
  });
  await flush();
}

/**
 * The one polite region of the window that says something: the sections that report what a command
 * answered keep an empty region in the page (an inserted region is not announced).
 */
function filledStatus(): HTMLElement {
  const filled = screen.getAllByRole('status').filter((s) => (s.textContent ?? '') !== '');
  expect(filled).toHaveLength(1);
  return filled[0] as HTMLElement;
}

const row = (alias: string): HTMLElement => {
  const cell = screen.getByRole('rowheader', { name: new RegExp(alias) });
  return cell.closest('tr') as HTMLElement;
};

beforeEach(() => {
  handlers = [];
  named = new Map();
  vi.mocked(on)
    .mockReset()
    .mockImplementation((name, handler) => {
      handlers.push(handler as (payload: unknown) => void);
      named.set(name, [...(named.get(name) ?? []), handler as (payload: unknown) => void]);
      return Promise.resolve(() => undefined);
    });
  for (const f of [
    anchorDirRemove,
    anchorDirSet,
    backupTrigger,
    exportCancel,
    forgetInstall,
    reAnchor,
    recoveryPassphraseChange,
    removalExport,
    restoreBegin,
    restoreCancel,
    cliInstall,
    cliUninstall,
    settingsApply,
    instanceAdd,
    instanceChangeUrl,
    instanceConfirmConfig,
    instanceAcceptUrlChange,
    instanceSetProxy,
    credentialWindowOpen,
    retestToken,
    pruneBacklogNow,
    removalBackup,
    removalBegin,
    removalFinish,
    removalMark,
  ]) {
    vi.mocked(f as (...a: unknown[]) => Promise<unknown>).mockReset();
  }
  vi.mocked(settingsGet).mockReset();
  vi.mocked(orphanInstalls).mockReset().mockResolvedValue([]);
  // "Prepare for removal" has its own tests (Removal.test.tsx): here it is the idle entry.
  vi.mocked(removalState)
    .mockReset()
    .mockResolvedValue({
      active: false,
      recorded: false,
      backup_made: false,
      retention_days: 92,
      legal_hold: false,
      retention_left_days: 92,
      instances: [],
    });
});

describe('Settings', () => {
  it('listens to settings_changed for this window only and re-reads on it', async () => {
    await show(plain({}));
    expect(vi.mocked(on).mock.calls[0]?.[0]).toBe('settings_changed');
    expect(vi.mocked(on).mock.calls[0]?.[2]).toEqual({ thisWindow: true });
    expect(settingsGet).toHaveBeenCalledTimes(1);
    await emitChanged();
    expect(settingsGet).toHaveBeenCalledTimes(2);
  });

  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'an instance state named like an object member (%s) is shown as configured text',
    async (state) => {
      await show(plain({ state }));
      expect(within(row('work')).getByText(state)).toBeTruthy();
    },
  );

  it('needs_token_offers_retest_before_replace', async () => {
    await show(plain({ state: 'needs_token' }));
    const r = within(row('work'));
    const retest = r.getByRole('button', { name: 'Re-test stored token' });
    const replace = r.getByRole('button', { name: 'Replace token' });
    // Document order: the re-test comes first (spec 7.1).
    expect(retest.compareDocumentPosition(replace) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    vi.mocked(retestToken).mockResolvedValue({
      ok: { atlassian_user: 'alice', product: 'jira', version: '9.12.0', warnings: [] },
    });
    fireEvent.click(retest);
    await flush();
    expect(retestToken).toHaveBeenCalledWith('work');
    expect(r.getByText(/Connected as/).textContent).toContain('alice');

    vi.mocked(credentialWindowOpen).mockResolvedValue(null);
    fireEvent.click(replace);
    await flush();
    expect(credentialWindowOpen).toHaveBeenCalledWith('work', 'replace_pat');
  });

  it('a needs_token instance without an identity offers Add token, an ok one only Replace', async () => {
    await show(plain({ state: 'needs_token', executes_as: null }));
    vi.mocked(credentialWindowOpen).mockResolvedValue(null);
    fireEvent.click(within(row('work')).getByRole('button', { name: 'Add token' }));
    await flush();
    expect(credentialWindowOpen).toHaveBeenCalledWith('work', 'add_pat');
    expect(within(row('work')).getByRole('button', { name: 'Re-test stored token' })).toBeTruthy();
  });

  it('identity header states show the admin text and offer re-test but no replace', async () => {
    for (const state of ['identity_header_missing', 'identity_header_mismatch']) {
      const { unmount } = await show(plain({ state }));
      const r = within(row('work'));
      expect(r.getByText(/X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator/)).toBeTruthy();
      expect(r.getByRole('button', { name: 'Re-test stored token' })).toBeTruthy();
      expect(r.queryByRole('button', { name: 'Replace token' })).toBeNull();
      unmount();
    }
  });

  it('a failed re-test shows a fixed class text, an unknown class as a fixed generic text', async () => {
    await show(plain({ state: 'needs_token' }));
    vi.mocked(retestToken).mockResolvedValue({ failed: { class: 'other_user' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    expect(filledStatus().textContent).toContain('the token now belongs to another user');
    vi.mocked(retestToken).mockResolvedValue({ failed: { class: 'x\u202ey' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    // An unknown class is fixed text: the wire name is not echoed.
    expect(filledStatus().textContent).toContain('does not recognize');
    expect(filledStatus().textContent).not.toContain('x\u202ey');
  });

  it('pending URL change banner is verbatim and accept calls the command', async () => {
    await show(plain({ pending_url_change: 'https://jira.example/moved' }));
    const banner = screen.getByText(/config\.toml requests a URL change for/);
    expect(banner.textContent).toBe('config.toml requests a URL change for work');
    expect(screen.getByText(/https:\/\/jira\.example\/moved/)).toBeTruthy();
    vi.mocked(instanceAcceptUrlChange).mockResolvedValue({ ...WORK, pending_url_change: null });
    fireEvent.click(screen.getByRole('button', { name: 'Accept the URL change' }));
    await flush();
    expect(instanceAcceptUrlChange).toHaveBeenCalledWith('work');
    expect(settingsGet).toHaveBeenCalled();
  });

  it('unconfirmed instance offers Confirm and no token button', async () => {
    await show(plain({ state: 'instance_unconfirmed', origin: null, executes_as: null }));
    const r = within(row('work'));
    expect(r.queryByRole('button', { name: /token/i })).toBeNull();
    vi.mocked(instanceConfirmConfig).mockResolvedValue(WORK);
    fireEvent.click(r.getByRole('button', { name: 'Confirm instance' }));
    await flush();
    expect(instanceConfirmConfig).toHaveBeenCalledWith('work');
  });

  it('insecure_scheme shows the fixed https hint', async () => {
    await show(plain({ state: 'insecure_scheme' }));
    expect(
      screen.getByText(
        "atlas-duck requires https; if your server uses an internal CA, add it as the instance's custom CA",
      ),
    ).toBeTruthy();
  });

  it('read_only_config_disables_config_writing_controls_with_banner', async () => {
    await show(FULL);
    expect(
      screen.getByText(/config written by v9\.9\.0; settings read-only until you upgrade/),
    ).toBeTruthy();
    const controls = [...document.querySelectorAll('input, select, button, textarea')];
    expect(controls.length).toBeGreaterThan(8);
    const open = controls.filter((c) => !c.matches(':disabled')).map((c) => c.textContent);
    // Only the token, re-test, prune, CLI, removal, backup/restore, passphrase, anchor and forget
    // buttons stay on: core refuses ConfigReadOnly for what writes config.toml; the CLI install,
    // "Prepare for removal" and the M10 recovery tier act on the audit store and keychain only.
    // The Help buttons (M16) only open the guide.
    for (const c of controls) {
      const name = c.textContent ?? '';
      // The degraded toggle is audit-authoritative, not a config.toml key: it stays on (PD-141).
      const degraded = c.closest('label')?.textContent === 'Allow scripts with degraded confinement';
      // M15 T3: the UI language is app-side (`ui-lang`), not a config.toml key: it stays on.
      const language = c.closest('section')?.getAttribute('aria-label') === 'Language';
      const stays =
        degraded ||
        language ||
        /token|Re-test|Prune backlog|CLI|full backup|Export the audit log|Back up now|Restore backup|recovery passphrase|anchor directory|Re-anchor|Forget|^Help$|^\?$/.test(
          name,
        );
      expect(c.matches(':disabled'), c.outerHTML).toBe(!stays);
    }
    expect(open.length).toBeGreaterThan(0);
  });

  it('read-only config keeps Re-test and Add/Replace token on for a needs_token instance', async () => {
    const banner = FULL.settings.config_read_only;
    await show(
      plain(
        { state: 'needs_token', executes_as: null },
        { settings: { ...FULL.settings, config_read_only: banner } },
      ),
    );
    const r = within(row('work'));
    expect(r.getByRole('button', { name: 'Re-test stored token' }).matches(':disabled')).toBe(false);
    expect(r.getByRole('button', { name: 'Add token' }).matches(':disabled')).toBe(false);
    expect(r.getByRole('button', { name: 'Apply URL change' }).matches(':disabled')).toBe(true);
    expect(r.getByRole('button', { name: 'Apply proxy' }).matches(':disabled')).toBe(true);
    vi.mocked(credentialWindowOpen).mockResolvedValue(null);
    fireEvent.click(r.getByRole('button', { name: 'Add token' }));
    await flush();
    expect(credentialWindowOpen).toHaveBeenCalledWith('work', 'add_pat');
  });

  it('without the banner the form is enabled (the pair of the test above)', async () => {
    await show(BARE);
    expect(screen.getByRole('button', { name: 'Add instance' }).matches(':disabled')).toBe(false);
    expect(screen.queryByText(/Settings are read-only/)).toBeNull();
  });

  it('limits_restart_markers', async () => {
    await show(plain({}, { settings: { ...FULL.settings, config_read_only: null } }));
    const field = (label: string) => screen.getByLabelText(label).closest('.field') as HTMLElement;
    for (const label of [
      'Candidate cache (MB)',
      'Pending bytes cap (MB, empty = off)',
      'Request expiry (hours)',
    ]) {
      expect(field(label).textContent).toContain('applies after restart');
    }
    expect(field('Jira comments cap').textContent).not.toContain('applies after restart');
    // The key core lists as pending also says its new value waits for the next start.
    expect(field('Candidate cache (MB)').textContent).toContain('waiting for the next start');
    expect(field('Request expiry (hours)').textContent).not.toContain('waiting');
    expect((screen.getByLabelText('Pending bytes cap (MB, empty = off)') as HTMLInputElement).value).toBe('512');
  });

  it('a null max_pending_bytes_mb shows an empty field and is sent as null when cleared', async () => {
    await show(plain({}, { settings: { ...BARE.settings } }));
    const input = screen.getByLabelText('Pending bytes cap (MB, empty = off)') as HTMLInputElement;
    expect(input.value).toBe('');
    vi.mocked(settingsApply).mockResolvedValue(BARE.settings);
    fireEvent.change(input, { target: { value: '300' } });
    fireEvent.click(within(screen.getByRole('region', { name: 'Limits' })).getByRole('button', { name: 'Apply' }));
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'max_pending_bytes_mb', value: 300 }]);
    fireEvent.change(input, { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Jira comments cap'), { target: { value: '60' } });
    fireEvent.click(within(screen.getByRole('region', { name: 'Limits' })).getByRole('button', { name: 'Apply' }));
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'jira_comments_cap', value: 60 }]);
  });

  it('limits send only changed fields, refuse non-numbers locally, show core refusals as text', async () => {
    await show(plain({}));
    const region = screen.getByRole('region', { name: 'Limits' });
    const apply = () => fireEvent.click(within(region).getByRole('button', { name: 'Apply' }));
    fireEvent.change(screen.getByLabelText('Jira comments cap'), { target: { value: 'abc' } });
    apply();
    await flush();
    expect(settingsApply).not.toHaveBeenCalled();
    expect(within(region).getByRole('alert').textContent).toBe('Enter a whole number');

    fireEvent.change(screen.getByLabelText('Jira comments cap'), { target: { value: '5000' } });
    vi.mocked(settingsApply).mockRejectedValue({
      kind: 'settings',
      error: { kind: 'invalid', key: 'jira_comments_cap' },
    });
    apply();
    await flush();
    expect(settingsApply).toHaveBeenCalledWith([{ key: 'jira_comments_cap', value: 5000 }]);
    expect(within(region).getByRole('alert').textContent).toBe('Check the value of Jira comments cap');
    // The refused text stays in the field.
    expect((screen.getByLabelText('Jira comments cap') as HTMLInputElement).value).toBe('5000');
  });

  it('typed limits survive a settings_changed re-read', async () => {
    await show(plain({}));
    fireEvent.change(screen.getByLabelText('Jira comments cap'), { target: { value: '77' } });
    vi.mocked(settingsGet).mockResolvedValue(plain({}));
    await emitChanged();
    expect((screen.getByLabelText('Jira comments cap') as HTMLInputElement).value).toBe('77');
  });

  it('retention, hold and attention mode go through settings_apply; cancelled is text', async () => {
    await show(plain({}));
    vi.mocked(settingsApply).mockResolvedValue(FULL.settings);
    fireEvent.change(screen.getByLabelText('Audit retention (days)'), { target: { value: '400' } });
    fireEvent.click(within(screen.getByRole('region', { name: 'Retention and legal hold' })).getAllByRole('button', { name: 'Apply' })[0] as HTMLElement);
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'retention_days', value: 400 }]);

    vi.mocked(settingsApply).mockRejectedValue({ kind: 'settings', error: { kind: 'cancelled' } });
    fireEvent.click(screen.getByLabelText('Legal hold (pruning stops)'));
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'legal_hold', value: false }]);
    expect(screen.getByText('Cancelled: nothing was changed')).toBeTruthy();

    vi.mocked(settingsApply).mockResolvedValue(FULL.settings);
    fireEvent.change(screen.getByLabelText('Attention mode'), { target: { value: 'show_and_focus' } });
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'attention_mode', value: 'show_and_focus' }]);
    expect(screen.getByText(/Presentation mode is a toggle in the tray menu/)).toBeTruthy();
  });

  it('prune backlog line and button run the command and show the report', async () => {
    await show(plain({}));
    expect(screen.getByText('pruning is 12 days behind')).toBeTruthy();
    vi.mocked(pruneBacklogNow).mockResolvedValue({ result: 'pruned', count: 42, cutoff: '2026-07-15', clamped: true });
    fireEvent.click(screen.getByRole('button', { name: 'Prune backlog now' }));
    await flush();
    expect(screen.getByText(/Pruned 42 record\(s\) older than 2026-07-15/)).toBeTruthy();
    vi.mocked(pruneBacklogNow).mockResolvedValue({ result: 'skipped', reason: 'legal_hold' });
    fireEvent.click(screen.getByRole('button', { name: 'Prune backlog now' }));
    await flush();
    expect(screen.getByText(/Pruning was skipped: legal hold is on/)).toBeTruthy();
  });

  it('no backlog line, no prune button', async () => {
    await show(BARE);
    expect(screen.queryByRole('button', { name: 'Prune backlog now' })).toBeNull();
  });

  it('confinement verdicts', async () => {
    const { unmount } = await show(plain({}));
    expect(screen.getByText('met: scripts may run')).toBeTruthy();
    expect(screen.getByText(/landlock/)).toBeTruthy();
    unmount();
    const second = await show({ ...BARE, settings: { ...BARE.settings } });
    expect(screen.getByText('not met: scripts are off')).toBeTruthy();
    expect(screen.getByText(/connect_loopback/)).toBeTruthy();
    second.unmount();
    await show({
      ...BARE,
      confinement: {
        state: 'pending',
        failed: [],
        mode: 'n/a',
        extra_layers: [],
        scripts: 'disabled',
        degraded_allowed: false,
      },
    });
    expect(screen.getByText('the startup probe has not finished')).toBeTruthy();
  });

  /** FULL with the confinement and the degraded setting replaced, and no read-only banner. */
  const scriptsView = (
    confinement: Partial<SettingsGet['confinement']>,
    allow: boolean,
    readOnly = false,
  ): SettingsGet =>
    plain(
      {},
      {
        confinement: { ...FULL.confinement, ...confinement },
        settings: {
          ...FULL.settings,
          config_read_only: readOnly ? { kind: 'read_only', text: 'newer config' } : null,
          restart_pending: [],
          allow_degraded_scripts: allow,
        },
      },
    );
  const NOT_MET: Partial<SettingsGet['confinement']> = {
    state: 'not_met',
    failed: ['cred_read'],
    mode: 'lpac',
  };

  it('confinement_scripts_state_rendered', async () => {
    const states: [Partial<SettingsGet['confinement']>, string][] = [
      [{}, 'Scripts are enabled'],
      [{ ...NOT_MET, scripts: 'disabled' }, 'Scripts are disabled'],
      [{ ...NOT_MET, scripts: 'degraded', degraded_allowed: true }, 'Scripts are enabled with degraded confinement'],
      [{ state: 'pending', failed: [], mode: 'n/a', extra_layers: [], scripts: 'disabled' }, 'Scripts are disabled'],
    ];
    for (const [confinement, text] of states) {
      const { unmount } = await show(scriptsView(confinement, false));
      const region = screen.getByRole('region', { name: 'Script confinement' });
      expect(within(region).getByText(text)).toBeTruthy();
      // Exactly one of the three state lines is shown.
      for (const other of ['Scripts are enabled', 'Scripts are disabled', 'Scripts are enabled with degraded confinement']) {
        expect(within(region).queryAllByText(other).length).toBe(other === text ? 1 : 0);
      }
      unmount();
    }
  });

  it('script_limits_restart_pending_is_shown_and_default_hint_is_described_by', async () => {
    await show(
      plain({}, { settings: { ...FULL.settings, config_read_only: null, restart_pending: ['script_limits'] } }),
    );
    const region = screen.getByRole('region', { name: 'Script limits' });
    expect(within(region).getByText('a changed value is waiting for the next start')).toBeTruthy();
    const input = within(region).getByLabelText('Script call limit');
    const hint = document.getElementById(input.getAttribute('aria-describedby') ?? '');
    expect(hint?.textContent).toContain('default 200');
  });

  it('confinement_degraded_shows_one_accurate_verdict', async () => {
    await show(scriptsView({ ...NOT_MET, scripts: 'degraded', degraded_allowed: true }, true));
    const region = screen.getByRole('region', { name: 'Script confinement' });
    expect(
      within(region).getByText('not met: scripts run only because degraded confinement is allowed'),
    ).toBeTruthy();
    // The "scripts are off" verdict would contradict the state line beside it.
    expect(within(region).queryByText('not met: scripts are off')).toBeNull();
    expect(within(region).getByText('Scripts are enabled with degraded confinement')).toBeTruthy();
  });

  it('degraded_toggle_shows_persistent_warning', async () => {
    const caution = 'scripts run with degraded confinement';
    const toggle = () => screen.getByLabelText('Allow scripts with degraded confinement') as HTMLInputElement;
    // Off: unchecked, no caution.
    const off = await show(scriptsView({ ...NOT_MET, scripts: 'disabled' }, false));
    expect(toggle().checked).toBe(false);
    expect(screen.queryByText(caution)).toBeNull();

    // Click: one settings_apply change; Rust confirms natively, a cancel is text and the box stays off.
    vi.mocked(settingsApply).mockRejectedValue({ kind: 'settings', error: { kind: 'cancelled' } });
    fireEvent.click(toggle());
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'allow_degraded_scripts', value: true }]);
    expect(screen.getByText('Cancelled: nothing was changed')).toBeTruthy();
    expect(toggle().checked).toBe(false);
    expect(screen.queryByText(caution)).toBeNull();
    off.unmount();

    // On and the floor not met: checked, the caution stays (a re-read does not remove it, it has no
    // dismiss), and turning it off is the same command with false.
    const on_ = await show(scriptsView({ ...NOT_MET, scripts: 'degraded', degraded_allowed: true }, true));
    expect(toggle().checked).toBe(true);
    expect(screen.getByText(caution)).toBeTruthy();
    vi.mocked(settingsGet).mockResolvedValue(
      scriptsView({ ...NOT_MET, scripts: 'degraded', degraded_allowed: true }, true),
    );
    await emitChanged();
    expect(screen.getByText(caution)).toBeTruthy();
    vi.mocked(settingsApply).mockReset().mockResolvedValue(FULL.settings);
    fireEvent.click(toggle());
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([{ key: 'allow_degraded_scripts', value: false }]);
    on_.unmount();

    // On while the floor is met: nothing runs degraded, so no caution, and the note says why.
    const met = await show(scriptsView({}, true));
    expect(toggle().checked).toBe(true);
    expect(screen.queryByText(caution)).toBeNull();
    expect(screen.getByText('Allowed, but not in use: the confinement floor is met.')).toBeTruthy();
    met.unmount();

    // The toggle is audit-authoritative, not a config.toml key: a read-only config leaves it on.
    await show(scriptsView({ ...NOT_MET, scripts: 'disabled' }, false, true));
    expect(toggle().matches(':disabled')).toBe(false);
  });

  it('script_limits_inputs_and_rust_errors', async () => {
    const LABELS = [
      ['timeout_s', 'Script timeout (s)', '120'],
      ['heap_mb', 'Script heap limit (MiB)', '256'],
      ['process_mb', 'Script process limit (MiB)', '512'],
      ['max_calls', 'Script call limit', '200'],
      ['max_fetch_mb', 'Script fetch limit (MiB)', '50'],
      ['max_call_result_mb', 'Script call result limit (MiB)', '16'],
      ['max_result_mb', 'Script result limit (MiB)', '16'],
      ['max_concurrent_calls', 'Script concurrent calls', '4'],
    ] as const;
    // Configured values (not the defaults) fill the inputs; the default is the hint beside each.
    const configured = { ...FULL.settings.limits.script, timeout_s: 90, max_calls: 150 };
    await show(
      plain({}, { settings: { ...FULL.settings, config_read_only: null, limits: { ...FULL.settings.limits, script: configured } } }),
    );
    const region = screen.getByRole('region', { name: 'Script limits' });
    expect(within(region).getAllByRole('textbox').length).toBe(8);
    for (const [key, label, dflt] of LABELS) {
      const input = within(region).getByLabelText(label) as HTMLInputElement;
      expect(input.value).toBe(String(configured[key]));
      const field = input.closest('.field') as HTMLElement;
      expect(field.textContent).toContain(`default ${dflt}`);
      // Script limits apply to the next run at once: no restart marker.
      expect(field.textContent).not.toContain('applies after restart');
    }
    const apply = () => fireEvent.click(within(region).getByRole('button', { name: 'Apply' }));

    // Nothing edited: nothing sent. A non-number is refused locally.
    apply();
    await flush();
    expect(settingsApply).not.toHaveBeenCalled();
    fireEvent.change(within(region).getByLabelText('Script call limit'), { target: { value: 'abc' } });
    apply();
    await flush();
    expect(settingsApply).not.toHaveBeenCalled();
    expect(within(region).getByRole('alert').textContent).toBe('Enter a whole number');

    // Only the changed keys go, in one script_limits change; Rust's refusal is text and the typed
    // value stays.
    fireEvent.change(within(region).getByLabelText('Script call limit'), { target: { value: '150' } });
    fireEvent.change(within(region).getByLabelText('Script heap limit (MiB)'), { target: { value: '9000' } });
    fireEvent.change(within(region).getByLabelText('Script result limit (MiB)'), { target: { value: '17' } });
    vi.mocked(settingsApply).mockRejectedValue({ kind: 'settings', error: { kind: 'invalid', key: 'heap_mb' } });
    apply();
    await flush();
    expect(settingsApply).toHaveBeenLastCalledWith([
      { key: 'script_limits', value: { heap_mb: 9000, max_result_mb: 17 } },
    ]);
    expect(within(region).getByRole('alert').textContent).toBe('Check the value of Script heap limit (MiB)');
    expect((within(region).getByLabelText('Script heap limit (MiB)') as HTMLInputElement).value).toBe('9000');

    // Rust's own bound refusal names the limit (the argument's field), also as text.
    vi.mocked(settingsApply).mockRejectedValue({ kind: 'invalid_argument', field: 'max_result_mb' });
    apply();
    await flush();
    expect(within(region).getByRole('alert').textContent).toBe('Check the value of Script result limit (MiB)');

    // A raise is confirmed natively by Rust: a cancel is text; an applied change clears the drafts.
    vi.mocked(settingsApply).mockRejectedValue({ kind: 'settings', error: { kind: 'cancelled' } });
    apply();
    await flush();
    expect(within(region).getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
    vi.mocked(settingsApply).mockResolvedValue(FULL.settings);
    apply();
    await flush();
    expect(within(region).getByRole('status').textContent).toBe('Applied');
    expect(within(region).queryByRole('alert')).toBeNull();
  });

  it('script limits are off under a read-only config', async () => {
    await show(scriptsView({}, false, true));
    const region = screen.getByRole('region', { name: 'Script limits' });
    for (const input of within(region).getAllByRole('textbox')) {
      expect(input.matches(':disabled')).toBe(true);
    }
  });

  it('the CLI button follows cli_installed and calls the matching command with no arguments', async () => {
    const { unmount } = await show(plain({}, { cli_installed: false, cli_dir_on_path: false }));
    const install = screen.getByRole('button', { name: 'Install CLI to PATH' }) as HTMLButtonElement;
    expect(install.disabled).toBe(false);
    expect(screen.getByText('The atlas-duck command is not on your PATH.')).toBeTruthy();
    vi.mocked(cliInstall).mockResolvedValue({ outcome: 'installed' });
    fireEvent.click(install);
    await flush();
    expect(cliInstall).toHaveBeenCalledTimes(1);
    expect(cliInstall).toHaveBeenCalledWith();
    expect(cliUninstall).not.toHaveBeenCalled();
    expect(filledStatus().textContent).toContain('Open a new terminal');
    // The window re-reads: the state shown is Rust's, not a local guess.
    expect(settingsGet).toHaveBeenCalledTimes(2);
    unmount();

    await show(plain({}, { cli_installed: true }));
    expect(screen.getByText('The atlas-duck command is on your PATH.')).toBeTruthy();
    vi.mocked(cliUninstall).mockResolvedValue({ outcome: 'removed' });
    fireEvent.click(screen.getByRole('button', { name: 'Remove CLI from PATH' }));
    await flush();
    expect(cliUninstall).toHaveBeenCalledTimes(1);
    expect(cliUninstall).toHaveBeenCalledWith();
    expect(cliInstall).toHaveBeenCalledTimes(1);
    expect(filledStatus().textContent).toContain('Removed');
  });

  it('the CLI status line follows cli_dir_on_path (T36b: path-aware, never over-asserts)', async () => {
    const cases: [boolean, boolean | null, string][] = [
      // installed: the folder is on the PATH, the PATH is unknown, or this app's PATH lacks it.
      [true, true, 'The atlas-duck command is on your PATH.'],
      [true, null, 'The atlas-duck command is on your PATH.'],
      [
        true,
        false,
        'The atlas-duck command is installed, but its folder is not on the PATH this app was started with. A terminal you open may still find it; if it does not, add that folder to the PATH of your shell.',
      ],
      // not installed: nothing there, or the folder is on the PATH already (the user's own entry).
      [false, false, 'The atlas-duck command is not on your PATH.'],
      [false, null, 'The atlas-duck command is not on your PATH.'],
      [
        false,
        true,
        'The folder for the atlas-duck command is already on your PATH, but the install is not complete yet. Use the button to finish it.',
      ],
    ];
    for (const [installed, onPath, text] of cases) {
      const { unmount } = await show(
        plain({}, { cli_installed: installed, cli_removable: true, cli_dir_on_path: onPath }),
      );
      expect(screen.getByText(text), `${installed} ${onPath}`).toBeTruthy();
      // Only one of the status sentences is shown.
      expect(screen.queryAllByText(/^The (atlas-duck command|folder for the atlas-duck)/)).toHaveLength(1);
      unmount();
    }
    // deb/rpm keeps the package sentence whatever the field says.
    await show(plain({}, { cli_installed: true, cli_removable: false, cli_dir_on_path: null }));
    expect(screen.getByText(/comes with the package and is already on your PATH/)).toBeTruthy();
  });

  it('every CLI outcome has its own fixed text', async () => {
    const seen = new Set<string>();
    for (const outcome of [
      'installed',
      'installed_local_bin',
      'installed_local_bin_on_path',
      'replaced_stale_entry',
      'already_installed',
      'removed',
      'already_on_path',
    ] as const) {
      const { unmount } = await show(plain({}, { cli_installed: false }));
      vi.mocked(cliInstall).mockResolvedValue({ outcome });
      fireEvent.click(screen.getByRole('button', { name: 'Install CLI to PATH' }));
      await flush();
      const text = filledStatus().textContent ?? '';
      expect(text.length).toBeGreaterThan(10);
      seen.add(text);
      if (outcome === 'installed_local_bin') {
        // `~/.local/bin` is not on every default PATH: the text says where it went and what to do.
        expect(text).toContain('~/.local/bin');
        expect(text).toMatch(/does not find the atlas-duck command/);
        expect(text).toMatch(/log out and in again/);
        // The app sees only its own PATH, so the text does not assert what the terminals have.
        expect(text).toContain('might not be on the PATH of the terminals you open');
        expect(text).not.toContain('not on your PATH');
      } else if (outcome === 'installed_local_bin_on_path') {
        // PD-177: the directory is on the PATH this app runs with, so the text claims nothing to fix.
        expect(text).toContain('~/.local/bin, which is on the PATH this app was started with');
        expect(text).not.toContain('might not be on the PATH');
        expect(text).not.toMatch(/log out and in again/);
      } else {
        expect(text).not.toContain('~/.local/bin');
      }
      if (outcome === 'replaced_stale_entry') {
        expect(text).toMatch(/earlier atlas-duck folder that no longer exists was removed/);
      }
      unmount();
    }
    expect(seen.size).toBe(7);
  });

  it('deb/rpm: no removal button, the package sentence is the status', async () => {
    await show(plain({}, { cli_installed: true, cli_removable: false }));
    expect(screen.queryByRole('button', { name: 'Remove CLI from PATH' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Install CLI to PATH' })).toBeNull();
    expect(screen.getByText(/comes with the package and is already on your PATH/)).toBeTruthy();
    expect(cliUninstall).not.toHaveBeenCalled();
  });

  it('a removable CLI shows the removal button (cli_removable true)', async () => {
    await show(plain({}, { cli_installed: true, cli_removable: true }));
    expect(screen.getByRole('button', { name: 'Remove CLI from PATH' })).toBeTruthy();
  });

  it('a refused CLI install shows a fixed text per error kind and never echoes the wire', async () => {
    await show(plain({}, { cli_installed: false }));
    const texts: Record<string, RegExp> = {
      no_stable_path: /cannot tell which file to put on your PATH/,
      unsafe_path: /cannot be put on the PATH safely/,
      occupied: /already in the way and was left alone/,
      unsupported: /not supported on this system/,
      registry: /user PATH could not be read or changed/,
      path_too_long: /user PATH is too long/,
      io: /command file could not be written or removed/,
      cli_toml: /records where the app is/,
      newer_version: /installed by a newer atlas-duck/,
    };
    for (const [kind, text] of Object.entries(texts)) {
      vi.mocked(cliInstall).mockRejectedValue({ kind: 'cli_install', error: { kind } });
      fireEvent.click(screen.getByRole('button', { name: 'Install CLI to PATH' }));
      await flush();
      expect(screen.getByRole('alert').textContent, kind).toMatch(text);
      // A failed call leaves no success text behind.
      expect(screen.queryAllByRole('status').filter((s) => s.textContent !== '')).toEqual([]);
    }
    // An unknown kind (or hostile text) is the generic line, not the wire string.
    vi.mocked(cliInstall).mockRejectedValue({ kind: 'cli_install', error: { kind: 'x\u202ey' } });
    fireEvent.click(screen.getByRole('button', { name: 'Install CLI to PATH' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('The command line could not be installed or removed');
    // The audit record that could not be written is the settings error's own text.
    vi.mocked(cliInstall).mockRejectedValue({ kind: 'settings', error: { kind: 'audit' } });
    fireEvent.click(screen.getByRole('button', { name: 'Install CLI to PATH' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('The change was refused');
  });

  it('the CLI buttons and the removal entry stay on under a read-only config (they write no config.toml)', async () => {
    await show(FULL);
    const cli = FULL.cli_installed ? 'Remove CLI from PATH' : 'Install CLI to PATH';
    expect((screen.getByRole('button', { name: cli }) as HTMLButtonElement).disabled).toBe(false);
    expect(
      (screen.getByRole('button', { name: 'Delete the stored tokens' }) as HTMLButtonElement).disabled,
    ).toBe(false);
  });
  it('add instance sends the typed values with no CA data and shows the https hint on refusal', async () => {
    await show(BARE);
    const form = within(screen.getByRole('region', { name: 'Add an instance' }));
    fireEvent.change(form.getByLabelText('Alias'), { target: { value: 'prod' } });
    fireEvent.change(form.getByLabelText(/Base URL/), { target: { value: 'http://jira.corp/jira' } });
    fireEvent.click(form.getByLabelText(/custom CA/));
    vi.mocked(instanceAdd).mockRejectedValue({ kind: 'admin', error: { kind: 'insecure_scheme' } });
    fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
    await flush();
    expect(instanceAdd).toHaveBeenCalledWith({
      alias: 'prod',
      product: 'jira',
      base_url: 'http://jira.corp/jira',
      proxy: '',
      use_custom_ca: true,
      is_default: false,
    });
    expect(Object.keys(vi.mocked(instanceAdd).mock.calls[0]?.[0] ?? {}).sort()).toEqual(
      ['alias', 'base_url', 'is_default', 'product', 'proxy', 'use_custom_ca'],
    );
    expect(form.getByRole('alert').textContent).toContain('atlas-duck requires https');

    vi.mocked(instanceAdd).mockResolvedValue({ ...WORK, state: 'needs_token' });
    fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
    await flush();
    expect(form.getByRole('status').textContent).toBe(
      'The instance was added. Add its token next.',
    );
    // The text follows the returned state, not a fixed next step.
    vi.mocked(instanceAdd).mockResolvedValue({ ...WORK, state: 'ok' });
    fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
    await flush();
    expect(form.getByRole('status').textContent).toBe('The instance was added.');
  });

  it('change URL and proxy send the typed values; proxy Apply is off until edited', async () => {
    await show(plain({}));
    const r = within(row('work'));
    const apply = r.getByRole('button', { name: 'Apply proxy' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    vi.mocked(instanceSetProxy).mockResolvedValue(WORK);
    fireEvent.change(r.getByLabelText(/^Proxy/), { target: { value: 'direct' } });
    fireEvent.click(apply);
    await flush();
    expect(instanceSetProxy).toHaveBeenCalledWith('work', 'direct');
    vi.mocked(instanceChangeUrl).mockResolvedValue(WORK);
    fireEvent.change(r.getByLabelText('New base URL'), { target: { value: 'https://new.example/jira' } });
    fireEvent.click(r.getByRole('button', { name: 'Apply URL change' }));
    await flush();
    expect(instanceChangeUrl).toHaveBeenCalledWith('work', 'https://new.example/jira');
  });

  it('a PAC configuration shows the fixed hint', async () => {
    await show(plain({ pac_configured: true }));
    expect(screen.getByText(/proxy auto-config script, which atlas-duck does not evaluate/)).toBeTruthy();
  });

  it('a busy credential window is shown as fixed text', async () => {
    await show(plain({ state: 'needs_token' }));
    vi.mocked(credentialWindowOpen).mockRejectedValue({ kind: 'busy' });
    fireEvent.click(screen.getByRole('button', { name: 'Replace token' }));
    await flush();
    expect(screen.getByText(/credential window is open, or another task is running/)).toBeTruthy();
  });

  it('a failed read shows a retry', async () => {
    vi.mocked(settingsGet).mockRejectedValue({ kind: 'not_ready' });
    render(<Settings />);
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Could not load the settings');
    vi.mocked(settingsGet).mockResolvedValue(plain({}));
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await flush();
    expect(screen.getByRole('table')).toBeTruthy();
  });

  it('expiry_warning_text', async () => {
    const base: InstanceView = { ...WORK, expires_at: '2027-01-31' };
    const text = (days_left: number | null, expiry_warning: number | null) =>
      expiryWarningText({ ...base, days_left, expiry_warning });
    expect(text(5, 7)).toBe('Token expires in 5 days');
    expect(text(1, 1)).toBe('Token expires in 1 day');
    expect(text(0, 1)).toBe('Token expires today');
    expect(text(-3, 1)).toBe('Token expired on 2027-01-31');
    expect(text(null, 7)).toBe('Token expiry is close');
    expect(text(30, null)).toBeNull();

    await show(plain({ days_left: 5, expiry_warning: 7 }));
    expect(row('work').querySelector('.expiry-warning')?.textContent).toContain('Token expires in 5 days');
    expect(within(row('work')).getByText(/2027-01-31/)).toBeTruthy();
  });

  it('no expiry warning is rendered while expiry_warning is null', async () => {
    await show(plain({ days_left: 40, expiry_warning: null }));
    expect(row('work').querySelector('.expiry-warning')).toBeNull();
  });

  it('all_server_strings_text_nodes', async () => {
    const markup = '<img src=x onerror=alert(1)>';
    const evil = `${markup}<b>bold</b>‮`;
    const data: SettingsGet = {
      ...FULL,
      settings: {
        ...FULL.settings,
        config_read_only: { kind: 'read_only', text: evil },
        anchor_dir: evil,
        health: { ...FULL.settings.health, prune_backlog: evil },
      },
      instances: [
        {
          ...WORK,
          alias: evil,
          origin: evil,
          executes_as: evil,
          note: evil,
          proxy_effective: evil,
          expires_at: evil,
          pending_url_change: evil,
          state: evil,
        },
      ],
      confinement: {
        state: 'not_met',
        mode: evil,
        failed: [evil],
        extra_layers: [{ name: evil, on: true }],
        scripts: 'disabled',
        degraded_allowed: false,
      },
    };
    const { container } = await show(data);
    expect(container.querySelector('img, b, script, iframe, a')).toBeNull();
    expect(container.textContent).toContain(markup);
    expect(screen.getAllByText('unusual characters').length).toBeGreaterThanOrEqual(8);
    // Unverified badge in front of the server-derived texts.
    expect(screen.getAllByText('unverified').length).toBeGreaterThanOrEqual(2);
  });

  it('re-test answers (user, warnings) are text nodes with the unverified badge', async () => {
    const evil = '<script>alert(1)</script>‮';
    await show(plain({ state: 'needs_token' }));
    vi.mocked(retestToken).mockResolvedValue({
      ok: { atlassian_user: evil, product: 'jira', version: '9', warnings: [evil] },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    const status = filledStatus();
    expect(status.querySelector('script')).toBeNull();
    expect(status.textContent).toContain('<script>alert(1)</script>');
    expect(within(status).getAllByText('unusual characters')).toHaveLength(2);
    // The user, the version and the warning are server strings.
    expect(within(status).getAllByText('unverified')).toHaveLength(3);
    expect(status.textContent).toContain('Jira');
  });

  it('error texts are honest: audit kind is neutral, invalid_url and keychain are specific', async () => {
    await show(BARE);
    const form = within(screen.getByRole('region', { name: 'Add an instance' }));
    const submit = async (e: unknown) => {
      vi.mocked(instanceAdd).mockRejectedValue(e);
      fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
      await flush();
      return form.getByRole('alert').textContent;
    };
    expect(await submit({ kind: 'admin', error: { kind: 'audit' } })).toBe('The change was refused');
    expect(await submit({ kind: 'admin', error: { kind: 'invalid_url' } })).toBe('That is not a valid URL');
    expect(await submit({ kind: 'admin', error: { kind: 'keychain' } })).toContain('token store');
    expect(await submit({ kind: 'admin', error: { kind: 'constructor' } })).toBe('The change was refused');
    expect(await submit({ kind: 'constructor' })).toBe('The command failed');
    expect(await submit({ kind: 'invalid_argument', field: 'use_custom_ca' })).toBe(
      'Check the value of the CA file: choose another file',
    );
    expect(await submit({ kind: 'invalid_argument', field: 'secret_field_name' })).toBe(
      'Check the value of a field',
    );
  });

  it('admin_error_kinds_have_texts', () => {
    const text = (kind: string, more: object = {}) => errorText({ kind: 'admin', error: { kind, ...more } });
    const neutral = text('audit');
    expect(neutral).toBe('The change was refused');
    // M10 T36 (L217): the three kinds that were the neutral `audit` text have their own.
    expect(text('duplicate_alias')).toBe('Another instance already uses that alias: choose another alias');
    expect(text('second_default', { product: 'jira' })).toBe(
      'That product already has a default instance: it can have only one',
    );
    expect(text('unusable_ca_bundle', { reason: 'no_certificate' })).toBe(
      'That file holds no usable CA certificate: choose a PEM file with the certificate',
    );
    // Every admin kind Rust sends (the fixtures) has a text of its own, except the neutral
    // `audit`; an unlisted kind falls back to the neutral text, so a new kind without a text
    // fails here once its fixture exists.
    const kinds = (commandErrorFixtures as { kind: string; error?: { kind: string } }[])
      .filter((e) => e.kind === 'admin' && e.error !== undefined)
      .map((e) => e.error?.kind ?? '');
    expect(kinds).toEqual(expect.arrayContaining(['duplicate_alias', 'second_default', 'unusable_ca_bundle']));
    for (const kind of kinds) {
      if (kind === 'audit') continue;
      expect(text(kind), kind).not.toBe(neutral);
    }
  });

  it('a re-test without a stored token shows the keychain text', async () => {
    await show(plain({ state: 'needs_token', executes_as: null }));
    vi.mocked(retestToken).mockRejectedValue({ kind: 'admin', error: { kind: 'keychain' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('token store');
  });

  it('every connection failure class of core has a fixed re-test text', async () => {
    await show(plain({ state: 'needs_token' }));
    const expected: Record<string, string> = {
      http_401: 'the server refused the token',
      tls: 'the TLS certificate was not accepted',
      proxy: 'the proxy refused',
      network: 'the server could not be reached',
      version_below_floor: 'below the supported minimum',
      identity_header_missing: 'identity header was not received',
      identity_header_mismatch: 'identity header did not match',
      other_user: 'another user',
      not_known_user: 'does not know',
      unavailable: 'did not answer with an identity',
    };
    for (const [cls, text] of Object.entries(expected)) {
      vi.mocked(retestToken).mockResolvedValue({ failed: { class: cls } });
      fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
      await flush();
      const status = filledStatus().textContent ?? '';
      expect(status, cls).toContain(text);
      expect(status, cls).not.toContain('recognize');
    }
  });

  it('a re-test success shows user, product and version', async () => {
    await show(plain({ state: 'needs_token' }));
    vi.mocked(retestToken).mockResolvedValue({
      ok: { atlassian_user: 'alice', product: 'jira', version: '9.12.0', warnings: [] },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    expect(filledStatus().textContent).toContain('alice');
    expect(filledStatus().textContent).toContain('Jira');
    expect(filledStatus().textContent).toContain('9.12.0');
  });

  it('every prune skip reason of core has a text', async () => {
    await show(plain({}));
    for (const reason of [
      'not_corroborated',
      'head_epoch_null',
      'legal_hold',
      'already_ran_this_epoch',
      'clock_before_head',
      'clock_before_last_prune',
      'nothing_to_advance',
      'config_not_reconciled',
      'clock_behind',
    ]) {
      vi.mocked(pruneBacklogNow).mockResolvedValue({ result: 'skipped', reason });
      fireEvent.click(screen.getByRole('button', { name: 'Prune backlog now' }));
      await flush();
      const text = screen.getByText(/Pruning was skipped/).textContent ?? '';
      expect(text, reason).not.toContain('_');
    }
  });

  it('a cancelled add, URL change and URL acceptance show the cancelled text and keep the form', async () => {
    const cancelled = { kind: 'admin', error: { kind: 'cancelled' } };
    await show(plain({ pending_url_change: 'https://jira.example/moved' }));
    const form = within(screen.getByRole('region', { name: 'Add an instance' }));
    fireEvent.change(form.getByLabelText('Alias'), { target: { value: 'prod' } });
    fireEvent.change(form.getByLabelText(/Base URL/), { target: { value: 'https://jira.corp/jira' } });
    vi.mocked(instanceAdd).mockRejectedValue(cancelled);
    fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
    await flush();
    expect(form.getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
    expect((form.getByLabelText('Alias') as HTMLInputElement).value).toBe('prod');
    expect(form.queryByRole('status')).toBeNull();

    const r = within(row('work'));
    vi.mocked(instanceChangeUrl).mockRejectedValue(cancelled);
    fireEvent.change(r.getByLabelText('New base URL'), { target: { value: 'https://new.example/jira' } });
    fireEvent.click(r.getByRole('button', { name: 'Apply URL change' }));
    await flush();
    expect((r.getByLabelText('New base URL') as HTMLInputElement).value).toBe('https://new.example/jira');
    expect(r.getAllByText('Cancelled: nothing was changed').length).toBeGreaterThan(0);

    vi.mocked(instanceAcceptUrlChange).mockRejectedValue(cancelled);
    const callsBefore = vi.mocked(settingsGet).mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Accept the URL change' }));
    await flush();
    expect(screen.getAllByText('Cancelled: nothing was changed').length).toBeGreaterThan(1);
    expect(settingsGet).toHaveBeenCalledTimes(callsBefore);
  });

  it('only one command is in flight in the window', async () => {
    await show(plain({ state: 'needs_token' }));
    let finish: (v: unknown) => void = () => undefined;
    vi.mocked(settingsApply).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }) as never,
    );
    fireEvent.change(screen.getByLabelText('Jira comments cap'), { target: { value: '60' } });
    const limits = within(screen.getByRole('region', { name: 'Limits' }));
    fireEvent.click(limits.getByRole('button', { name: 'Apply' }));
    await flush();
    // Every other control that starts a command is off while it runs.
    expect(screen.getByRole('button', { name: 'Re-test stored token' }).matches(':disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Replace token' }).matches(':disabled')).toBe(true);
    expect(screen.getByRole('button', { name: 'Add instance' }).matches(':disabled')).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Prune backlog now' }));
    expect(pruneBacklogNow).not.toHaveBeenCalled();
    finish(FULL.settings);
    await flush();
    expect(screen.getByRole('button', { name: 'Re-test stored token' }).matches(':disabled')).toBe(false);
  });

  it('per-row controls point at the alias of their row', async () => {
    await show(plain({ state: 'needs_token' }));
    const r = within(row('work'));
    for (const el of [
      r.getByRole('button', { name: 'Re-test stored token' }),
      r.getByRole('button', { name: 'Replace token' }),
      r.getByLabelText('New base URL'),
      r.getByRole('button', { name: 'Apply proxy' }),
    ]) {
      const id = el.getAttribute('aria-describedby') ?? '';
      expect(document.getElementById(id)?.textContent, el.outerHTML).toContain('work');
    }
  });
});

// ---- M10 T21: recovery and backup, anchor directory, recovery tier ----

/** `plain()` with the store health changed. */
function withHealth(health: Partial<SettingsGet['settings']['health']>, anchorDir: string | null = null): SettingsGet {
  const base = plain({});
  return {
    ...base,
    settings: { ...base.settings, anchor_dir: anchorDir, health: { ...base.settings.health, ...health } },
  };
}

const section = (name: string): ReturnType<typeof within> => within(screen.getByRole('region', { name }));

const never = <T,>() => new Promise<T>(() => undefined);

/** What the polite regions of a section hold (the banner region is empty unless a restore waits). */
const statusText = (w: { getAllByRole: (role: string) => HTMLElement[] }): string =>
  w.getAllByRole('status').map((s) => s.textContent ?? '').join('');

const DONE = {
  restore_seq: 5,
  records_lost: 2,
  tokens_deleted: 1,
  offer_passphrase_change: true,
  after_restore_failed: false,
};

describe('Settings recovery and backup (M10 T21)', () => {
  it('backup_text_states_no_tokens: the L27 sentence, the upgrade advice, and a backup that carries no argument', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    // Written out here on purpose: the test must not read the constants it checks.
    expect(
      recovery.getByText('Backups never contain stored tokens; after a restore every instance needs its token again.'),
    ).toBeTruthy();
    expect(recovery.getByText('Make a full backup before every upgrade.')).toBeTruthy();
    vi.mocked(backupTrigger).mockResolvedValue({ saved: true });
    fireEvent.click(recovery.getByRole('button', { name: 'Back up now…' }));
    await flush();
    expect(backupTrigger).toHaveBeenCalledWith();
    expect(statusText(recovery)).toBe('The backup was saved.');
  });

  it('a failed backup, a cancelled folder dialog and a busy slot are fixed texts', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    const press = async () => {
      fireEvent.click(recovery.getByRole('button', { name: 'Back up now…' }));
      await flush();
    };
    vi.mocked(backupTrigger).mockRejectedValueOnce({ kind: 'backup' });
    await press();
    expect(recovery.getByRole('alert').textContent).toContain('The backup failed.');
    vi.mocked(backupTrigger).mockRejectedValueOnce({ kind: 'cancelled' });
    await press();
    expect(recovery.getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
    vi.mocked(backupTrigger).mockRejectedValueOnce({ kind: 'busy' });
    await press();
    expect(recovery.getByRole('alert').textContent).toContain('another task is running');
    vi.mocked(backupTrigger).mockResolvedValueOnce({ saved: false });
    await press();
    expect(statusText(recovery)).toBe('No backup was made.');
  });

  it('restore_indeterminate_progress_and_wait_banner: no value on the bar, the banner from started, Cancel valid', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    let finish: (v: unknown) => void = () => undefined;
    vi.mocked(restoreBegin).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve;
      }) as never,
    );
    fireEvent.click(recovery.getByRole('button', { name: 'Restore backup…' }));
    await flush();
    expect(restoreBegin).toHaveBeenCalledWith();
    const bar = recovery.getByRole('progressbar');
    expect(bar.hasAttribute('value')).toBe(false);
    expect(recovery.queryByText('Requests wait while the restore runs')).toBeNull();
    // Rust emits `started` once its own dialogs are answered and the store call is next.
    await emitEvent('audit_job', { job: 'restore', phase: 'started' });
    expect(recovery.getByText('Requests wait while the restore runs')).toBeTruthy();
    // An export's event does not say the restore waits.
    vi.mocked(restoreCancel).mockResolvedValue({ cancelled: true });
    fireEvent.click(recovery.getByRole('button', { name: 'Cancel restore' }));
    await flush();
    expect(restoreCancel).toHaveBeenCalledWith();
    expect(statusText(recovery)).toContain('Cancel requested.');
    finish(DONE);
    await flush();
    await emitEvent('audit_job', { job: 'restore', phase: 'done' });
    expect(recovery.queryByRole('progressbar')).toBeNull();
    expect(recovery.queryByText('Requests wait while the restore runs')).toBeNull();
    const said = statusText(recovery);
    expect(said).toContain('The restore is complete.');
    expect(said).toContain('2 records written after the backup are no longer in the log.');
    expect(said).toContain('1 stored token was deleted');
    expect(said).toContain("The backup's recovery passphrase is now the recovery passphrase of this log.");
  });

  it('a cancel that is too late says so; a foreign job is not a restore', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    vi.mocked(restoreBegin).mockReturnValue(never());
    fireEvent.click(recovery.getByRole('button', { name: 'Restore backup…' }));
    await flush();
    await emitEvent('audit_job', { job: 'export', phase: 'started' });
    expect(recovery.queryByText('Requests wait while the restore runs')).toBeNull();
    vi.mocked(restoreCancel).mockRejectedValue({ kind: 'busy' });
    fireEvent.click(recovery.getByRole('button', { name: 'Cancel restore' }));
    await flush();
    expect(recovery.getByRole('alert').textContent).toContain('cannot be cancelled');
  });

  it('a follow-up that failed and a restore that committed incompletely each ask for a restart', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    vi.mocked(restoreBegin).mockResolvedValueOnce({ ...DONE, after_restore_failed: true });
    fireEvent.click(recovery.getByRole('button', { name: 'Restore backup…' }));
    await flush();
    expect(statusText(recovery)).toContain('follow-up step failed');
    expect(statusText(recovery)).toContain('start it again');
    vi.mocked(restoreBegin).mockRejectedValueOnce({ kind: 'restore', error: { kind: 'committed_incomplete' } });
    fireEvent.click(recovery.getByRole('button', { name: 'Restore backup…' }));
    await flush();
    const alert = recovery.getByRole('alert').textContent ?? '';
    expect(alert).toContain('Restore will be completed at the next start');
    expect(alert).toContain('start it again');
    // No retry once the restore committed: the only restore control is gone while the text stands.
    expect((recovery.getByRole('button', { name: 'Restore backup…' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('every other restore failure says that nothing changed', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    for (const kind of ['wrong_passphrase', 'not_a_backup', 'newer', 'broken', 'anchor_dir_mismatch', 'keychain', 'failed']) {
      vi.mocked(restoreBegin).mockRejectedValueOnce({ kind: 'restore', error: { kind } });
      fireEvent.click(recovery.getByRole('button', { name: 'Restore backup…' }));
      await flush();
      expect(recovery.getByRole('alert').textContent, kind).toContain('Nothing was changed.');
    }
  });

  it('the passphrase change asks Rust to open the credential window, and the restore offers it', async () => {
    await show(plain({}));
    const recovery = section('Recovery and backup');
    vi.mocked(recoveryPassphraseChange).mockResolvedValue(null);
    fireEvent.click(recovery.getByRole('button', { name: 'Change recovery passphrase…' }));
    await flush();
    expect(recoveryPassphraseChange).toHaveBeenCalledWith();
    expect(statusText(recovery)).toContain('credential window is open');
  });

  it('anchor_dir_failure_line_shown: a failing anchor write is a line, never an incident; pending lines are counted', async () => {
    await show(withHealth({ anchor_dir_write_failing: true, anchor_dir_lines_pending: 3 }, '/mnt/anchors'));
    const anchor = section('External anchor directory');
    expect(anchor.getByText('Writing to the anchor directory fails; 3 lines wait and will be retried.')).toBeTruthy();
    expect(anchor.getByText('/mnt/anchors')).toBeTruthy();
  });

  it('lines that wait without a failing write are counted too, and no line shows when nothing waits', async () => {
    await show(withHealth({ anchor_dir_write_failing: false, anchor_dir_lines_pending: 1 }, '/mnt/anchors'));
    expect(section('External anchor directory').getByText('1 line waits to be written to the anchor directory.')).toBeTruthy();
    cleanup();
    await show(withHealth({ anchor_dir_write_failing: false, anchor_dir_lines_pending: 0 }, '/mnt/anchors'));
    expect(section('External anchor directory').queryByText(/waits? to be written/)).toBeNull();
  });

  it('anchor directory: set, change and remove carry no path; the answers are texts', async () => {
    await show(withHealth({}, null));
    let anchor = section('External anchor directory');
    expect(anchor.getByText(/\(not set\)/)).toBeTruthy();
    expect(anchor.queryByRole('button', { name: 'Remove anchor directory…' })).toBeNull();
    vi.mocked(anchorDirSet).mockRejectedValueOnce({ kind: 'anchor_dir', error: { kind: 'not_writable' } });
    fireEvent.click(anchor.getByRole('button', { name: 'Set anchor directory…' }));
    await flush();
    expect(anchorDirSet).toHaveBeenCalledWith();
    expect(anchor.getByRole('alert').textContent).toBe('This folder cannot be written');
    vi.mocked(anchorDirSet).mockResolvedValueOnce({ anchor_dir: '/mnt/new' });
    fireEvent.click(anchor.getByRole('button', { name: 'Set anchor directory…' }));
    await flush();
    expect(anchor.getByRole('status').textContent).toBe('The anchor directory was changed.');
    cleanup();
    await show(withHealth({}, '/mnt/anchors'));
    anchor = section('External anchor directory');
    expect(anchor.getByRole('button', { name: 'Change anchor directory…' })).toBeTruthy();
    vi.mocked(anchorDirRemove).mockResolvedValueOnce({ anchor_dir: null });
    fireEvent.click(anchor.getByRole('button', { name: 'Remove anchor directory…' }));
    await flush();
    expect(anchorDirRemove).toHaveBeenCalledWith();
    expect(anchor.getByRole('status').textContent).toBe('The anchor directory was removed.');
    for (const [kind, text] of [
      ['unchanged', 'already in use'],
      ['writer_busy', 'busy'],
      ['not_set', 'No anchor directory is set'],
      ['failed', 'cannot be used'],
    ] as const) {
      vi.mocked(anchorDirRemove).mockRejectedValueOnce({ kind: 'anchor_dir', error: { kind } });
      fireEvent.click(anchor.getByRole('button', { name: 'Remove anchor directory…' }));
      await flush();
      expect(anchor.getByRole('alert').textContent, kind).toContain(text);
    }
    vi.mocked(anchorDirRemove).mockRejectedValueOnce({ kind: 'cancelled' });
    fireEvent.click(anchor.getByRole('button', { name: 'Remove anchor directory…' }));
    await flush();
    expect(anchor.getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
  });

  it('reanchor_only_when_offered: a missing entry is named, the button only while Rust offers it', async () => {
    await show(withHealth({ anchors_missing: 'head', re_anchor_offered: false }));
    expect(screen.getByText('The head anchor entry is missing from the keychain.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Re-anchor…' })).toBeNull();
    cleanup();
    await show(withHealth({ anchors_missing: null, re_anchor_offered: false }));
    expect(screen.queryByRole('button', { name: 'Re-anchor…' })).toBeNull();
    expect(screen.queryByText(/entry is missing|entries are missing/)).toBeNull();
    cleanup();
    await show(withHealth({ anchors_missing: 'both', re_anchor_offered: true }));
    expect(screen.getByText(/head anchor and the first-retained anchor entries are missing/)).toBeTruthy();
    // The text says that both anchors are written again and that an incident is recorded.
    const note = screen.getByText(/writes both the head anchor and the first-retained anchor again/);
    expect(note.textContent).toContain('integrity incident');
    vi.mocked(reAnchor).mockResolvedValue({ verify_seq: 9 });
    fireEvent.click(screen.getByRole('button', { name: 'Re-anchor…' }));
    await flush();
    expect(reAnchor).toHaveBeenCalledWith();
    expect(screen.getByText(/Re-anchored\. An integrity incident was recorded/)).toBeTruthy();
  });

  it('a re-anchor that left an incident, or did nothing, says which', async () => {
    await show(withHealth({ anchors_missing: 'head', re_anchor_offered: true }));
    for (const [kind, text] of [
      ['does_not_verify', 'integrity incident was recorded'],
      ['keychain', 'integrity incident was recorded'],
      ['held', 'held'],
      ['nothing_missing', 'nothing was changed'],
      ['restored', 'nothing was changed'],
      ['failed', 'failed'],
    ] as const) {
      vi.mocked(reAnchor).mockRejectedValueOnce({ kind: 're_anchor', error: { kind } });
      fireEvent.click(screen.getByRole('button', { name: 'Re-anchor…' }));
      await flush();
      expect(screen.getAllByRole('alert').map((a) => a.textContent).join('|'), kind).toContain(text);
    }
  });

  it('forget_lists_orphans: install, archived files and entries are listed; Forget carries the id only', async () => {
    const id = 'ab'.repeat(16);
    vi.mocked(orphanInstalls).mockResolvedValue([
      { install_id: id, archived_files: ['archived/old.db'], entries: ['kek', 'pat/1'] },
    ]);
    await show(plain({}));
    const old = section('Old installs');
    expect(old.getByText(id)).toBeTruthy();
    expect(old.getByText('archived/old.db')).toBeTruthy();
    expect(old.getByText('kek')).toBeTruthy();
    expect(old.getByText('pat/1')).toBeTruthy();
    vi.mocked(forgetInstall).mockResolvedValue({ install_id: id, deleted: ['kek'], keys_deleted: true });
    vi.mocked(orphanInstalls).mockResolvedValue([]);
    fireEvent.click(old.getByRole('button', { name: `Forget the install ${id}` }));
    await flush();
    expect(forgetInstall).toHaveBeenCalledWith(id);
    expect(old.getByRole('status').textContent).toContain('Forgotten: its keychain entries and the keys of its archived log were deleted.');
    // The list is read again: the forgotten install is gone, and focus moved to the section heading.
    expect(old.queryByText(id)).toBeNull();
    expect(old.getByText('No old installs were found.')).toBeTruthy();
    expect(document.activeElement).toBe(old.getByRole('heading', { name: 'Old installs' }));
  });

  it('forgetting keeps the keys when the second confirmation was declined, and names a partial failure', async () => {
    const id = 'cd'.repeat(16);
    vi.mocked(orphanInstalls).mockResolvedValue([{ install_id: id, archived_files: [], entries: ['kek', 'pat/1'] }]);
    await show(plain({}));
    const old = section('Old installs');
    vi.mocked(forgetInstall).mockResolvedValueOnce({ install_id: id, deleted: ['pat/1'], keys_deleted: false });
    fireEvent.click(old.getByRole('button', { name: `Forget the install ${id}` }));
    await flush();
    expect(old.getByRole('status').textContent).toContain('the keys of its archived log were kept');
    vi.mocked(forgetInstall).mockRejectedValueOnce({
      kind: 'forget',
      error: { kind: 'keychain', deleted: ['pat/1'], not_deleted: ['kek'] },
    });
    fireEvent.click(old.getByRole('button', { name: `Forget the install ${id}` }));
    await flush();
    const alert = old.getByRole('alert');
    expect(alert.textContent).toContain('Some entries could not be deleted');
    expect(within(alert).getByText('pat/1')).toBeTruthy();
    expect(within(alert).getByText('kek')).toBeTruthy();
    vi.mocked(forgetInstall).mockRejectedValueOnce({ kind: 'cancelled' });
    fireEvent.click(old.getByRole('button', { name: `Forget the install ${id}` }));
    await flush();
    expect(old.getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
  });
});