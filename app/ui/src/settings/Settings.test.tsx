import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import {
  credentialWindowOpen,
  instanceAcceptUrlChange,
  instanceAdd,
  instanceChangeUrl,
  instanceConfirmConfig,
  instanceSetProxy,
  pruneBacklogNow,
  retestToken,
  settingsApply,
  settingsGet,
} from '../shared/ipc/invoke';
import settingsFixture from '../shared/ipc/fixtures/settings_get.json';
import type { InstanceView, SettingsGet } from '../shared/ipc/types';
import { Settings } from './Settings';
import { expiryWarningText } from './text';

vi.mock('../shared/ipc/invoke', () => ({
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

const row = (alias: string): HTMLElement => {
  const cell = screen.getByRole('rowheader', { name: new RegExp(alias) });
  return cell.closest('tr') as HTMLElement;
};

beforeEach(() => {
  handlers = [];
  vi.mocked(on)
    .mockReset()
    .mockImplementation((_name, handler) => {
      handlers.push(handler as (payload: unknown) => void);
      return Promise.resolve(() => undefined);
    });
  for (const f of [
    settingsApply,
    instanceAdd,
    instanceChangeUrl,
    instanceConfirmConfig,
    instanceAcceptUrlChange,
    instanceSetProxy,
    credentialWindowOpen,
    retestToken,
    pruneBacklogNow,
  ]) {
    vi.mocked(f as (...a: unknown[]) => Promise<unknown>).mockReset();
  }
  vi.mocked(settingsGet).mockReset();
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

  it('a failed re-test shows a fixed class text, an unknown class as text with the badge', async () => {
    await show(plain({ state: 'needs_token' }));
    vi.mocked(retestToken).mockResolvedValue({ failed: { class: 'other_user' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    expect(screen.getByRole('status').textContent).toContain('the token now belongs to another user');
    vi.mocked(retestToken).mockResolvedValue({ failed: { class: 'x‮y' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-test stored token' }));
    await flush();
    expect(screen.getByRole('status').textContent).toContain('unknown failure class');
    expect(screen.getAllByText('unusual characters').length).toBeGreaterThan(0);
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

  it('read_only_config_disables_form_with_banner', async () => {
    await show(FULL);
    expect(
      screen.getByText(/config written by v9\.9\.0; settings read-only until you upgrade/),
    ).toBeTruthy();
    const controls = [...document.querySelectorAll('input, select, button, textarea')];
    expect(controls.length).toBeGreaterThan(8);
    for (const c of controls) {
      expect(c.matches(':disabled'), c.outerHTML).toBe(true);
    }
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
    await show({ ...BARE, confinement: { state: 'pending', failed: [], mode: 'n/a', extra_layers: [] } });
    expect(screen.getByText('the startup probe has not finished')).toBeTruthy();
  });

  it('CLI and removal entries are off stubs per cli_installed', async () => {
    const { unmount } = await show(plain({}, { cli_installed: true }));
    expect((screen.getByRole('button', { name: 'Remove CLI from PATH' }) as HTMLButtonElement).disabled).toBe(true);
    unmount();
    await show(plain({}, { cli_installed: false }));
    expect((screen.getByRole('button', { name: 'Install CLI to PATH' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Prepare for removal' }) as HTMLButtonElement).disabled).toBe(true);
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

    vi.mocked(instanceAdd).mockResolvedValue(WORK);
    fireEvent.click(form.getByRole('button', { name: 'Add instance' }));
    await flush();
    expect(form.getByRole('status').textContent).toContain('The instance was added');
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
    expect(screen.getByText(/credential window is open for something else/)).toBeTruthy();
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
      confinement: { state: 'not_met', mode: evil, failed: [evil], extra_layers: [{ name: evil, on: true }] },
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
    const status = screen.getByRole('status');
    expect(status.querySelector('script')).toBeNull();
    expect(status.textContent).toContain('<script>alert(1)</script>');
    expect(within(status).getAllByText('unusual characters')).toHaveLength(2);
    expect(within(status).getAllByText('unverified')).toHaveLength(2);
  });
});
