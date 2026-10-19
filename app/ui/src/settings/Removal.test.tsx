import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  removalBackup,
  removalBegin,
  removalFinish,
  removalMark,
  removalState,
} from '../shared/ipc/invoke';
import type { RemovalItem, RemovalState } from '../shared/ipc/types';
import { Removal } from './Removal';
import { WindowBusyContext, useWindowBusy } from './useAction';

vi.mock('../shared/ipc/invoke', () => ({
  removalBackup: vi.fn(),
  removalBegin: vi.fn(),
  removalFinish: vi.fn(),
  removalMark: vi.fn(),
  removalState: vi.fn(),
}));

/** The spec's 12.5 sentence, written out here on purpose: the test must not read the constant it checks. */
const REVOKE = 'Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)';

const item = (over: Partial<RemovalItem> = {}): RemovalItem => ({
  alias: 'work',
  product: 'jira',
  origin: 'https://jira.example/jira',
  identity: 'jdoe',
  token_deleted: true,
  error: null,
  choice: 'pending',
  ...over,
});

const idle: RemovalState = {
  active: false,
  recorded: false,
  backup_made: false,
  retention_days: 92,
  legal_hold: false,
  retention_left_days: 92,
  instances: [],
};

const active = (...instances: RemovalItem[]): RemovalState => ({
  ...idle,
  active: true,
  instances,
});

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

function Harness({ onChanged = () => undefined }: { onChanged?: () => void }) {
  const busy = useWindowBusy();
  return (
    <WindowBusyContext.Provider value={busy}>
      <Removal onChanged={onChanged} />
    </WindowBusyContext.Provider>
  );
}

async function show(state: RemovalState, onChanged?: () => void) {
  vi.mocked(removalState).mockResolvedValue(state);
  const view = render(<Harness onChanged={onChanged} />);
  await flush();
  return view;
}

const click = async (name: string | RegExp) => {
  fireEvent.click(screen.getByRole('button', { name }));
  await flush();
};

const disabled = (name: string | RegExp) =>
  (screen.getByRole('button', { name }) as HTMLButtonElement).disabled;

beforeEach(() => {
  for (const f of [removalBackup, removalBegin, removalFinish, removalMark, removalState]) {
    vi.mocked(f as (...a: unknown[]) => Promise<unknown>).mockReset();
  }
});

describe('Removal', () => {
  it('revoke_checklist_text_verbatim: the spec sentence, the alias and the token identity per instance', async () => {
    await show(
      active(item(), item({ alias: 'wiki', product: 'confluence', identity: 'asmith', origin: null })),
    );
    const steps = screen.getAllByText(REVOKE);
    expect(steps).toHaveLength(2);
    const [first, second] = screen.getAllByRole('listitem');
    expect(first?.textContent).toContain('work');
    expect(first?.textContent).toContain('“jdoe”');
    expect(first?.textContent).toContain('https://jira.example/jira');
    expect(second?.textContent).toContain('wiki');
    expect(second?.textContent).toContain('“asmith”');
  });

  it('shows the retention and the backup offer before anything is deleted', async () => {
    await show({ ...idle, retention_days: 1, legal_hold: true });
    expect(
      screen.getByText(
        'The newest audit record is kept until the legal hold is lifted, then for at least 1 more day.',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Create a full backup' })).toBeTruthy();
    expect(screen.queryByText(REVOKE)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Finish removal' })).toBeNull();
  });

  it('a backup carries no path: the call has no arguments and the answer is text', async () => {
    await show(idle);
    vi.mocked(removalBackup).mockResolvedValue({ saved: true });
    await click('Create a full backup');
    expect(removalBackup).toHaveBeenCalledWith();
    expect(screen.getByText('The backup was saved.')).toBeTruthy();
    vi.mocked(removalBackup).mockResolvedValue({ saved: false });
    await click('Create a full backup');
    expect(screen.getByText('No backup was made.')).toBeTruthy();
  });

  it('begin takes no arguments and replaces the entry with the checklist', async () => {
    await show(idle);
    vi.mocked(removalBegin).mockResolvedValue(active(item()));
    await click('Delete the stored tokens');
    expect(removalBegin).toHaveBeenCalledWith();
    expect(screen.getByText(REVOKE)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Delete the stored tokens' })).toBeNull();
  });

  it('a cancelled native confirmation shows fixed text and leaves the entry as it was', async () => {
    await show(idle);
    vi.mocked(removalBegin).mockRejectedValue({ kind: 'settings', error: { kind: 'cancelled' } });
    await click('Delete the stored tokens');
    expect(screen.getByRole('alert').textContent).toBe('Cancelled: nothing was changed');
    expect(screen.queryByText(REVOKE)).toBeNull();
    expect(disabled('Delete the stored tokens')).toBe(false);
  });

  it('cannot_finish_until_each_ticked_or_skipped: Finish stays off until every instance is answered', async () => {
    await show(active(item(), item({ alias: 'wiki', identity: 'asmith' })));
    expect(disabled('Finish removal')).toBe(true);
    vi.mocked(removalMark).mockResolvedValueOnce(
      active(item({ choice: 'done' }), item({ alias: 'wiki', identity: 'asmith' })),
    );
    fireEvent.click(screen.getAllByRole('button', { name: 'I revoked it' })[0] as HTMLElement);
    await flush();
    expect(removalMark).toHaveBeenCalledWith('work', 'done');
    expect(disabled('Finish removal')).toBe(true);
    vi.mocked(removalMark).mockResolvedValueOnce(
      active(item({ choice: 'done' }), item({ alias: 'wiki', identity: 'asmith', choice: 'skipped' })),
    );
    fireEvent.click(screen.getAllByRole('button', { name: 'Skip' })[1] as HTMLElement);
    await flush();
    expect(removalMark).toHaveBeenLastCalledWith('wiki', 'skipped');
    expect(disabled('Finish removal')).toBe(false);
    expect(screen.getByText(/Skipped: the token stays valid on the server/)).toBeTruthy();
  });

  it('an answer can be taken back; the buttons mirror the choice', async () => {
    await show(active(item({ choice: 'skipped' })));
    expect(
      screen.getByRole('button', { name: 'Skip' }).getAttribute('aria-pressed'),
    ).toBe('true');
    expect(
      screen.getByRole('button', { name: 'I revoked it' }).getAttribute('aria-pressed'),
    ).toBe('false');
    vi.mocked(removalMark).mockResolvedValue(active(item({ choice: 'pending' })));
    await click('Answer again');
    expect(removalMark).toHaveBeenCalledWith('work', 'pending');
    expect(disabled('Finish removal')).toBe(true);
  });

  it('an instance whose token is still stored cannot be answered and offers the retry', async () => {
    await show(active(item({ token_deleted: false, error: 'keychain' })));
    expect(screen.getByRole('alert').textContent).toBe(
      'The token is still stored: it could not be deleted.',
    );
    expect(screen.queryByRole('button', { name: 'I revoked it' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Skip' })).toBeNull();
    expect(disabled('Finish removal')).toBe(true);
    vi.mocked(removalBegin).mockResolvedValue(active(item()));
    await click('Delete the remaining tokens');
    expect(removalBegin).toHaveBeenCalledWith();
    expect(screen.queryByText('The token is still stored: it could not be deleted.')).toBeNull();
  });

  it('a token identity that is no longer known is said so, not guessed', async () => {
    await show(active(item({ identity: null })));
    expect(screen.getByText(/not known/)).toBeTruthy();
  });

  it('finish takes no arguments, then shows what was removed and the controls are gone', async () => {
    const changed = vi.fn();
    await show(active(item({ choice: 'done' })), changed);
    vi.mocked(removalFinish).mockResolvedValue({
      cli: 'removed',
      cli_reason: null,
      autostart: 'removed',
    });
    vi.mocked(removalState).mockResolvedValue(idle);
    await click('Finish removal');
    expect(removalFinish).toHaveBeenCalledWith();
    expect(screen.getByText('The command line was removed.')).toBeTruthy();
    expect(screen.getByText('atlas-duck no longer starts at login.')).toBeTruthy();
    expect(screen.getByText(/You can uninstall atlas-duck now/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Finish removal' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete the stored tokens' })).toBeNull();
    expect(changed).toHaveBeenCalled();
  });

  it('a finish whose command line step could not look says so and never says Done', async () => {
    await show(active(item({ choice: 'done' })));
    vi.mocked(removalFinish).mockResolvedValue({
      cli: 'not_removed',
      cli_reason: 'no_stable_path',
      autostart: 'removed',
    });
    vi.mocked(removalState).mockResolvedValue(idle);
    await click('Finish removal');
    expect(screen.getByText('The command line was not removed.')).toBeTruthy();
    expect(screen.getByText(/cannot tell where it is installed from this location/)).toBeTruthy();
    expect(screen.getByText(/Not done: the command line may still be installed/)).toBeTruthy();
    expect(screen.queryByText(/Done\. You can uninstall/)).toBeNull();
    // A kind the page does not know gets the general sentence, never the raw kind.
    vi.mocked(removalFinish).mockResolvedValue({
      cli: 'not_removed',
      cli_reason: 'x‮y',
      autostart: 'was_off',
    });
    cleanup();
    await show(active(item({ choice: 'done' })));
    await click('Finish removal');
    expect(screen.getByText('The command line could not be removed')).toBeTruthy();
    expect(screen.queryByText(/x‮y/)).toBeNull();
  });

  it('a command file of a newer atlas-duck is named as the reason, not the general sentence', async () => {
    await show(active(item({ choice: 'done' })));
    vi.mocked(removalFinish).mockResolvedValue({
      cli: 'not_removed',
      cli_reason: 'newer_version',
      autostart: 'removed',
    });
    vi.mocked(removalState).mockResolvedValue(idle);
    await click('Finish removal');
    expect(screen.getByText(/installed by a newer atlas-duck and was left alone/)).toBeTruthy();
    expect(screen.queryByText(/Done\. You can uninstall/)).toBeNull();
  });

  it('a nothing-found command line is an honest, complete finish', async () => {
    await show(active(item({ choice: 'done' })));
    vi.mocked(removalFinish).mockResolvedValue({
      cli: 'not_found',
      cli_reason: null,
      autostart: 'was_off',
    });
    vi.mocked(removalState).mockResolvedValue(idle);
    await click('Finish removal');
    expect(screen.getByText('No command line of atlas-duck was found.')).toBeTruthy();
    expect(screen.getByText(/You can uninstall atlas-duck now/)).toBeTruthy();
  });

  it('refusals of finish are fixed texts by kind, each followed by a re-read of the state', async () => {
    await show(active(item({ choice: 'done' })));
    for (const [kind, text] of [
      ['unticked', 'Tick or skip every instance first'],
      ['token_stored', 'A token is stored again for an instance: delete it again, then finish'],
      ['autostart', 'The login item could not be read or removed'],
      ['no_procedure', 'Delete the stored tokens first'],
      ['recorded', 'The answers are already recorded: finish the removal'],
      // M10 T16 (T28 m-8): another removal step, or a backup in its claim, runs (not `busy`).
      ['running', 'Another removal step or a backup is running: wait for it to end, then try again'],
    ]) {
      vi.mocked(removalState).mockClear();
      vi.mocked(removalFinish).mockRejectedValue({ kind: 'removal', error: { kind } });
      await click('Finish removal');
      expect(screen.getByRole('alert').textContent).toBe(text);
      expect(removalState).toHaveBeenCalledTimes(1);
    }
    // An unknown kind (or one with unusual characters) is never echoed.
    vi.mocked(removalFinish).mockRejectedValue({ kind: 'removal', error: { kind: 'x‮y' } });
    await click('Finish removal');
    expect(screen.getByRole('alert').textContent).toBe('The change was refused');
    expect(screen.getByRole('alert').textContent).not.toContain('‮');
  });

  it('a token_stored refusal is followed by a re-read: the stale ticks give way to the retry button', async () => {
    await show(active(item({ choice: 'done' })));
    expect(disabled('Finish removal')).toBe(false);
    // Rust flipped the item back to "not deleted, not answered" before it refused.
    vi.mocked(removalState).mockResolvedValue(
      active(item({ token_deleted: false, choice: 'pending', error: null })),
    );
    vi.mocked(removalFinish).mockRejectedValue({ kind: 'removal', error: { kind: 'token_stored' } });
    await click('Finish removal');
    expect(
      screen.getAllByRole('alert').map((a) => a.textContent),
    ).toContain('A token is stored again for an instance: delete it again, then finish');
    expect(screen.getByText('A token is stored again for this instance: delete it again.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'I revoked it' })).toBeNull();
    expect(disabled('Finish removal')).toBe(true);
    vi.mocked(removalBegin).mockResolvedValue(active(item()));
    await click('Delete the remaining tokens');
    expect(removalBegin).toHaveBeenCalledWith();
    expect(screen.getByRole('button', { name: 'I revoked it' })).toBeTruthy();
  });

  it('a refused tick or begin reads the state again too', async () => {
    await show(active(item()));
    vi.mocked(removalState).mockClear();
    vi.mocked(removalMark).mockRejectedValue({ kind: 'removal', error: { kind: 'recorded' } });
    await click('I revoked it');
    expect(screen.getByRole('alert').textContent).toBe(
      'The answers are already recorded: finish the removal',
    );
    expect(removalState).toHaveBeenCalledTimes(1);
    cleanup();
    await show(idle);
    vi.mocked(removalState).mockClear();
    vi.mocked(removalBegin).mockRejectedValue({ kind: 'busy' });
    await click('Delete the stored tokens');
    expect(removalState).toHaveBeenCalledTimes(1);
  });

  it('a second click while a command runs sends nothing (in-flight guard)', async () => {
    await show(idle);
    let release: (v: RemovalState) => void = () => undefined;
    vi.mocked(removalBegin).mockReturnValue(
      new Promise<RemovalState>((resolve) => {
        release = resolve;
      }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Delete the stored tokens' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete the stored tokens' }));
    await flush();
    expect(removalBegin).toHaveBeenCalledTimes(1);
    expect(disabled('Create a full backup')).toBe(true);
    expect(disabled('Delete the stored tokens')).toBe(true);
    release(active(item()));
    await flush();
    expect(removalBegin).toHaveBeenCalledTimes(1);
    expect(screen.getByText(REVOKE)).toBeTruthy();
  });

  it('aliases and identities are marked when they hold unusual characters', async () => {
    await show(active(item({ alias: 'wo‮rk', identity: 'jd​oe', origin: 'https://j‮x' })));
    expect(screen.getAllByText('unusual characters').length).toBeGreaterThanOrEqual(3);
    // An ordinary instance carries no mark.
  });

  it('an ordinary instance has no unusual-characters mark', async () => {
    await show(active(item()));
    expect(screen.queryByText('unusual characters')).toBeNull();
  });

  it('all_server_strings_text_nodes: markup in an identity or an origin is text, never elements', async () => {
    const payload = '<img src=x onerror="document.title=1"><b>x</b>';
    const { container } = await show(
      active(item({ identity: payload, origin: payload, alias: 'work' })),
    );
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('li b')).toBeNull();
    expect(container.textContent).toContain(payload);
  });

  it('a failed read shows a retry, not an empty checklist', async () => {
    vi.mocked(removalState).mockRejectedValueOnce({ kind: 'not_ready' });
    render(<Harness />);
    await flush();
    expect(screen.getByRole('alert')).toBeTruthy();
    vi.mocked(removalState).mockResolvedValue(idle);
    await click('Try again');
    expect(screen.getByRole('button', { name: 'Create a full backup' })).toBeTruthy();
  });
});
