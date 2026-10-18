import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import { runningKill, runningList } from '../shared/ipc/invoke';
import type { KillAnswer, RunningScriptView } from '../shared/ipc/types';
import { Running } from './Running';

vi.mock('../shared/ipc/invoke', () => ({ runningKill: vi.fn(), runningList: vi.fn() }));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const REQ = 'req_0123456789abcdefghij';
const REQ_2 = 'req_abcdefghij0123456789';

const run = (over: Partial<RunningScriptView> = {}): RunningScriptView => ({
  request_id: REQ,
  agent_name: 'claude-code-billing-api',
  instances: ['jira-main', 'wiki'],
  started_at: '2026-10-15T08:30:00.000Z',
  elapsed_ms: 93_500,
  host_calls: 4,
  bytes_fetched: 182_400,
  ...over,
});

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const handlers: Record<string, ((payload: unknown) => void)[]> = {};

async function show(rows: RunningScriptView[]) {
  vi.mocked(runningList).mockResolvedValue(rows);
  render(<Running />);
  await flush();
}

async function emit(name: string): Promise<void> {
  act(() => {
    for (const h of handlers[name] ?? []) h(null);
  });
  await flush();
}

const killButtons = () =>
  screen.queryAllByRole('button', { name: /^Kill the script/ }) as HTMLButtonElement[];

beforeEach(() => {
  for (const k of Object.keys(handlers)) delete handlers[k];
  vi.mocked(on)
    .mockReset()
    .mockImplementation((name, handler) => {
      (handlers[name] ??= []).push(handler as (payload: unknown) => void);
      return Promise.resolve(() => undefined);
    });
  vi.mocked(runningList).mockReset();
  vi.mocked(runningKill).mockReset();
});

describe('Running scripts shell', () => {
  it('running_shell_lists_and_kill_button: one row per run, a kill button asks Rust for that id', async () => {
    await show([run(), run({ request_id: REQ_2, agent_name: null, host_calls: 0 })]);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Running scripts');
    const table = screen.getByRole('table', { name: 'Running scripts' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]?.textContent).toContain(REQ);
    expect(rows[0]?.textContent).toContain('claude-code-billing-api');
    expect(rows[0]?.textContent).toContain('2026-10-15T08:30:00.000Z');
    expect(rows[1]?.textContent).toContain('no agent name');
    expect(killButtons()).toHaveLength(2);

    vi.mocked(runningKill).mockResolvedValue({ answer: 'killed' });
    // The list after the kill: the run is gone.
    vi.mocked(runningList).mockResolvedValue([run({ request_id: REQ_2, agent_name: null })]);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: `Kill the script ${REQ}` }));
    });
    await flush();
    expect(runningKill).toHaveBeenCalledTimes(1);
    expect(runningKill).toHaveBeenCalledWith(REQ);
    expect(screen.getByRole('status').textContent).toBe('Kill requested');
    expect(killButtons()).toHaveLength(1);
  });

  it('shows the empty state, and reads again on running_scripts_changed for this window only', async () => {
    await show([]);
    expect(screen.getByText('No scripts are running.')).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
    const calls = vi.mocked(on).mock.calls;
    expect(calls.map((c) => c[0])).toEqual(['running_scripts_changed']);
    expect(calls[0]?.[2]).toEqual({ thisWindow: true });
    vi.mocked(runningList).mockResolvedValue([run()]);
    await emit('running_scripts_changed');
    expect(killButtons()).toHaveLength(1);
  });

  it('agent text and ids are text nodes, never markup', async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>';
    await show([run({ agent_name: hostile })]);
    const table = screen.getByRole('table');
    expect(table.querySelector('img, script')).toBeNull();
    expect(table.textContent).toContain(hostile);
    // Agent text always carries its "unverified" badge.
    expect(within(table).getByText('unverified')).toBeTruthy();
    expect((window as unknown as Record<string, unknown>)['__pwned']).toBeUndefined();
  });

  it('x11_columns_agent_instances_started_elapsed_calls_bytes: one cell per column, Rust values as text', async () => {
    await show([
      run(),
      run({
        request_id: REQ_2,
        agent_name: null,
        instances: [],
        elapsed_ms: 4_000,
        host_calls: 0,
        bytes_fetched: 0,
      }),
      run({ request_id: 'req_zzzzzzzzzz0123456789', elapsed_ms: 3_725_000, bytes_fetched: 5_452_595 }),
    ]);
    const table = screen.getByRole('table', { name: 'Running scripts' });
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((h) => h.textContent);
    expect(headers).toEqual([
      'Request',
      'Agent',
      'Instances',
      'Started',
      'Elapsed',
      'Host calls',
      'Bytes fetched',
      'Actions',
    ]);
    const cells = (i: number) =>
      within(within(table).getAllByRole('row')[i + 1] as HTMLElement)
        .getAllByRole('cell')
        .map((c) => c.textContent);
    const first = cells(0);
    expect(first[0]).toBe(REQ);
    expect(first[1]).toContain('claude-code-billing-api');
    expect(first.slice(2, 7)).toEqual([
      'jira-main, wiki',
      '2026-10-15T08:30:00.000Z',
      '1 min 33 s',
      '4',
      '178.1 KiB',
    ]);
    expect(cells(1).slice(1, 7)).toEqual(['no agent name', 'none yet', '2026-10-15T08:30:00.000Z', '4 s', '0', '0 B']);
    expect(cells(2).slice(4, 7)).toEqual(['1 h 2 min', '4', '5.2 MiB']);
  });

  it('kill_answers_texts: each of the three answers has its own text (PD-143)', async () => {
    const cases: [KillAnswer['answer'], string][] = [
      ['killed', 'Kill requested'],
      ['not_running', 'That script is no longer running.'],
      ['already_stopping', 'That script is already stopping.'],
    ];
    await show([run()]);
    for (const [answer, text] of cases) {
      vi.mocked(runningKill).mockResolvedValueOnce({ answer });
      await act(async () => {
        fireEvent.click(killButtons()[0] as HTMLButtonElement);
      });
      await flush();
      expect(screen.getByRole('status').textContent).toBe(text);
    }
  });

  it('relists_on_event_and_every_second_while_visible: a timer read per second, none while hidden', async () => {
    vi.useFakeTimers();
    let state: DocumentVisibilityState = 'visible';
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
    const visibility = {
      mockReturnValue: (s: DocumentVisibilityState) => {
        state = s;
      },
    };
    try {
      visibility.mockReturnValue('visible');
      vi.mocked(runningList).mockResolvedValue([run()]);
      render(<Running />);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      const base = vi.mocked(runningList).mock.calls.length;
      expect(base).toBeGreaterThanOrEqual(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3_000);
      });
      expect(vi.mocked(runningList).mock.calls.length).toBe(base + 3);
      // An event reads at once, without waiting for the timer.
      await emit('running_scripts_changed');
      expect(vi.mocked(runningList).mock.calls.length).toBe(base + 4);
      // Hidden: no timer reads.
      visibility.mockReturnValue('hidden');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3_000);
      });
      expect(vi.mocked(runningList).mock.calls.length).toBe(base + 4);
      // Visible again: one read at once, then the timer.
      visibility.mockReturnValue('visible');
      act(() => {
        document.dispatchEvent(new Event('visibilitychange'));
      });
      await flush();
      expect(vi.mocked(runningList).mock.calls.length).toBe(base + 5);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_000);
      });
      expect(vi.mocked(runningList).mock.calls.length).toBe(base + 6);
    } finally {
      Reflect.deleteProperty(document, 'visibilityState');
      vi.useRealTimers();
    }
  });

  it('agent_name_after_unverified_badge_isolated: the badge comes first, the name sits in its own bdi', async () => {
    const name = 'abc‮evil⁩';
    await show([run({ agent_name: name })]);
    const table = screen.getByRole('table');
    const cell = within(table).getAllByRole('row')[1]?.querySelectorAll('td')[1] as HTMLElement;
    const badge = within(cell).getByText('unverified');
    const bdi = cell.querySelector('bdi') as HTMLElement;
    expect(bdi.textContent).toContain(name);
    expect(badge.compareDocumentPosition(bdi) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(cell.textContent?.startsWith('unverified')).toBe(true);
    // The name is in the isolated element only.
    expect(cell.textContent?.replace(bdi.textContent ?? '', '')).not.toContain('abc');
  });

  it('a kill answered not_running says the script already ended; a failed kill is an alert', async () => {
    await show([run()]);
    vi.mocked(runningKill).mockResolvedValueOnce({ answer: 'not_running' });
    await act(async () => {
      fireEvent.click(killButtons()[0] as HTMLButtonElement);
    });
    await flush();
    expect(screen.getByRole('status').textContent).toBe('That script is no longer running.');
    vi.mocked(runningKill).mockRejectedValueOnce({ kind: 'internal' });
    await act(async () => {
      fireEvent.click(killButtons()[0] as HTMLButtonElement);
    });
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('Could not stop the script.');
  });

  it('one kill at a time: every kill button is off meanwhile and a second click is dropped', async () => {
    await show([run(), run({ request_id: REQ_2 })]);
    let finish: (a: KillAnswer) => void = () => undefined;
    vi.mocked(runningKill).mockReturnValue(new Promise<KillAnswer>((resolve) => (finish = resolve)));
    const [first, second] = killButtons() as [HTMLButtonElement, HTMLButtonElement];
    act(() => {
      fireEvent.click(first);
      fireEvent.click(first);
      fireEvent.click(second);
    });
    expect(runningKill).toHaveBeenCalledTimes(1);
    expect(killButtons().every((b) => b.disabled)).toBe(true);
    expect(first.textContent).toBe('Stopping…');
    await act(async () => {
      finish({ answer: 'killed' });
      await Promise.resolve();
    });
    await flush();
    expect(killButtons().every((b) => !b.disabled)).toBe(true);
    expect(runningKill).toHaveBeenCalledTimes(1);
  });

  it('a failed load is a fixed alert with a retry', async () => {
    vi.mocked(runningList).mockRejectedValueOnce({ kind: 'not_ready' });
    render(<Running />);
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Could not load the running scripts');
    vi.mocked(runningList).mockResolvedValue([run()]);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    });
    await flush();
    expect(killButtons()).toHaveLength(1);
  });
});
