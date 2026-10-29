import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { on } from '../shared/ipc/events';
import { runningKill, runningList } from '../shared/ipc/invoke';
import { Running } from './Running';

vi.mock('../shared/ipc/invoke', () => ({ runningKill: vi.fn(), runningList: vi.fn() }));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

beforeEach(() => {
  vi.mocked(on).mockReset().mockResolvedValue(() => undefined);
  vi.mocked(runningList).mockReset();
  vi.mocked(runningKill).mockReset();
});

afterEach(() => {
  cleanup();
});

describe('the running scripts window in German (M15 T6)', () => {
  it('running_window_in_german: texts, German bytes and time', async () => {
    vi.mocked(runningList).mockResolvedValue([
      {
        request_id: 'req_0123456789abcdefghij',
        agent_name: null,
        instances: [],
        started_at: '2026-10-15T08:30:00.000Z',
        elapsed_ms: 3_723_000,
        host_calls: 4,
        bytes_fetched: 182_400,
      },
    ]);
    render(
      <LangProvider lang="de">
        <Running />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.approvals.window_titles.running_scripts);
    const table = screen.getByRole('table', { name: de.running.list_label });
    const row = within(table).getAllByRole('row')[1] as HTMLElement;
    expect(row.textContent).toContain('15.10.2026, 08:30 UTC');
    expect(row.textContent).toContain('1 h 2 min');
    expect(row.textContent).toContain('178,1 KiB');
    expect(row.textContent).toContain(de.running.no_agent);
    expect(row.textContent).toContain(de.running.no_instances);
    expect(screen.getByRole('button', { name: de.running.kill_label('req_0123456789abcdefghij') })).toBeTruthy();
    expect(screen.queryByRole('button', { name: en.running.kill_label('req_0123456789abcdefghij') })).toBeNull();
  });

  it('empty_list_in_german', async () => {
    vi.mocked(runningList).mockResolvedValue([]);
    render(
      <LangProvider lang="de">
        <Running />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByText(de.running.empty)).toBeTruthy();
  });
});