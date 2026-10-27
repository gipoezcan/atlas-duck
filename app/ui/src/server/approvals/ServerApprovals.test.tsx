import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import queueFixture from '../../shared/ipc/fixtures/queue_item.json';
import { on } from '../../shared/ipc/events';
import { appStatus, previewFetch, queueList, recentList } from '../../shared/ipc/invoke';
import type { QueueItem } from '../../shared/ipc/types';
import { loadSession } from '../../shared/ipc/transport-http';
import { NOTIFY_TEXT, type NotifyEnv } from './notify';
import { ServerApprovals } from './ServerApprovals';

vi.mock('../../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  queueGet: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../../shared/ipc/events', () => ({ on: vi.fn() }));
vi.mock('../../shared/ipc/transport-http', () => ({ loadSession: vi.fn(), csrf: () => 't' }));

const items: QueueItem[] = queueFixture satisfies QueueItem[];
const [, SECOND] = items as [QueueItem, QueueItem];

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 30; i++) await Promise.resolve();
  });
}

const quietEnv = (request = vi.fn(() => Promise.resolve('granted' as NotificationPermission))): NotifyEnv => ({
  permission: () => 'default',
  request,
  hidden: () => false,
  show: vi.fn(),
});

describe('ServerApprovals', () => {
  beforeEach(() => {
    vi.mocked(loadSession).mockResolvedValue({
      user: 'alice',
      roles: ['user'],
      csrf_token: 't',
      expires_at: '2026-10-27T18:00:00Z',
    });
    vi.mocked(queueList).mockResolvedValue(items);
    vi.mocked(recentList).mockResolvedValue([]);
    vi.mocked(appStatus).mockResolvedValue([]);
    vi.mocked(previewFetch).mockReturnValue(new Promise(() => undefined));
    vi.mocked(on).mockResolvedValue(() => undefined);
  });
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('the_deep_link_opens_its_item_once_the_queue_loads', async () => {
    render(<ServerApprovals item={SECOND.request_id} env={quietEnv()} />);
    await flush();
    expect(vi.mocked(previewFetch).mock.calls.map((c) => c[0])).toContain(SECOND.request_id);
    // The server header replaces the desktop one: no window buttons, no Quit.
    expect(screen.queryByRole('button', { name: 'Quit' })).toBeNull();
    expect(screen.getByText('alice')).toBeTruthy();
  });

  it('without_a_link_nothing_opens', async () => {
    render(<ServerApprovals item={null} env={quietEnv()} />);
    await flush();
    expect(previewFetch).not.toHaveBeenCalled();
  });

  it('asks_for_notification_permission_only_on_click', async () => {
    const request = vi.fn(() => Promise.resolve('granted' as NotificationPermission));
    render(<ServerApprovals item={null} env={quietEnv(request)} />);
    await flush();
    expect(request).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: NOTIFY_TEXT.enable }));
    await flush();
    expect(request).toHaveBeenCalledTimes(1);
    expect(screen.getByText(NOTIFY_TEXT.enabled)).toBeTruthy();
  });
});
