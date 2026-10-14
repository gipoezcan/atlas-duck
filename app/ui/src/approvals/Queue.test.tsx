import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import queueFixture from '../shared/ipc/fixtures/queue_item.json';
import recentFixture from '../shared/ipc/fixtures/recent_item.json';
import statusFixture from '../shared/ipc/fixtures/status_line.json';
import {
  acknowledgeAttention,
  appStatus,
  previewFetch,
  queueList,
  recentList,
} from '../shared/ipc/invoke';
import type { QueueItem, RecentItem, StatusLine } from '../shared/ipc/types';
import { App } from './App';
import { Queue } from './Queue';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

// Typed, not cast: tsc checks the Rust-produced fixture against the wire type.
const base: QueueItem = (queueFixture satisfies QueueItem[])[0] as QueueItem;
const item = (over: Partial<QueueItem>): QueueItem => ({ ...base, ...over });

const SESSION_A = 'a'.repeat(64);
const SESSION_B = 'b'.repeat(64);

describe('Queue', () => {
  it('renders_every_column_as_text', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const { container } = render(
      <Queue
        items={[
          item({
            agent_name: hostile,
            reason_excerpt: '<b>why</b>',
            session_label: 'x · <i>dir</i>',
            possible_duplicate_of: null,
          }),
        ]}
      />,
    );
    expect(container.querySelector('[dangerously]')).toBeNull();
    expect(container.querySelector('img, b, i')).toBeNull();
    const bdi = screen.getByText(`\u201C${hostile}\u201D`);
    expect(bdi.tagName).toBe('BDI');
    // The badge comes before the text, inside the same agent-text wrapper.
    const wrapper = bdi.parentElement as HTMLElement;
    const badge = within(wrapper).getByText('unverified');
    expect(badge.compareDocumentPosition(bdi) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    for (const text of ['jira.issue.get', 'work', 'PROJ-1', 'Read', '12 s']) {
      expect(screen.getByText(text)).toBeTruthy();
    }
    expect(screen.getByText('\u201C<b>why</b>\u201D').tagName).toBe('BDI');
  });

  it('shows_no_reason_badge_and_unusual_flag', () => {
    render(<Queue items={[item({ reason_excerpt: '', unusual: true, possible_duplicate_of: null })]} />);
    expect(screen.getByLabelText('no reason given')).toBeTruthy();
    expect(screen.getAllByLabelText('unusual characters').length).toBeGreaterThan(0);
  });

  it('ui05_similar_and_duplicate_flags_rendered_text_labelled', () => {
    const other = item({
      request_id: 'req_abcdefghij0123456789',
      session_id: SESSION_B,
      session_label: 'other-agent · elsewhere',
      possible_duplicate_of: null,
    });
    const flagged = item({ similar_to: 'req_zzzzzzzzzzzzzzzzzzzz' });
    render(<Queue items={[flagged, other]} />);
    const dup = screen.getByLabelText('possible duplicate');
    expect(dup.textContent).toBe('possible duplicate');
    // The flag names the other item's session, as agent text behind the badge.
    const flag = dup.parentElement as HTMLElement;
    expect(within(flag).getByText('\u201Cother-agent · elsewhere\u201D').tagName).toBe('BDI');
    expect(flag.textContent).toContain('req_abcdefghij0123456789');
    expect(screen.getByLabelText('similar request').textContent).toBe('similar request');
  });

  it('ui05_similar_outcome_unknown_caution_rendered', () => {
    // "similar to req_ ... outcome unknown" is a Caution warning: it arrives as caution_count.
    render(
      <Queue
        items={[item({ similar_to: 'req_zzzzzzzzzzzzzzzzzzzz', caution_count: 2, possible_duplicate_of: null })]}
      />,
    );
    expect(screen.getByLabelText('caution (2)').textContent).toBe('caution (2)');
    expect(screen.getByLabelText('similar request')).toBeTruthy();
  });

  it('u34_info_never_counts_in_caution_badge', () => {
    // Info warnings never reach the list: a row with no Caution warning has no caution badge.
    render(<Queue items={[item({ caution_count: 0, possible_duplicate_of: null })]} />);
    expect(screen.queryByText(/caution/)).toBeNull();
  });

  it('stale_flag_is_text_and_pins_its_group_first', () => {
    const calm = item({ request_id: 'req_calmcalmcalmcalmcalm', session_id: SESSION_A, possible_duplicate_of: null });
    const stale = item({
      request_id: 'req_stalestalestalestale',
      session_id: SESSION_B,
      stale: true,
      possible_duplicate_of: null,
    });
    render(<Queue items={[calm, stale]} />);
    const boxes = screen.getAllByRole('checkbox', { name: /^select jira/ });
    expect(boxes).toHaveLength(2);
    expect(screen.getAllByLabelText('stale')).toHaveLength(1);
    const rows = screen.getAllByRole('listitem');
    // group header, stale item, then the calm group.
    expect(within(rows[1] as HTMLElement).getByLabelText('stale')).toBeTruthy();
  });

  it('x13_grouped_by_session_select_all', () => {
    const onSelectionChange = vi.fn();
    const mk = (id: string, session: string, target: string) =>
      item({ request_id: id, session_id: session, target_display: target, possible_duplicate_of: null });
    render(
      <Queue
        onSelectionChange={onSelectionChange}
        items={[
          mk('req_a1a1a1a1a1a1a1a1a1a1', SESSION_A, 'A-1'),
          mk('req_a2a2a2a2a2a2a2a2a2a2', SESSION_A, 'A-2'),
          mk('req_b1b1b1b1b1b1b1b1b1b1', SESSION_B, 'B-1'),
        ]}
      />,
    );
    const groups = screen.getAllByRole('checkbox', { name: /^select all from session/ });
    expect(groups).toHaveLength(2);
    fireEvent.click(groups[0] as HTMLElement);
    expect(onSelectionChange).toHaveBeenLastCalledWith(['req_a1a1a1a1a1a1a1a1a1a1', 'req_a2a2a2a2a2a2a2a2a2a2']);
    expect((screen.getByRole('checkbox', { name: 'select jira.issue.get A-1' }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole('checkbox', { name: 'select jira.issue.get B-1' }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(groups[0] as HTMLElement);
    expect(onSelectionChange).toHaveBeenLastCalledWith([]);
  });

  it('null_agent_name_and_reason_render_as_fixed_text', () => {
    render(<Queue items={[item({ agent_name: null, reason_excerpt: null, possible_duplicate_of: null })]} />);
    expect(screen.getByText('“(no agent name)”').tagName).toBe('BDI');
    expect(screen.getByLabelText('no reason given')).toBeTruthy();
  });

  it('the_unusual_flag_follows_the_agent_name_and_the_reason', () => {
    render(
      <Queue
        items={[item({ agent_name: 'n'.repeat(500), unusual: true, possible_duplicate_of: null })]}
      />,
    );
    // One flag per agent string of the row (name, reason) and one for the session group.
    expect(screen.getAllByLabelText('unusual characters')).toHaveLength(3);
  });

  it('the_group_checkbox_name_includes_its_session', () => {
    render(
      <Queue
        items={[
          item({ session_id: SESSION_A, session_label: 'agent-a', possible_duplicate_of: null }),
          item({ request_id: 'req_otherotherotherother', session_id: SESSION_B, session_label: 'agent-b', possible_duplicate_of: null }),
        ]}
      />,
    );
    const boxes = screen.getAllByRole('checkbox', { name: /^select all from session/ });
    const names = boxes.map((b) => b.getAttribute('aria-labelledby'));
    expect(new Set(names).size).toBe(2);
    expect(screen.getByRole('checkbox', { name: /select all from session.*agent-a/ })).toBeTruthy();
    expect(screen.getByRole('checkbox', { name: /select all from session.*agent-b/ })).toBeTruthy();
  });

  it('an_inline_selection_callback_that_sets_parent_state_does_not_loop', () => {
    function Parent() {
      const [ids, setIds] = useState<string[]>([]);
      return (
        <>
          <output>{ids.length}</output>
          <Queue items={[item({ possible_duplicate_of: null })]} onSelectionChange={(next) => setIds(next)} />
        </>
      );
    }
    render(<Parent />);
    fireEvent.click(screen.getByRole('checkbox', { name: 'select jira.issue.get PROJ-1' }));
    expect(screen.getByRole('status').textContent).toBe('1');
  });

  it('empty_queue_says_so', () => {
    render(<Queue items={[]} />);
    expect(screen.getByText('No pending requests')).toBeTruthy();
  });
});

describe('Approvals window', () => {
  const handlers = new Map<string, ((payload: unknown) => void)[]>();

  beforeEach(() => {
    handlers.clear();
    vi.mocked(on).mockReset().mockImplementation((name, handler) => {
      handlers.set(name, [...(handlers.get(name) ?? []), handler as (payload: unknown) => void]);
      return Promise.resolve(() => undefined);
    });
    vi.mocked(queueList).mockReset().mockResolvedValue(queueFixture);
    vi.mocked(recentList).mockReset().mockResolvedValue(recentFixture satisfies RecentItem[]);
    vi.mocked(appStatus)
      .mockReset()
      .mockResolvedValue(statusFixture as StatusLine[]);
    vi.mocked(acknowledgeAttention).mockReset().mockResolvedValue(null);
    vi.mocked(previewFetch).mockReset();
  });

  it('auto_display_never_fetches_preview', async () => {
    render(<App />);
    await screen.findByRole('checkbox', { name: 'select jira.issue.get PROJ-1' });
    expect(queueList).toHaveBeenCalledTimes(1);

    vi.mocked(queueList).mockResolvedValue([item({ target_display: 'PROJ-9', possible_duplicate_of: null })]);
    await act(async () => {
      for (const h of handlers.get('queue_changed') ?? []) h({ request_ids: ['req_0123456789abcdefghij'] });
    });
    await screen.findByRole('checkbox', { name: 'select jira.issue.get PROJ-9' });
    expect(queueList).toHaveBeenCalledTimes(2);
    expect(previewFetch).not.toHaveBeenCalled();
  });

  it('acknowledging_re_reads_the_recent_list_and_banner', async () => {
    render(<App />);
    const pinned = await screen.findByRole('region', { name: 'Needs attention' });
    vi.mocked(recentList).mockResolvedValue(recentFixture.map((r) => ({ ...r, acknowledged: true })));
    fireEvent.click(within(pinned).getByRole('button', { name: 'Acknowledge all' }));
    await waitFor(() => expect(acknowledgeAttention).toHaveBeenCalledWith(['req_0123456789abcdefghij']));
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Needs attention' })).toBeNull());
    expect(appStatus).toHaveBeenCalledTimes(2);
  });

  it('a_failed_read_is_announced', async () => {
    vi.mocked(queueList).mockRejectedValue({ kind: 'not_ready' });
    render(<App />);
    expect((await screen.findAllByRole('alert'))[0]?.textContent).toBe('Could not load the queue');
    // A failure is not an empty queue.
    expect(screen.queryByText('No pending requests')).toBeNull();
  });

  it('loading_is_not_the_empty_state', async () => {
    vi.mocked(queueList).mockReturnValue(new Promise(() => undefined));
    vi.mocked(recentList).mockReturnValue(new Promise(() => undefined));
    render(<App />);
    expect(await screen.findByText('Loading the queue')).toBeTruthy();
    expect(screen.queryByText('No pending requests')).toBeNull();
    expect(screen.queryByText('Nothing decided in the last 24 hours')).toBeNull();
  });

  it('a_null_agent_name_does_not_hide_the_queue', async () => {
    vi.mocked(queueList).mockResolvedValue(queueFixture);
    render(<App />);
    await screen.findByRole('checkbox', { name: 'select jira.issue.create PROJ' });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('an_older_read_that_resolves_last_is_ignored', async () => {
    render(<App />);
    await screen.findByRole('checkbox', { name: 'select jira.issue.get PROJ-1' });
    let resolveOld: (v: QueueItem[]) => void = () => undefined;
    vi.mocked(queueList).mockReturnValueOnce(new Promise((r) => (resolveOld = r)));
    vi.mocked(queueList).mockResolvedValueOnce([item({ target_display: 'NEW-1', possible_duplicate_of: null })]);
    await act(async () => {
      for (const h of handlers.get('queue_changed') ?? []) h({});
      for (const h of handlers.get('queue_changed') ?? []) h({});
    });
    await screen.findByRole('checkbox', { name: 'select jira.issue.get NEW-1' });
    await act(async () => {
      resolveOld([item({ target_display: 'OLD-1', possible_duplicate_of: null })]);
    });
    expect(screen.queryByRole('checkbox', { name: 'select jira.issue.get OLD-1' })).toBeNull();
    expect(screen.getByRole('checkbox', { name: 'select jira.issue.get NEW-1' })).toBeTruthy();
  });

  it('the_first_read_happens_after_the_listeners_are_attached', async () => {
    const order: string[] = [];
    vi.mocked(on).mockImplementation((name) => {
      order.push(`on:${name}`);
      return Promise.resolve(() => undefined);
    });
    vi.mocked(queueList).mockImplementation(() => {
      order.push('queue_list');
      return Promise.resolve([]);
    });
    render(<App />);
    await waitFor(() => expect(order).toContain('queue_list'));
    expect(order.indexOf('on:queue_changed')).toBeLessThan(order.indexOf('queue_list'));
  });
});
