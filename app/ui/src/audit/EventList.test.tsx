import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { auditQuery } from '../shared/ipc/invoke';
import type { AuditPage, EventHeader } from '../shared/ipc/types';
import { EventList, FOLLOW_LIMIT } from './EventList';
import { flush, header } from './testing';

vi.mock('../shared/ipc/invoke', () => ({ auditQuery: vi.fn() }));

const page = (rows: EventHeader[], next: AuditPage['next'], scanned: number): AuditPage => ({
  rows,
  next,
  scanned,
});

beforeEach(() => {
  vi.mocked(auditQuery).mockReset();
});

describe('Audit event list (spec 8.10, PD-74)', () => {
  it('follows `next` over an empty page: the row budget ended the scan, not the log', async () => {
    vi.mocked(auditQuery)
      .mockResolvedValueOnce(page([], { before_seq: 100, limit: 200 }, 20_000))
      .mockResolvedValueOnce(page([header(5)], null, 99));
    render(<EventList filter={{ agent_name: 'a' }} selected={null} onOpen={() => undefined} />);
    await flush();
    expect(auditQuery).toHaveBeenCalledTimes(2);
    expect(vi.mocked(auditQuery).mock.calls[0]).toEqual([{ agent_name: 'a' }]);
    // The cursor goes back exactly as Rust sent it.
    expect(vi.mocked(auditQuery).mock.calls[1]).toEqual([{ agent_name: 'a' }, { before_seq: 100, limit: 200 }]);
    expect(screen.getByRole('button', { name: 'Open record 5' })).toBeTruthy();
    expect(screen.getByText('1 shown, 20099 examined')).toBeTruthy();
    expect(screen.getByText('End of the log.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('stops after a bounded number of empty pages and offers to keep searching', async () => {
    vi.mocked(auditQuery).mockImplementation((_f, c) =>
      Promise.resolve(page([], { before_seq: (c?.before_seq ?? 1_000_000) - 20_000, limit: 200 }, 20_000)),
    );
    render(<EventList filter={{}} selected={null} onOpen={() => undefined} />);
    await flush();
    expect(auditQuery).toHaveBeenCalledTimes(FOLLOW_LIMIT);
    expect(screen.getByText('More records may match: load more to keep searching.')).toBeTruthy();
    expect(screen.queryByText('No records match.')).toBeNull();
    vi.mocked(auditQuery).mockResolvedValueOnce(page([header(3)], null, 10));
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await flush();
    expect(vi.mocked(auditQuery).mock.calls[FOLLOW_LIMIT]?.[1]).toEqual({
      before_seq: 1_000_000 - 20_000 * FOLLOW_LIMIT,
      limit: 200,
    });
    expect(screen.getByRole('button', { name: 'Open record 3' })).toBeTruthy();
    expect(screen.getByText('End of the log.')).toBeTruthy();
  });

  it('a full page keeps its rows and loads the next one only when asked', async () => {
    vi.mocked(auditQuery).mockResolvedValueOnce(page([header(9), header(8)], { before_seq: 8, limit: 200 }, 3));
    render(<EventList filter={{}} selected={null} onOpen={() => undefined} />);
    await flush();
    expect(auditQuery).toHaveBeenCalledTimes(1);
    vi.mocked(auditQuery).mockResolvedValueOnce(page([header(7)], null, 2));
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await flush();
    const list = screen.getByRole('list', { name: 'Audit records, newest first' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByText('3 shown, 5 examined')).toBeTruthy();
  });

  it('a failed read is an alert and Load more retries from the same position', async () => {
    vi.mocked(auditQuery)
      .mockResolvedValueOnce(page([header(9)], { before_seq: 9, limit: 200 }, 1))
      .mockRejectedValueOnce({ kind: 'audit', error: { kind: 'failed' } });
    render(<EventList filter={{}} selected={null} onOpen={() => undefined} />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Could not read the records');
    vi.mocked(auditQuery).mockResolvedValueOnce(page([], null, 0));
    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    await flush();
    expect(vi.mocked(auditQuery).mock.calls[2]?.[1]).toEqual({ before_seq: 9, limit: 200 });
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('nothing found is said; a row is text, the agent name behind the "unverified" badge', async () => {
    vi.mocked(auditQuery).mockResolvedValueOnce(page([], null, 7));
    const { unmount } = render(<EventList filter={{}} selected={null} onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText('No records match.')).toBeTruthy();
    unmount();

    const onOpen = vi.fn();
    const h = header(41, {
      agent_name: '<img src=x onerror=alert(1)>',
      target: 'PROJ-7‮',
      flags: ['redacted', 'integrity_incident'],
      event_type: 'CREDENTIAL_CHANGED',
    });
    vi.mocked(auditQuery).mockResolvedValueOnce(page([h], null, 1));
    render(<EventList filter={{}} selected={41} onOpen={onOpen} />);
    await flush();
    const row = screen.getByRole('listitem');
    expect(row.querySelector('img')).toBeNull();
    expect(row.textContent).toContain('“<img src=x onerror=alert(1)>”');
    expect(within(row).getAllByRole('note').map((n) => n.textContent)).toEqual(
      expect.arrayContaining(['unverified', 'redacted', 'integrity incident', 'unusual characters']),
    );
    expect(row.textContent).toContain('CREDENTIAL_CHANGED');
    const open = within(row).getByRole('button', { name: 'Open record 41' });
    expect(open.getAttribute('aria-current')).toBe('true');
    fireEvent.click(open);
    expect(onOpen).toHaveBeenCalledWith(h);
  });
});
