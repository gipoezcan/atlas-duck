import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { auditTrail } from '../shared/ipc/invoke';
import type { AuditTrail } from '../shared/ipc/types';
import { deferred, flush, header } from './testing';
import { Trail } from './Trail';

vi.mock('../shared/ipc/invoke', () => ({ auditTrail: vi.fn() }));

beforeEach(() => {
  vi.mocked(auditTrail).mockReset();
});

const MORE_THAN_ONCE = 'delivered more than once';
const OTHER_PROGRAM = 'delivered to a different program';

describe('Audit request trail (spec 8.10)', () => {
  it('trail_highlights_multi_delivery_text_labelled: both marks are text, with the advisory wording', async () => {
    vi.mocked(auditTrail).mockResolvedValueOnce({
      headers: [
        header(10, { event_type: 'REQUEST_RECEIVED', decision: null }),
        header(12, { event_type: 'READ_RELEASED' }),
        header(13, { event_type: 'DELIVERED', decision: null }),
        header(14, { event_type: 'DELIVERED', decision: null, peer_origin_exe: '/tmp/other' }),
      ],
      deliveries: { count: 2, to_other_peer: true },
    });
    const onOpen = vi.fn();
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={onOpen} />);
    await flush();
    expect(auditTrail).toHaveBeenCalledWith('req_0123456789abcdefghij');
    const region = screen.getByRole('region', { name: 'Request trail' });
    // Oldest first, as Rust answered.
    const items = within(region).getAllByRole('listitem');
    expect(items.map((li) => li.textContent?.match(/REQUEST_RECEIVED|READ_RELEASED|DELIVERED/)?.[0])).toEqual([
      'REQUEST_RECEIVED',
      'READ_RELEASED',
      'DELIVERED',
      'DELIVERED',
    ]);
    expect(within(region).getByText('Delivered 2 times')).toBeTruthy();
    // The highlight is a text label (never colour alone) and its accessible name says the same.
    const notes = within(region).getAllByRole('note');
    expect(notes.map((n) => n.getAttribute('aria-label'))).toEqual(
      expect.arrayContaining([MORE_THAN_ONCE, OTHER_PROGRAM]),
    );
    expect(within(region).getByText(/^Advisory:/)).toBeTruthy();
    fireEvent.click(within(region).getByRole('button', { name: 'Open record 14' }));
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ seq: 14, event_type: 'DELIVERED' }));
  });

  it('one delivery to the submitter carries no mark', async () => {
    vi.mocked(auditTrail).mockResolvedValueOnce({
      headers: [header(10), header(11, { event_type: 'DELIVERED' })],
      deliveries: { count: 1, to_other_peer: false },
    });
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText('Delivered 1 time')).toBeTruthy();
    expect(screen.queryByText(MORE_THAN_ONCE)).toBeNull();
    expect(screen.queryByText(OTHER_PROGRAM)).toBeNull();
    expect(screen.queryByText(/^Advisory:/)).toBeNull();
  });

  it('each mark alone', async () => {
    vi.mocked(auditTrail).mockResolvedValueOnce({ headers: [], deliveries: { count: 1, to_other_peer: true } });
    const { unmount } = render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText(OTHER_PROGRAM)).toBeTruthy();
    expect(screen.queryByText(MORE_THAN_ONCE)).toBeNull();
    unmount();
    vi.mocked(auditTrail).mockResolvedValueOnce({ headers: [], deliveries: { count: 3, to_other_peer: false } });
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText(MORE_THAN_ONCE)).toBeTruthy();
    expect(screen.queryByText(OTHER_PROGRAM)).toBeNull();
  });

  it('an unreadable record of the request is named; other failures are a fixed sentence', async () => {
    vi.mocked(auditTrail).mockRejectedValueOnce({ kind: 'audit', error: { kind: 'unreadable', seq: 17 } });
    const { unmount } = render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(
      'Record 17 of this request could not be read, so its trail cannot be shown. Its records are still in the list.',
    );
    unmount();
    // What `call()` turns a rejection it does not recognise into.
    vi.mocked(auditTrail).mockRejectedValueOnce({ kind: 'refused', message: 'command not allowed' });
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('Could not read the trail of this request.');
  });

  it('the answer of an earlier request never replaces the one now shown', async () => {
    const first = deferred<AuditTrail>();
    vi.mocked(auditTrail).mockReturnValueOnce(first.promise);
    vi.mocked(auditTrail).mockResolvedValueOnce({ headers: [], deliveries: { count: 1, to_other_peer: false } });
    const { rerender } = render(<Trail requestId="req_aaaaaaaaaaaaaaaaaaaa" onOpen={() => undefined} />);
    rerender(<Trail requestId="req_bbbbbbbbbbbbbbbbbbbb" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText('Delivered 1 time')).toBeTruthy();
    first.resolve({ headers: [], deliveries: { count: 5, to_other_peer: false } });
    await flush();
    expect(screen.getByText('Delivered 1 time')).toBeTruthy();
    expect(screen.queryByText('Delivered 5 times')).toBeNull();
  });

  it('an answer that comes after the trail was closed changes nothing and raises nothing', async () => {
    const late = deferred<AuditTrail>();
    vi.mocked(auditTrail).mockReturnValueOnce(late.promise);
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { unmount, container } = render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    unmount();
    late.resolve({ headers: [], deliveries: { count: 2, to_other_peer: false } });
    await flush();
    expect(container.textContent).toBe('');
    expect(errors).not.toHaveBeenCalled();
    errors.mockRestore();
  });

  it('the status region is there empty before the trail is asked for, and says "reading" once it is', async () => {
    const pending = deferred<AuditTrail>();
    vi.mocked(auditTrail).mockReturnValueOnce(pending.promise);
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    const region = screen.getByRole('status');
    await flush();
    expect(screen.getByRole('status')).toBe(region);
    expect(region.textContent).toBe('Reading the trail');
    pending.resolve({ headers: [], deliveries: { count: 1, to_other_peer: false } });
    await flush();
    expect(region.textContent).toBe('');
  });

  it('the time of a record is a bidi-isolated text node like every other column', async () => {
    vi.mocked(auditTrail).mockResolvedValueOnce({
      headers: [header(10, { ts_utc: '2026-10-19T08:30:15.250Z' })],
      deliveries: { count: 0, to_other_peer: false },
    });
    render(<Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />);
    await flush();
    expect(screen.getByText('2026-10-19 08:30 UTC').tagName).toBe('BDI');
  });
});
