import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { acknowledgeIncident } from '../shared/ipc/invoke';
import type { Acknowledged } from '../shared/ipc/types';
import { Incidents } from './Incidents';
import { deferred, flush, status } from './testing';

vi.mock('../shared/ipc/invoke', () => ({ acknowledgeIncident: vi.fn() }));

beforeEach(() => {
  vi.mocked(acknowledgeIncident).mockReset();
});

const TWO = status(
  {
    incident_count: 150,
    open_incidents: [
      { verify_seq: 42, result: 'anchor_missing', detected_at: '2026-10-19T08:31:00.000Z' },
      { verify_seq: 7, result: null, detected_at: null },
    ],
    anchor_dir: '\\\\nas\\audit\\anchors',
  },
  { open_incidents: 150, anchor_dir_write_failing: true, anchor_dir_lines_pending: 12 },
);

describe('Audit integrity incidents (spec 8.7, PD-180, L134)', () => {
  it('incident_count_and_ack_flow: the count, the list, the note, Rust confirms, the result', async () => {
    const onChanged = vi.fn();
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={onChanged} />);
    const region = screen.getByRole('region', { name: 'Integrity incidents' });
    expect(within(region).getByText('150 open integrity incidents')).toBeTruthy();
    expect(within(region).getByText('The newest 2 of 150 are listed here.')).toBeTruthy();
    const items = within(region).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]?.textContent).toContain('Incident 42');
    expect(items[0]?.textContent).toContain('anchor_missing');
    expect(items[0]?.textContent).toContain('2026-10-19 08:31 UTC');
    expect(items[1]?.textContent).toContain('its record could not be read');
    // The anchor directory, display only, and its failing writes (spec 8.5: shown, never an incident).
    expect(region.textContent).toContain('\\\\nas\\audit\\anchors');
    expect(region.textContent).toContain('Writing to the anchor directory fails; 12 lines wait and will be retried.');

    // The note field opens focused; it holds at most 1000 characters.
    fireEvent.click(within(region).getByRole('button', { name: 'Acknowledge integrity incident 42' }));
    const note = within(region).getByLabelText('Note (up to 1000 characters)') as HTMLTextAreaElement;
    expect(document.activeElement).toBe(note);
    expect(note.maxLength).toBe(1000);
    fireEvent.change(note, { target: { value: 'checked with the custodian' } });
    const pending = deferred<Acknowledged>();
    vi.mocked(acknowledgeIncident).mockReturnValueOnce(pending.promise);
    const send = within(region).getByRole('button', { name: 'Acknowledge…' }) as HTMLButtonElement;
    fireEvent.click(send);
    fireEvent.click(send);
    expect(acknowledgeIncident).toHaveBeenCalledTimes(1);
    expect(acknowledgeIncident).toHaveBeenCalledWith(42, 'checked with the custodian');
    expect(send.disabled).toBe(true);
    pending.resolve({ verify_seq: 42, ack_seq: 57 });
    await flush();
    expect(within(region).getByRole('status').textContent).toBe(
      'Incident 42 was acknowledged (record 57). The red banner is cleared for this incident.',
    );
    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(within(region).queryByLabelText('Note (up to 1000 characters)')).toBeNull();
  });

  it('a cancelled native confirmation is "cancelled", and nothing is re-read', async () => {
    const onChanged = vi.fn();
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge integrity incident 7' }));
    vi.mocked(acknowledgeIncident).mockRejectedValueOnce({ kind: 'cancelled' });
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge…' }));
    await flush();
    expect(acknowledgeIncident).toHaveBeenCalledWith(7, '');
    expect(screen.getByRole('status').textContent).toBe('Cancelled: the incident is still open.');
    expect(onChanged).not.toHaveBeenCalled();
    // The note stays open for another try.
    expect(screen.getByLabelText('Note (up to 1000 characters)')).toBeTruthy();
  });

  it('refusals are fixed sentences: closed meanwhile, a note Rust refused, an unreadable record', async () => {
    const onChanged = vi.fn();
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={onChanged} />);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge integrity incident 42' }));
    const cases: [unknown, string][] = [
      [{ kind: 'not_found' }, 'That incident is no longer open.'],
      [
        { kind: 'invalid_argument', field: 'note' },
        'The note was refused: at most 1000 characters, and no NUL character.',
      ],
      [{ kind: 'audit', error: { kind: 'unreadable', seq: 42 } }, 'The incident record could not be read, so it cannot be acknowledged here.'],
      [{ kind: 'not_ready' }, 'The audit log is not open yet: try again in a moment.'],
      // What `call()` turns a rejection it does not recognise into (`toCommandError`).
      [{ kind: 'refused', message: 'command not allowed' }, 'The command was refused.'],
      [{ kind: 'internal' }, 'The command failed.'],
    ];
    for (const [error, text] of cases) {
      vi.mocked(acknowledgeIncident).mockRejectedValueOnce(error);
      fireEvent.click(screen.getByRole('button', { name: 'Acknowledge…' }));
      await flush();
      expect(screen.getByRole('alert').textContent).toBe(text);
    }
    // `not_found`: the list is out of date, so it is read again.
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it('a note Rust refused (a NUL, or too long) gets a sentence that names both limits, never "too long" alone', async () => {
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={() => undefined} />);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge integrity incident 42' }));
    fireEvent.change(screen.getByLabelText('Note (up to 1000 characters)'), { target: { value: 'a\u0000b' } });
    vi.mocked(acknowledgeIncident).mockRejectedValueOnce({ kind: 'invalid_argument', field: 'note' });
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge…' }));
    await flush();
    // Rust, not the page, decides what a note may hold: the page sends it as typed.
    expect(acknowledgeIncident).toHaveBeenCalledWith(42, 'a\u0000b');
    const said = screen.getByRole('alert').textContent ?? '';
    expect(said).toContain('NUL');
    expect(said).toContain('1000');
    expect(said).not.toContain('too long');
  });

  it('the status region is in the page before any result, empty, and is filled in later', async () => {
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={() => undefined} />);
    const region = screen.getByRole('status');
    expect(region.textContent).toBe('');
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge integrity incident 7' }));
    vi.mocked(acknowledgeIncident).mockRejectedValueOnce({ kind: 'cancelled' });
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge…' }));
    await flush();
    // The same element, now holding the text (not a new one inserted with it).
    expect(screen.getByRole('status')).toBe(region);
    expect(region.textContent).toBe('Cancelled: the incident is still open.');
  });

  it('focus returns to the Acknowledge button when the note closes, and to the heading after an acknowledgement', async () => {
    render(<Incidents status={TWO} failed={false} onRetry={() => undefined} onChanged={() => undefined} />);
    const trigger = screen.getByRole('button', { name: 'Acknowledge integrity incident 42' });
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(document.activeElement).toBe(trigger);
    fireEvent.click(trigger);
    vi.mocked(acknowledgeIncident).mockResolvedValueOnce({ verify_seq: 42, ack_seq: 57 });
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge…' }));
    await flush();
    expect(screen.queryByLabelText('Note (up to 1000 characters)')).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Integrity incidents' }));
  });

  it('no incident, a read that failed', () => {
    const { unmount } = render(
      <Incidents status={status()} failed={false} onRetry={() => undefined} onChanged={() => undefined} />,
    );
    expect(screen.getByText('No open integrity incidents.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Acknowledge/ })).toBeNull();
    expect(screen.getByText('none')).toBeTruthy();
    unmount();
    const onRetry = vi.fn();
    render(<Incidents status={null} failed={true} onRetry={onRetry} onChanged={() => undefined} />);
    expect(screen.getByRole('alert').textContent).toContain('Could not read the integrity incidents');
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
