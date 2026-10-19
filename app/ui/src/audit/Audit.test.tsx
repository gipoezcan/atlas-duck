import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import {
  acknowledgeIncident,
  auditPayload,
  auditQuery,
  auditStatus,
  auditTrail,
  backupTrigger,
  exportCancel,
  exportTrigger,
  verifyNow,
} from '../shared/ipc/invoke';
import type { VerifyNow } from '../shared/ipc/types';
import { Audit } from './Audit';
import { flush, header, status } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  verifyNow: vi.fn(),
  auditStatus: vi.fn(),
  auditQuery: vi.fn(),
  auditTrail: vi.fn(),
  auditPayload: vi.fn(),
  acknowledgeIncident: vi.fn(),
  exportTrigger: vi.fn(),
  exportCancel: vi.fn(),
  backupTrigger: vi.fn(),
}));
vi.mock('../shared/ipc/events');

// The PD-82 sentences, written out here on purpose: the test must not read the table it checks.
const VERIFIED = 'verified';
const DID_NOT_COMPLETE = 'verification did not complete';
const INCIDENT = 'integrity incident: see Audit';

/** The handlers the window registered, by event name. */
let handlers = new Map<string, (payload: unknown) => void>();

async function emit(name: string, payload: unknown): Promise<void> {
  await act(async () => {
    handlers.get(name)?.(payload);
    await Promise.resolve();
  });
}

const verification = () => screen.getByRole('region', { name: 'Verification' });
const verifyButton = () => within(verification()).getByRole('button', { name: /Verify/ }) as HTMLButtonElement;

beforeEach(() => {
  for (const f of [verifyNow, auditStatus, auditQuery, auditTrail, auditPayload, acknowledgeIncident, exportTrigger, exportCancel, backupTrigger]) {
    vi.mocked(f).mockReset();
  }
  vi.mocked(auditStatus).mockResolvedValue(status());
  vi.mocked(auditQuery).mockResolvedValue({ rows: [], next: null, scanned: 0 });
  handlers = new Map();
  vi.mocked(on).mockImplementation((name, handler) => {
    handlers.set(name, handler as (payload: unknown) => void);
    return Promise.resolve(() => undefined);
  });
});

describe('Audit shell', () => {
  it('audit_shell_verify_button: each of the three outcomes shows its own sentence', async () => {
    const answers: [VerifyNow, string][] = [
      [{ result: 'verified', text: 'ignored by the page' }, VERIFIED],
      [{ result: 'did_not_complete', text: 'ignored by the page' }, DID_NOT_COMPLETE],
      [{ result: 'incident', count: 2, text: 'ignored by the page' }, INCIDENT],
    ];
    render(<Audit />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Audit');
    expect(verifyButton().textContent).toBe('Verify now');
    expect(within(verification()).queryByRole('status')).toBeNull();
    expect(within(verification()).queryByRole('alert')).toBeNull();
    for (const [answer, sentence] of answers) {
      vi.mocked(verifyNow).mockResolvedValueOnce(answer);
      fireEvent.click(verifyButton());
      await flush();
      const shown = within(verification()).getByRole(answer.result === 'verified' ? 'status' : 'alert');
      expect(shown.textContent).toBe(sentence);
      // Only the one result is on the page, and the button is back.
      expect(
        within(verification()).queryAllByRole('status').length + within(verification()).queryAllByRole('alert').length,
      ).toBe(1);
      expect(verifyButton().disabled).toBe(false);
    }
    expect(verifyNow).toHaveBeenCalledTimes(3);
  });

  it('a refused or failed call is "verification did not complete", never a pass', async () => {
    render(<Audit />);
    await flush();
    for (const rejection of [{ kind: 'not_ready' }, 'command not allowed', { kind: 'internal' }]) {
      vi.mocked(verifyNow).mockRejectedValueOnce(rejection);
      fireEvent.click(verifyButton());
      await flush();
      expect(within(verification()).getByRole('alert').textContent).toBe(DID_NOT_COMPLETE);
      expect(within(verification()).queryByText(VERIFIED)).toBeNull();
    }
  });

  it('one verification at a time: the button is off meanwhile and a second click is dropped', async () => {
    let finish: (v: VerifyNow) => void = () => undefined;
    vi.mocked(verifyNow).mockReturnValue(new Promise<VerifyNow>((resolve) => (finish = resolve)));
    render(<Audit />);
    await flush();
    const b = verifyButton();
    // Two clicks in one tick: the second reaches the handler before React re-rendered.
    act(() => {
      fireEvent.click(b);
      fireEvent.click(b);
    });
    expect(verifyNow).toHaveBeenCalledTimes(1);
    expect(verifyButton().disabled).toBe(true);
    expect(verifyButton().textContent).toBe('Verifying…');
    expect(within(verification()).queryByRole('status')).toBeNull();
    await act(async () => {
      finish({ result: 'verified', text: VERIFIED });
      await Promise.resolve();
    });
    await flush();
    expect(verifyButton().disabled).toBe(false);
    expect(within(verification()).getByRole('status').textContent).toBe(VERIFIED);
  });

  it('a new run clears the previous result while it runs', async () => {
    vi.mocked(verifyNow).mockResolvedValueOnce({ result: 'incident', count: 1, text: INCIDENT });
    render(<Audit />);
    await flush();
    fireEvent.click(verifyButton());
    await flush();
    expect(within(verification()).getByRole('alert').textContent).toBe(INCIDENT);
    vi.mocked(verifyNow).mockReturnValueOnce(new Promise(() => undefined));
    fireEvent.click(verifyButton());
    await flush();
    expect(within(verification()).queryByRole('alert')).toBeNull();
  });
});

describe('Audit window (M10 T20)', () => {
  it('reads the incidents once its listeners are attached, again on audit_changed and after an incident', async () => {
    render(<Audit />);
    await flush();
    expect([...handlers.keys()].sort()).toEqual(['audit_changed', 'audit_job']);
    expect(auditStatus).toHaveBeenCalledTimes(1);
    expect(auditQuery).toHaveBeenCalledTimes(1);
    vi.mocked(auditStatus).mockResolvedValueOnce(
      status({ incident_count: 1, open_incidents: [{ verify_seq: 9, result: 'chain_broken', detected_at: '2026-10-19T08:31:00.000Z' }] }),
    );
    await emit('audit_changed', null);
    await flush();
    expect(auditStatus).toHaveBeenCalledTimes(2);
    expect(screen.getByText('1 open integrity incident')).toBeTruthy();
    vi.mocked(verifyNow).mockResolvedValueOnce({ result: 'incident', count: 1, text: INCIDENT });
    fireEvent.click(verifyButton());
    await flush();
    expect(auditStatus).toHaveBeenCalledTimes(3);
  });

  it('an audit_job payload is checked before it is shown; a malformed one changes nothing', async () => {
    render(<Audit />);
    await flush();
    await emit('audit_job', { job: 'export', phase: 'progress', done: 5, total: 8 });
    expect(screen.getByText('5 of 8 records written')).toBeTruthy();
    for (const bad of [
      { job: 'export', phase: 'progress' },
      { job: 'backup', phase: 'progress', done: 1, total: 2 },
      { job: 'export', phase: 'started', extra: 1 },
      { job: '__proto__', phase: 'started' },
      'started',
      null,
    ]) {
      await emit('audit_job', bad);
      expect(screen.getByText('5 of 8 records written')).toBeTruthy();
    }
    await emit('audit_job', { job: 'export', phase: 'done' });
    expect(screen.queryByRole('progressbar')).toBeNull();
  });

  it('applying the filters reads the list again with them', async () => {
    render(<Audit />);
    await flush();
    fireEvent.change(screen.getByLabelText('Agent name'), { target: { value: 'claude' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await flush();
    expect(auditQuery).toHaveBeenCalledTimes(2);
    expect(vi.mocked(auditQuery).mock.calls[1]).toEqual([{ agent_name: 'claude' }]);
  });

  it('an opened record shows its columns and its trail; the payload is decrypted only on request', async () => {
    vi.mocked(auditQuery).mockResolvedValueOnce({ rows: [header(41)], next: null, scanned: 1 });
    vi.mocked(auditTrail).mockResolvedValueOnce({ headers: [header(41)], deliveries: { count: 0, to_other_peer: false } });
    vi.mocked(auditPayload).mockResolvedValueOnce({ srcdoc: '<p>x</p>', page: 0, page_count: 1, total_bytes: 3, display: 'x' });
    render(<Audit />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Open record 41' }));
    await flush();
    const detail = screen.getByRole('region', { name: 'Record 41' });
    expect(document.activeElement).toBe(within(detail).getByRole('heading', { name: 'Record 41' }));
    expect(detail.textContent).toContain('C:\\Tools\\agent.exe');
    expect(auditTrail).toHaveBeenCalledWith('req_0123456789abcdefghij');
    expect(auditPayload).not.toHaveBeenCalled();
    expect(detail.querySelector('iframe')).toBeNull();
    fireEvent.click(within(detail).getByRole('button', { name: 'Show the decrypted payload' }));
    await flush();
    expect(auditPayload).toHaveBeenCalledWith(41, 0);
    expect(detail.querySelector('iframe')?.getAttribute('sandbox')).toBe('');
    fireEvent.click(within(detail).getByRole('button', { name: 'Close record' }));
    expect(screen.queryByRole('region', { name: 'Record 41' })).toBeNull();
  });

  // L126's fixed line ("token store failed" / "token delete failed") needs the record's `change`,
  // which is only in the encrypted payload: no plaintext column carries it (T20 report, lead ruling
  // pending). What the window can do today: the record opens, and its decrypted payload (Rust's
  // tree, which shows `change`) is one press away.
  it.todo('credential_store_or_delete_failed_line_shown: the fixed line from a plaintext signal');

  it('a CREDENTIAL_CHANGED record opens and its decrypted payload is reachable', async () => {
    vi.mocked(auditQuery).mockResolvedValueOnce({
      rows: [header(43, { request_id: null, event_type: 'CREDENTIAL_CHANGED', instance_id: 'inst-1' })],
      next: null,
      scanned: 1,
    });
    vi.mocked(auditPayload).mockResolvedValueOnce({
      srcdoc: '<p>change: store_failed</p>',
      page: 0,
      page_count: 1,
      total_bytes: 80,
      display: '{"change":"store_failed"}',
    });
    render(<Audit />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Open record 43' }));
    await flush();
    const detail = screen.getByRole('region', { name: 'Record 43' });
    expect(detail.textContent).toContain('CREDENTIAL_CHANGED');
    fireEvent.click(within(detail).getByRole('button', { name: 'Show the decrypted payload' }));
    await flush();
    expect(auditPayload).toHaveBeenCalledWith(43, 0);
    expect(detail.querySelector('iframe')?.getAttribute('srcdoc')).toBe('<p>change: store_failed</p>');
  });

  it('a record of no request has no trail to read', async () => {
    vi.mocked(auditQuery).mockResolvedValueOnce({
      rows: [header(42, { request_id: null, event_type: 'VERIFY' })],
      next: null,
      scanned: 1,
    });
    render(<Audit />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Open record 42' }));
    await flush();
    expect(auditTrail).not.toHaveBeenCalled();
    expect(screen.getByRole('region', { name: 'Record 42' })).toBeTruthy();
  });
});
