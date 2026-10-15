import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { verifyNow } from '../shared/ipc/invoke';
import type { VerifyNow } from '../shared/ipc/types';
import { Audit } from './Audit';

vi.mock('../shared/ipc/invoke', () => ({ verifyNow: vi.fn() }));

// The PD-82 sentences, written out here on purpose: the test must not read the table it checks.
const VERIFIED = 'verified';
const DID_NOT_COMPLETE = 'verification did not complete';
const INCIDENT = 'integrity incident: see Audit';

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const button = () => screen.getByRole('button') as HTMLButtonElement;

beforeEach(() => {
  vi.mocked(verifyNow).mockReset();
});

describe('Audit shell', () => {
  it('audit_shell_verify_button: each of the three outcomes shows its own sentence', async () => {
    const answers: [VerifyNow, string][] = [
      [{ result: 'verified', text: 'ignored by the page' }, VERIFIED],
      [{ result: 'did_not_complete', text: 'ignored by the page' }, DID_NOT_COMPLETE],
      [{ result: 'incident', count: 2, text: 'ignored by the page' }, INCIDENT],
    ];
    render(<Audit />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Audit');
    expect(button().textContent).toBe('Verify now');
    expect(screen.queryByRole('status')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    for (const [answer, sentence] of answers) {
      vi.mocked(verifyNow).mockResolvedValueOnce(answer);
      fireEvent.click(button());
      await flush();
      const shown = screen.getByRole(answer.result === 'verified' ? 'status' : 'alert');
      expect(shown.textContent).toBe(sentence);
      // Only the one result is on the page, and the button is back.
      expect(screen.queryAllByRole('status').length + screen.queryAllByRole('alert').length).toBe(1);
      expect(button().disabled).toBe(false);
    }
    expect(verifyNow).toHaveBeenCalledTimes(3);
  });

  it('a refused or failed call is "verification did not complete", never a pass', async () => {
    render(<Audit />);
    for (const rejection of [{ kind: 'not_ready' }, 'command not allowed', { kind: 'internal' }]) {
      vi.mocked(verifyNow).mockRejectedValueOnce(rejection);
      fireEvent.click(button());
      await flush();
      expect(screen.getByRole('alert').textContent).toBe(DID_NOT_COMPLETE);
      expect(screen.queryByText(VERIFIED)).toBeNull();
    }
  });

  it('one verification at a time: the button is off meanwhile and a second click is dropped', async () => {
    let finish: (v: VerifyNow) => void = () => undefined;
    vi.mocked(verifyNow).mockReturnValue(new Promise<VerifyNow>((resolve) => (finish = resolve)));
    render(<Audit />);
    const b = button();
    // Two clicks in one tick: the second reaches the handler before React re-rendered.
    act(() => {
      fireEvent.click(b);
      fireEvent.click(b);
    });
    expect(verifyNow).toHaveBeenCalledTimes(1);
    expect(button().disabled).toBe(true);
    expect(button().textContent).toBe('Verifying…');
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => {
      finish({ result: 'verified', text: VERIFIED });
      await Promise.resolve();
    });
    await flush();
    expect(button().disabled).toBe(false);
    expect(screen.getByRole('status').textContent).toBe(VERIFIED);
  });

  it('a new run clears the previous result while it runs', async () => {
    vi.mocked(verifyNow).mockResolvedValueOnce({ result: 'incident', count: 1, text: INCIDENT });
    render(<Audit />);
    fireEvent.click(button());
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(INCIDENT);
    vi.mocked(verifyNow).mockReturnValueOnce(new Promise(() => undefined));
    fireEvent.click(button());
    await flush();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
