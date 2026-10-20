import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { auditPayload } from '../shared/ipc/invoke';
import type { AuditPayload } from '../shared/ipc/types';
import { PayloadView } from './PayloadView';
import { flush } from './testing';

vi.mock('../shared/ipc/invoke', () => ({ auditPayload: vi.fn() }));

const SRCDOC = '<!doctype html><p>DOC-MARKER <b>x</b></p><script>window.__pwned=1</script>';
const DISPLAY = 'DISPLAY-MARKER {"secret":"x"}';

const answer = (page: number, page_count = 2): AuditPayload => ({
  srcdoc: `${SRCDOC}${page}`,
  page,
  page_count,
  total_bytes: 300_000,
  display: `${DISPLAY}${page}`,
  credential_change: null,
});

beforeEach(() => {
  vi.mocked(auditPayload).mockReset();
});

describe('Audit payload view (spec 8.10, PD-67, PD-68)', () => {
  it('payload_in_sandboxed_iframe_only: the decrypted page reaches the DOM only as an empty-sandbox srcdoc', async () => {
    vi.mocked(auditPayload).mockImplementation((_seq, page = 0) => Promise.resolve(answer(page)));
    const { container } = render(<PayloadView seq={41} />);
    await flush();
    expect(auditPayload).toHaveBeenCalledWith(41, 0);
    const frames = container.querySelectorAll('iframe');
    expect(frames).toHaveLength(1);
    const frame = frames[0] as HTMLIFrameElement;
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(frame.getAttribute('srcdoc')).toBe(`${SRCDOC}0`);
    expect(frame.getAttribute('title')).toBe('Decrypted payload of record 41');
    // Nothing else on the frame, nothing that could load or run.
    expect(frame.getAttributeNames().sort()).toEqual(['sandbox', 'srcdoc', 'title']);
    // Neither the document nor Rust's display text is in the window's own DOM.
    const outside = container.cloneNode(true) as HTMLElement;
    outside.querySelectorAll('iframe').forEach((f) => f.remove());
    const attributes = [...outside.querySelectorAll('*')].flatMap((el) =>
      el.getAttributeNames().map((n) => el.getAttribute(n) ?? ''),
    );
    for (const marker of ['DOC-MARKER', 'DISPLAY-MARKER']) {
      expect(outside.textContent).not.toContain(marker);
      expect(attributes.filter((a) => a.includes(marker))).toEqual([]);
    }
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByRole('status').textContent).toBe('Page 1 of 2, 300000 bytes');
  });

  it('pages through the payload, one page at a time', async () => {
    vi.mocked(auditPayload).mockImplementation((_seq, page = 0) => Promise.resolve(answer(page)));
    const { container } = render(<PayloadView seq={41} />);
    await flush();
    const previous = screen.getByRole('button', { name: 'Previous page' }) as HTMLButtonElement;
    const next = screen.getByRole('button', { name: 'Next page' }) as HTMLButtonElement;
    expect(previous.disabled).toBe(true);
    fireEvent.click(next);
    await flush();
    expect(auditPayload).toHaveBeenLastCalledWith(41, 1);
    expect(container.querySelector('iframe')?.getAttribute('srcdoc')).toBe(`${SRCDOC}1`);
    expect(screen.getByRole('status').textContent).toBe('Page 2 of 2, 300000 bytes');
    expect((screen.getByRole('button', { name: 'Next page' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
    await flush();
    expect(auditPayload).toHaveBeenLastCalledWith(41, 0);
  });

  it('a payload that does not decrypt, a pruned record and other failures are fixed sentences', async () => {
    const cases: [unknown, string][] = [
      [{ kind: 'audit', error: { kind: 'unreadable', seq: 41 } }, 'The payload could not be read: it does not decrypt or does not match its digest.'],
      [{ kind: 'not_found' }, 'That record is no longer in the log.'],
      [{ kind: 'internal' }, 'Could not read the payload.'],
    ];
    for (const [error, text] of cases) {
      vi.mocked(auditPayload).mockRejectedValueOnce(error);
      const { container, unmount } = render(<PayloadView seq={41} />);
      await flush();
      expect(screen.getByRole('alert').textContent).toBe(text);
      expect(container.querySelector('iframe')).toBeNull();
      unmount();
    }
  });
});
