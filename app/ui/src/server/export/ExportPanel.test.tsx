import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { EXPORT_TEXT, ExportPanel, exportBrowser } from './ExportPanel';

const BASE = '/api/me/audit/exports';
const JOB = '0123456789abcdef0123456789abcdef';
const MANIFEST = 'ab'.repeat(32);
const HEAD = 'cd'.repeat(32);
const CMD = `atlas-duck verify-export d --manifest-sha256 ${MANIFEST} --anchor-chain d/anchor-chain.jsonl --anchor-chain-head 7:${HEAD}`;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const running = { job_id: JOB, state: 'running', progress: { done: 0, total: 0 } };
const done = {
  job_id: JOB,
  state: 'done',
  manifest_sha256: MANIFEST,
  anchor_head: { seq: 7, hash: HEAD },
  verify_command: CMD,
};

let fetchMock: ReturnType<typeof vi.fn>;
let copy: ReturnType<typeof vi.fn<(text: string) => Promise<void>>>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  copy = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);
  vi.spyOn(exportBrowser, 'copy').mockImplementation(copy);
  vi.spyOn(exportBrowser, 'hidden').mockReturnValue(false);
  exportBrowser.pollMs = 0;
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const calls = () => fetchMock.mock.calls.map((c) => [c[0] as string, (c[1] as RequestInit | undefined)?.method ?? 'GET']);

describe('ExportPanel', () => {
  it('starts a job, follows it and shows the download with copyable roots', async () => {
    fetchMock
      .mockResolvedValueOnce(json(202, running))
      .mockResolvedValueOnce(json(200, { ...running, progress: { done: 3, total: 9 } }))
      .mockResolvedValueOnce(json(200, done));
    render(<ExportPanel base={BASE} />);
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await screen.findByText(EXPORT_TEXT.done);
    expect(calls()).toEqual([
      [BASE, 'POST'],
      [`${BASE}/${JOB}`, 'GET'],
      [`${BASE}/${JOB}`, 'GET'],
    ]);
    const init = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    expect(init.body).toBe('{}');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBeDefined();
    expect(screen.getByRole('link', { name: EXPORT_TEXT.download }).getAttribute('href')).toBe(
      `${BASE}/${JOB}/download`,
    );
    // Each copy button copies its exact string.
    fireEvent.click(screen.getByRole('button', { name: `${EXPORT_TEXT.copy} ${EXPORT_TEXT.manifest}` }));
    fireEvent.click(screen.getByRole('button', { name: `${EXPORT_TEXT.copy} ${EXPORT_TEXT.anchor}` }));
    fireEvent.click(screen.getByRole('button', { name: `${EXPORT_TEXT.copy} ${EXPORT_TEXT.verify}` }));
    expect(copy.mock.calls.map((c) => c[0])).toEqual([MANIFEST, `7:${HEAD}`, CMD]);
    await waitFor(() => expect(screen.getAllByText(EXPORT_TEXT.copied)).toHaveLength(3));
    // Nothing of the export is kept in browser storage.
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('sends the from date and refuses a missing one without a request', async () => {
    fetchMock.mockResolvedValueOnce(json(202, running)).mockResolvedValue(json(200, done));
    render(<ExportPanel base={BASE} />);
    fireEvent.click(screen.getByRole('radio', { name: EXPORT_TEXT.range_from }));
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    expect(screen.getByRole('alert').textContent).toBe(EXPORT_TEXT.bad_date);
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(EXPORT_TEXT.range_from, { selector: 'input[type="date"]' }), {
      target: { value: '2026-10-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await screen.findByText(EXPORT_TEXT.done);
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit | undefined)?.body).toBe(
      JSON.stringify({ from_utc: '2026-10-01T00:00:00.000Z' }),
    );
  });

  it('answers busy (409) and expired (410) with their texts', async () => {
    fetchMock.mockResolvedValueOnce(json(409, { error: { code: 'audit/export_busy', message: 'x' } }));
    render(<ExportPanel base={BASE} />);
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    expect((await screen.findByRole('alert')).textContent).toBe(EXPORT_TEXT.busy);
    fetchMock
      .mockResolvedValueOnce(json(202, running))
      .mockResolvedValueOnce(json(410, { error: { code: 'audit/export_expired', message: 'x' } }));
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe(EXPORT_TEXT.expired));
  });

  it('a failed job says so', async () => {
    fetchMock
      .mockResolvedValueOnce(json(202, running))
      .mockResolvedValueOnce(json(200, { job_id: JOB, state: 'failed' }));
    render(<ExportPanel base={BASE} />);
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe(EXPORT_TEXT.failed));
  });

  it('does not poll while the page is hidden', async () => {
    vi.mocked(exportBrowser.hidden).mockReturnValue(true);
    fetchMock.mockResolvedValueOnce(json(202, running));
    render(<ExportPanel base={BASE} />);
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await screen.findByText(EXPORT_TEXT.running(0, 0));
    await new Promise((r) => setTimeout(r, 20));
    expect(calls()).toEqual([[BASE, 'POST']]);
  });
});
