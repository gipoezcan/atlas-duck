import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import rawFixture from '../shared/ipc/fixtures/raw_page.json';
import { rawPage } from '../shared/ipc/invoke';
import type { CandidateRev, RawPage } from '../shared/ipc/types';
import { RawPager } from './RawPager';

vi.mock('../shared/ipc/invoke', () => ({ rawPage: vi.fn() }));

const pages: readonly RawPage[] = rawFixture;
const rev: CandidateRev = { counter: 2, candidate_hash: 'ab'.repeat(32) };
const mockedRaw = vi.mocked(rawPage);

beforeEach(() => {
  vi.resetAllMocks();
  mockedRaw.mockImplementation((_id, _rev, page) => {
    const p = pages[page];
    return p === undefined ? Promise.reject({ kind: 'not_found' }) : Promise.resolve(p);
  });
});

describe('RawPager', () => {
  it('raw_pager_requests_pages_on_demand_and_shows_display', async () => {
    const { container } = render(<RawPager requestId="req_x" candidateRev={rev} />);
    // Only the first page is requested; the next one is not prefetched.
    await screen.findByText('page 1 of 2, 262,150 bytes');
    expect(mockedRaw.mock.calls).toEqual([['req_x', rev, 0]]);
    // The Rust display projection is shown as text; the base64 bytes never reach the DOM.
    expect(container.querySelector('pre')?.textContent).toBe((pages[0] as RawPage).display);
    expect(document.body.textContent).not.toContain((pages[0] as RawPage).bytes_b64);
    expect((screen.getByRole('button', { name: 'Previous page' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }));
    await screen.findByText('page 2 of 2, 262,150 bytes');
    expect(mockedRaw.mock.calls).toEqual([
      ['req_x', rev, 0],
      ['req_x', rev, 1],
    ]);
    expect((screen.getByRole('button', { name: 'Next page' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }));
    await waitFor(() => expect(mockedRaw).toHaveBeenCalledTimes(3));
    expect(mockedRaw.mock.calls[2]).toEqual(['req_x', rev, 0]);
  });

  it('a_failed_page_shows_one_fixed_text', async () => {
    mockedRaw.mockRejectedValue({ kind: 'decision', error: { kind: 'stale' } });
    render(<RawPager requestId="req_x" candidateRev={rev} />);
    expect((await screen.findByRole('alert')).textContent).toBe('Could not load this page');
  });
});
