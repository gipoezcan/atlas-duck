import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import previewFixture from '../shared/ipc/fixtures/preview.json';
import queueDetailFixture from '../shared/ipc/fixtures/queue_detail.json';
import queueFixture from '../shared/ipc/fixtures/queue_item.json';
import rawFixture from '../shared/ipc/fixtures/raw_page.json';
import { decide, previewFetch, queueGet, rawPage } from '../shared/ipc/invoke';
import type {
  Preview,
  PreviewFetchResponse,
  QueueDetail,
  QueueItem,
  RawPage,
} from '../shared/ipc/types';
import { Detail } from './Detail';
import { INERT_MS } from './inert';

vi.mock('../shared/ipc/invoke', () => ({
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
}));

// Typed, not cast: tsc checks the Rust-produced fixtures against the wire types.
const item: QueueItem = (queueFixture satisfies QueueItem[])[0] as QueueItem;
const previews: readonly Preview[] = previewFixture as unknown as Preview[];
const detail: QueueDetail = (queueDetailFixture satisfies QueueDetail[])[0] as QueueDetail;
const pages: readonly RawPage[] = rawFixture;

/** The fixture preview of `kind`, approvable, on the item's revision and not blocked. */
function responseOf(kind: string, over: Record<string, unknown> = {}): PreviewFetchResponse {
  const base = previews.find((p) => p.body.kind === kind);
  if (base === undefined) throw new Error(`no ${kind} fixture`);
  return {
    preview: {
      ...base,
      approvable: true,
      candidate_rev: item.candidate_rev,
      header: { ...base.header, release_blocked: null },
      ...over,
    },
    srcdoc: '<!doctype html><p>preview</p>',
    redaction: null,
  };
}

const mockedPreview = vi.mocked(previewFetch);
const mockedDecide = vi.mocked(decide);
const mockedRaw = vi.mocked(rawPage);
const mockedQueueGet = vi.mocked(queueGet);

/** The names of the buttons of the Decision group. */
function actionNames(): string[] {
  const group = screen.getByRole('group', { name: 'Decision' });
  return within(group)
    .getAllByRole('button')
    .map((b) => b.textContent ?? '');
}

/** Lets the 1 s approve/release inert period of a newly displayed candidate run out (spec 5.6). */
function pastInert() {
  act(() => {
    vi.advanceTimersByTime(INERT_MS);
  });
}

async function opened(kind: string, over: Record<string, unknown> = {}) {
  mockedPreview.mockResolvedValue(responseOf(kind, over));
  const view = render(<Detail item={item} openToken={1} />);
  // The mocked answer resolves inside act, so the render it causes and that render's effects (the
  // inert period's timer) are flushed before the clock moves.
  await act(async () => {
    for (let i = 0; i < 10; i++) await Promise.resolve();
  });
  screen.getByTitle('Preview');
  pastInert();
  return view;
}

beforeEach(() => {
  vi.resetAllMocks();
  // Fake clock (the inert periods), still advancing with real time so findBy/waitFor poll.
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Detail', () => {
  it('iframe_sandbox_attribute_is_exactly_empty', async () => {
    const { container } = await opened('json_tree');
    const frames = container.querySelectorAll('iframe');
    expect(frames).toHaveLength(1);
    const frame = frames[0] as HTMLIFrameElement;
    // Exactly these three attributes: nothing that loosens the sandbox (allow, referrerpolicy,
    // csp, credentialless, src, ...).
    expect([...frame.attributes].map((a) => a.name).sort()).toEqual(['sandbox', 'srcdoc', 'title']);
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(frame.getAttribute('title')).toBe('Preview');
    expect(frame.getAttribute('srcdoc')).toBe('<!doctype html><p>preview</p>');
  });

  it('preview_fetched_only_on_open_action', async () => {
    const { rerender } = render(<Detail item={item} />);
    expect(mockedPreview).not.toHaveBeenCalled();
    expect(screen.getByText(/preview is not open/)).toBeTruthy();
    // A queue re-read hands in a fresh row object: still nothing is fetched.
    rerender(<Detail item={{ ...item, age_s: item.age_s + 5 }} />);
    expect(mockedPreview).not.toHaveBeenCalled();
    mockedPreview.mockResolvedValue(responseOf('json_tree'));
    fireEvent.click(screen.getByRole('button', { name: 'Open preview' }));
    await screen.findByTitle('Preview');
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(mockedPreview).toHaveBeenCalledWith(item.request_id);
  });

  it('a_new_revision_clears_opened', async () => {
    const { rerender } = await opened('json_tree');
    rerender(
      <Detail
        item={{ ...item, candidate_rev: { ...item.candidate_rev, counter: item.candidate_rev.counter + 1 } }}
        openToken={1}
      />,
    );
    expect(screen.queryByTitle('Preview')).toBeNull();
    expect(screen.getByRole('button', { name: 'Open preview' })).toBeTruthy();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
  });

  it('i38_release_status_only_sends_preset', async () => {
    await opened('upstream_error');
    expect(actionNames()).toEqual(['Release', 'Release status only', 'Deny']);
    // Core answers with a new revision; the UI opens it for review before the release.
    mockedDecide.mockResolvedValue({ request_id: item.request_id, status: 'pending' });
    fireEvent.click(screen.getByRole('button', { name: 'Release status only' }));
    await waitFor(() => expect(mockedPreview).toHaveBeenCalledTimes(2));
    expect(mockedDecide).toHaveBeenCalledWith({
      request_id: item.request_id,
      candidate_rev: item.candidate_rev,
      decision: 'release_redacted',
      redactions: [{ preset: 'status_only' }],
    });
    // The consequence lines are fixed text with the status filled in.
    expect(screen.getByText(/agent receives `failed` \(exit 6\), HTTP \d+, no text/)).toBeTruthy();
  });

  it('i38_second_press_sends_the_displayed_revision', async () => {
    const { rerender } = await opened('upstream_error');
    const rev2 = { ...item.candidate_rev, counter: item.candidate_rev.counter + 1 };
    const item2: QueueItem = { ...item, candidate_rev: rev2 };
    mockedDecide.mockResolvedValueOnce({ request_id: item.request_id, status: 'pending' });
    mockedPreview.mockResolvedValueOnce(responseOf('upstream_error', { candidate_rev: rev2 }));
    fireEvent.click(screen.getByRole('button', { name: 'Release status only' }));
    await waitFor(() => expect(mockedPreview).toHaveBeenCalledTimes(2));
    // Until the queue re-read brings rev 2, nothing can be sent against rev 1.
    expect(screen.queryByRole('button', { name: 'Release status only' })).toBeNull();
    rerender(<Detail item={item2} openToken={1} />);
    // rev 2 is a newly displayed candidate: its controls start inert (T14 review I3 ruling).
    const second = await screen.findByRole('button', { name: 'Release status only' });
    expect((second as HTMLButtonElement).disabled).toBe(true);
    pastInert();
    mockedDecide.mockResolvedValueOnce({ request_id: item.request_id, status: 'released' });
    fireEvent.click(screen.getByRole('button', { name: 'Release status only' }));
    await waitFor(() => expect(mockedDecide).toHaveBeenCalledTimes(2));
    expect(mockedDecide.mock.calls[1]?.[0]).toEqual({
      request_id: item.request_id,
      candidate_rev: rev2,
      decision: 'release_redacted',
      redactions: [{ preset: 'status_only' }],
    });
  });

  it('decision_buttons_are_disabled_while_a_decision_is_in_flight', async () => {
    await opened('jira_issue');
    mockedDecide.mockReturnValue(new Promise(() => undefined));
    fireEvent.click(screen.getByRole('button', { name: 'Release' }));
    await waitFor(() =>
      expect((screen.getByRole('button', { name: 'Release' }) as HTMLButtonElement).disabled).toBe(true),
    );
    expect((screen.getByRole('button', { name: 'Deny' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Release' }));
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('outcome_card_offers_release_outcome_and_deny_only', async () => {
    await opened('outcome');
    expect(actionNames()).toEqual(['Release outcome', 'Deny']);
    mockedDecide.mockResolvedValue({ request_id: item.request_id, status: 'released' });
    fireEvent.click(screen.getByRole('button', { name: 'Release outcome' }));
    await waitFor(() => expect(mockedDecide).toHaveBeenCalled());
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release' });
  });

  it.each(['enrichment_error', 'unresolved_name', 'conflict'])(
    '%s_card_offers_deny_only_with_approve_disabled',
    async (kind) => {
      await opened(kind);
      expect(actionNames()).toEqual(['Approve', 'Deny']);
      expect((screen.getByRole('button', { name: 'Approve' }) as HTMLButtonElement).disabled).toBe(true);
      expect((screen.getByRole('button', { name: 'Deny' }) as HTMLButtonElement).disabled).toBe(false);
    },
  );

  it('a_decision_leaves_nothing_open_and_fetches_nothing', async () => {
    await opened('jira_issue');
    mockedDecide.mockResolvedValue({ request_id: item.request_id, status: 'released' });
    fireEvent.click(screen.getByRole('button', { name: 'Release' }));
    await screen.findByText('Decision recorded: released');
    expect(screen.queryByTitle('Preview')).toBeNull();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
  });

  it('a_write_approval_answered_pending_is_recorded_and_fetches_nothing', async () => {
    // Core answers an approved write `pending` until it starts executing (its stale check runs
    // first): a recorded decision, not a new revision to open (e2e UI-06, CI run 38859187604).
    await opened('write_requests');
    mockedDecide.mockResolvedValue({ request_id: item.request_id, status: 'pending' });
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await screen.findByText('Decision recorded: approved');
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'approve' });
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByTitle('Preview')).toBeNull();
  });

  it('m11_release_blocked_internal_banner_text', async () => {
    // From the model: the banner is Rust's text, rendered as a text node; only Deny remains.
    const text = 'release blocked: the candidate could not be built exactly (internal); deny it';
    mockedPreview.mockResolvedValue(
      responseOf('json_tree', { header: { ...(responseOf('json_tree').preview.header), release_blocked: text } }),
    );
    const { unmount } = render(<Detail item={item} openToken={1} />);
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toBe(`Caution: ${text}`);
    expect(actionNames()).toEqual(['Deny']);
    unmount();

    // From a rejected preview_fetch: `release_blocked {text}`; the UI renders the text, no mapping.
    vi.resetAllMocks();
    mockedPreview.mockRejectedValue({ kind: 'release_blocked', text: 'blocked by core' });
    render(<Detail item={item} openToken={1} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Caution: blocked by core');
    expect(actionNames()).toEqual(['Deny']);
    mockedDecide.mockResolvedValue({ request_id: item.request_id, status: 'denied' });
    fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    fireEvent.click(screen.getByRole('button', { name: 'Send deny' }));
    await waitFor(() => expect(mockedDecide).toHaveBeenCalled());
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({
      decision: 'deny',
      candidate_rev: item.candidate_rev,
    });
  });

  it('a_failed_open_shows_one_fixed_text', async () => {
    mockedPreview.mockRejectedValue({ kind: 'decision', error: { kind: 'stale' } });
    render(<Detail item={item} openToken={1} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Could not load the preview');
    expect(screen.queryByText(/stale/)).toBeNull();
    // The error's kinds, for a test driver that cannot read the console: identifiers only.
    expect(alert.getAttribute('data-error')).toBe('decision/stale');
  });

  it('a_failed_open_names_no_text_of_the_error', async () => {
    for (const [rejection, code] of [
      [{ kind: 'not_ready' }, 'not_ready'],
      [{ kind: 'decision', error: { kind: 'not_decidable' } }, 'decision/not_decidable'],
      [{ kind: 'decision', error: { kind: '<b>x</b>' } }, 'decision/unknown'],
      [{ kind: 'internal error at /home/user' }, 'unknown'],
      ['a string', 'unknown'],
      [null, 'unknown'],
    ] as const) {
      vi.resetAllMocks();
      mockedPreview.mockRejectedValue(rejection);
      const { unmount } = render(<Detail item={item} openToken={1} />);
      expect((await screen.findByRole('alert')).getAttribute('data-error')).toBe(code);
      unmount();
    }
  });

  it('the_tabs_show_preview_structured_raw_and_request', async () => {
    mockedRaw.mockResolvedValue(pages[0] as RawPage);
    mockedQueueGet.mockResolvedValue(detail);
    await opened('json_tree');
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual([
      'Preview',
      'Structured',
      'Raw',
      'Request',
    ]);
    // Raw pages are requested when the tab is used, never before.
    expect(mockedRaw).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('tab', { name: 'Raw' }));
    await waitFor(() => expect(mockedRaw).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    // This preview carries no redaction context (`redaction: null`): nothing to redact.
    expect(screen.getByText('Nothing to redact in this request')).toBeTruthy();
  });

  it('request_tab_all_text_nodes', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    mockedQueueGet.mockResolvedValue({
      item,
      request: {
        ...detail.request,
        params: { body: hostile, list: [1, null] },
        agent_name: '<b>agent</b>',
        reason: '<script>reason</script>',
        peer_exe: '<i>/bin/x</i>',
        peer_chain: ['<u>1 /bin/x</u>'],
      },
    });
    const { container } = render(<Detail item={item} />);
    fireEvent.click(screen.getByRole('tab', { name: 'Request' }));
    await screen.findByText(detail.request.params_sha256);
    expect(container.querySelector('img, b, i, u, script')).toBeNull();
    // Params are JSON text in a <pre>.
    const params = container.querySelector('pre.params-text');
    expect(params?.textContent).toBe(JSON.stringify({ body: hostile, list: [1, null] }, null, 2));
    // Agent strings are quoted in a <bdi> after the unverified badge.
    for (const s of ['<b>agent</b>', '<script>reason</script>']) {
      const bdi = screen.getByText(`“${s}”`);
      expect(bdi.tagName).toBe('BDI');
      expect(within(bdi.parentElement as HTMLElement).getByText('unverified')).toBeTruthy();
    }
    expect(screen.getByText('<i>/bin/x</i>').tagName).toBe('BDI');
    expect(screen.getByText('<u>1 /bin/x</u>').tagName).toBe('BDI');
    // The OS-derived peer facts each carry the unverified marker (spec 3.1): pid, exe, origin exe, chain.
    for (const label of ['Peer pid', 'Peer exe', 'Peer origin exe', 'Peer chain']) {
      const dd = screen.getByText(label).nextElementSibling as HTMLElement;
      expect(within(dd).getByText('unverified')).toBeTruthy();
    }
    // The rest of the spec 5.6 list, as text.
    for (const label of [
      'Params',
      'params_sha256',
      'Reason',
      'Operation',
      'Instance',
      'Submitted',
      'Client kind',
      'Agent name',
      'Agent name source',
      'cwd_basename',
      'Peer pid',
      'Peer exe',
      'Peer origin exe',
      'Peer chain',
    ]) {
      expect(screen.getByText(label).tagName).toBe('DT');
    }
    expect(screen.getByText('2026-10-14T09:30:00.000Z')).toBeTruthy();
    expect(screen.getByText('4242')).toBeTruthy();
    expect(mockedPreview).not.toHaveBeenCalled();
  });
});
