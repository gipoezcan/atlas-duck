import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

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

async function opened(kind: string, over: Record<string, unknown> = {}) {
  mockedPreview.mockResolvedValue(responseOf(kind, over));
  const view = render(<Detail item={item} openToken={1} />);
  await screen.findByTitle('Preview');
  return view;
}

beforeEach(() => {
  vi.resetAllMocks();
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
    await waitFor(() => expect(mockedDecide).toHaveBeenCalled());
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({
      decision: 'deny',
      candidate_rev: item.candidate_rev,
    });
  });

  it('a_failed_open_shows_one_fixed_text', async () => {
    mockedPreview.mockRejectedValue({ kind: 'decision', error: { kind: 'stale' } });
    render(<Detail item={item} openToken={1} />);
    expect((await screen.findByRole('alert')).textContent).toBe('Could not load the preview');
    expect(screen.queryByText(/stale/)).toBeNull();
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
    expect(screen.getByText(/Open the preview to use the structured view/)).toBeTruthy();
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
      },
    });
    const { container } = render(<Detail item={item} />);
    fireEvent.click(screen.getByRole('tab', { name: 'Request' }));
    await screen.findByText(detail.request.params_sha256);
    expect(container.querySelector('img, b, i, script')).toBeNull();
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
    ]) {
      expect(screen.getByText(label).tagName).toBe('DT');
    }
    expect(screen.getByText('2026-10-14T09:30:00.000Z')).toBeTruthy();
    expect(screen.getByText('4242')).toBeTruthy();
    expect(mockedPreview).not.toHaveBeenCalled();
  });
});
