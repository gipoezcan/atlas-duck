import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import queueDetailFixture from '../shared/ipc/fixtures/queue_detail.json';
import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { formatTimestamp } from '../shared/i18n/format';
import { pluralCases } from '../shared/i18n/testing';
import { decideBatch, previewFetch, queueGet } from '../shared/ipc/invoke';
import type { QueueDetail } from '../shared/ipc/types';
import { App } from './App';
import { Batch, classSummary } from './Batch';
import { Detail } from './Detail';
import { INERT_MS } from './inert';
import { advance, flush, mockWindow, previewOf, READ, WRITE } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  decideBatch: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const detail: QueueDetail = (queueDetailFixture satisfies QueueDetail[])[0] as QueueDetail;

beforeEach(() => {
  vi.resetAllMocks();
  mockWindow();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the approvals window in German (M15 T5)', () => {
  it('queue_and_detail_render_in_german', async () => {
    render(
      <LangProvider lang="de">
        <App />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.approvals.window_titles.approvals);
    expect(screen.getByLabelText(de.approvals.queue.heading)).toBeTruthy();
    expect(screen.queryByLabelText(en.approvals.queue.heading)).toBeNull();
    expect(screen.getByText(de.approvals.detail.select_prompt)).toBeTruthy();
    expect(screen.queryByText(en.approvals.detail.select_prompt)).toBeNull();
    // The header buttons are German too.
    expect(screen.getByRole('button', { name: de.approvals.header.settings })).toBeTruthy();
    expect(screen.getByRole('button', { name: de.approvals.header.quit })).toBeTruthy();

    fireEvent.click(screen.getAllByRole('button', { name: new RegExp(`^${de.approvals.queue.open}`) })[0] as HTMLElement);
    await flush();
    expect(screen.getByRole('heading', { name: de.approvals.detail.heading })).toBeTruthy();
    expect(screen.getByRole('tab', { name: de.approvals.detail.tab_request })).toBeTruthy();
    expect(screen.queryByRole('tab', { name: en.approvals.detail.tab_raw })).toBeNull();
    expect(document.documentElement.lang).toBe('de');
  });

  it('the_decision_bar_is_german', async () => {
    vi.mocked(previewFetch).mockResolvedValue(previewOf(WRITE, 'transition'));
    render(
      <LangProvider lang="de">
        <Detail item={WRITE} openToken={1} />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('button', { name: de.approvals.detail.approve })).toBeTruthy();
    expect(screen.getByRole('button', { name: de.approvals.detail.deny })).toBeTruthy();
    expect(screen.queryByRole('button', { name: en.approvals.detail.approve })).toBeNull();
    expect(screen.getByText((_, el) => el?.tagName === 'LI' && el.textContent === de.approvals.keyboard.approve)).toBeTruthy();
  });

  it('the_request_tab_shows_the_submitted_date_in_the_language', async () => {
    vi.mocked(previewFetch).mockResolvedValue(previewOf(READ, 'jira_issue'));
    vi.mocked(queueGet).mockResolvedValue(detail);
    for (const [lang, tab, submitted] of [
      ['de', de.approvals.detail.tab_request, '14.10.2026, 09:30 UTC'],
      ['en', en.approvals.detail.tab_request, '2026-10-14 09:30 UTC'],
    ] as const) {
      const { unmount } = render(
        <LangProvider lang={lang}>
          <Detail item={READ} openToken={1} />
        </LangProvider>,
      );
      await flush();
      fireEvent.click(screen.getByRole('tab', { name: tab }));
      await flush();
      const term = within(document.querySelector('.request-tab') as HTMLElement).getByText(
        (lang === 'de' ? de : en).approvals.request.submitted_at,
      );
      expect(term.nextElementSibling?.textContent, lang).toBe(submitted);
      unmount();
    }
  });

  it('the_release_blocked_banner_has_a_german_prefix', async () => {
    // Rust's sentence itself stays as Rust sent it (residual, see the T5 report); the prefix is German.
    vi.mocked(previewFetch).mockRejectedValue({ kind: 'release_blocked', text: 'blocked by core' });
    render(
      <LangProvider lang="de">
        <Detail item={READ} openToken={1} />
      </LangProvider>,
    );
    await flush();
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toBe(`${de.approvals.detail.caution_prefix} blocked by core`);
    expect(alert.textContent).not.toContain(en.approvals.detail.caution_prefix);
    expect(screen.getByRole('button', { name: de.approvals.detail.deny })).toBeTruthy();
  });

  // M15 T10: core's one release-blocked sentence is shown in German; any other text as it came.
  it('cores_release_blocked_sentence_is_german', async () => {
    vi.mocked(previewFetch).mockRejectedValue({
      kind: 'release_blocked',
      text: en.approvals.release_blocked_internal,
    });
    render(
      <LangProvider lang="de">
        <Detail item={READ} openToken={1} />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(
      `${de.approvals.detail.caution_prefix} ${de.approvals.release_blocked_internal}`,
    );
  });
  it('the_batch_confirm_flow_is_german', async () => {
    vi.useFakeTimers();
    const row = (id: string, over: Partial<typeof READ> = {}) => ({
      ...READ,
      request_id: id,
      target_display: `T-${id}`,
      possible_duplicate_of: null,
      similar_to: null,
      opened: true,
      approvable: true,
      candidate_rev: { counter: 1, candidate_hash: id.padEnd(64, '0') },
      ...over,
    });
    const a = row('req_a');
    const b = row('req_b', { class: 'write', op_id: 'jira.issue.create' });
    vi.mocked(decideBatch).mockResolvedValue({
      batch_id: 'batch_0123456789abcdefghij',
      items: [
        { request_id: 'req_a', status: 'released' },
        { request_id: 'req_b', status: 'pending' },
      ],
    });
    render(
      <LangProvider lang="de">
        <Batch items={[a, b]} selectedIds={['req_a', 'req_b']} />
      </LangProvider>,
    );
    advance(INERT_MS);
    expect(screen.getByRole('status').textContent).toBe('2 ausgewählt');
    fireEvent.click(screen.getByRole('button', { name: de.approvals.batch.review(2) }));
    advance(INERT_MS);
    const group = screen.getByRole('group', { name: de.approvals.batch.confirm_title });
    expect(group.textContent).toContain(
      'Das passiert: 2 Anfragen: 1 Lesezugriff übergeben, 1 Schreibzugriff freigeben.',
    );
    expect(group.textContent).toContain(de.approvals.class_labels.read);
    fireEvent.click(within(group).getByRole('button', { name: de.approvals.batch.confirm }));
    await act(async () => {
      for (let i = 0; i < 20; i++) await Promise.resolve();
    });
    expect(screen.getByText('2 entschieden')).toBeTruthy();
    expect(screen.getByText(/req_b|T-req_b/).textContent).toContain(
      `${de.approvals.detail.decided}: ${de.approvals.detail.decided_approved}`,
    );
    expect(screen.queryByText(en.approvals.batch.decided(2))).toBeNull();
  });

  it('batch_plurals_in_german', () => {
    const forms = pluralCases(de.approvals.batch.deny_selected_title);
    expect(new Set(forms).size).toBe(3);
    expect(forms).toEqual([
      'Die 0 ausgewählten Anfragen ablehnen',
      'Die ausgewählte Anfrage ablehnen',
      'Die 2 ausgewählten Anfragen ablehnen',
    ]);
    expect(de.approvals.batch.class_summary(2, 1, 0, 1)).toBe(
      '2 Anfragen: 1 Lesezugriff übergeben, 1 Schreibzugriff freigeben',
    );
    expect(de.approvals.batch.class_summary(1, 0, 1, 0)).toBe('1 Anfrage: 1 Skript übergeben');
    expect(de.approvals.batch.class_summary(3, 0, 2, 1)).toBe(
      '3 Anfragen: 2 Skripte übergeben, 1 Schreibzugriff freigeben',
    );
    // The English summary is unchanged.
    expect(classSummary([READ, { ...READ, class: 'other' }])).toBe('2 requests: release 1 read, approve 1 write');
    expect(classSummary([READ, { ...READ, class: 'other' }], de)).toBe(
      '2 Anfragen: 1 Lesezugriff übergeben, 1 Schreibzugriff freigeben',
    );
  });

  it('numbers_follow_the_language', () => {
    expect(de.approvals.raw.page_status(1, 3, 12345)).toBe('Seite 1 von 3, 12.345 Bytes');
    expect(en.approvals.raw.page_status(1, 3, 12345)).toBe('page 1 of 3, 12,345 bytes');
    expect(de.approvals.redaction.released_bytes(1234567)).toBe('Übergebene Größe: 1.234.567 Bytes');
    expect(en.approvals.redaction.released_bytes(1234567)).toBe('Released size: 1,234,567 bytes');
    expect(de.approvals.redaction.value_cut(100000, 250000)).toBe('100.000 von 250.000 Zeichen werden angezeigt');
    expect(en.approvals.redaction.value_cut(100000, 250000)).toBe('Showing 100,000 of 250,000 characters');
  });

  it('dates_and_ages_follow_the_language', () => {
    expect(de.approvals.queue.age(30)).toBe('30 s');
    expect(de.approvals.queue.age(125)).toBe('2 min');
    expect(de.approvals.queue.age(7300)).toBe('2 Std.');
    expect(en.approvals.queue.age(7300)).toBe('2 h');
    expect(formatTimestamp('en', '2026-10-14T09:30:00.000Z')).toBe('2026-10-14 09:30 UTC');
    expect(formatTimestamp('de', '2026-10-14T09:30:00.000Z')).toBe('14.10.2026, 09:30 UTC');
    expect(formatTimestamp('de', '2026-10-14T11:30:00+02:00')).toBe('14.10.2026, 09:30 UTC');
    expect(formatTimestamp('de', 'garbage')).toBe('garbage');
  });
});
