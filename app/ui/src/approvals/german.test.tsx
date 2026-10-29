import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { de, en } from '../shared/i18n/dict';
import { previewFetch } from '../shared/ipc/invoke';
import { LangProvider } from '../shared/i18n/context';
import { pluralCases } from '../shared/i18n/testing';
import { Detail } from './Detail';
import { App } from './App';
import { classSummary } from './Batch';
import { formatDecidedAt } from './Recent';
import { flush, mockWindow, previewOf, READ, WRITE } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

beforeEach(() => {
  vi.resetAllMocks();
  mockWindow();
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
    expect(screen.getByText(de.approvals.keyboard.approve)).toBeTruthy();
  });

  it('batch_plurals_in_german', () => {
    const forms = pluralCases(de.approvals.batch.deny_selected_title);
    expect(new Set(forms).size).toBe(3);
    expect(forms).toEqual([
      'Die 0 ausgewählten Anfragen ablehnen',
      'Die 1 ausgewählte Anfrage ablehnen',
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

  it('decision_bar_short_keys', () => {
    // The same keys as `SHORT_KEYS` in ci/check-i18n.mjs, which fails the build on a longer German text.
    const keys: [string, string][] = [
      [en.approvals.detail.approve, de.approvals.detail.approve],
      [en.approvals.detail.release, de.approvals.detail.release],
      [en.approvals.detail.release_outcome, de.approvals.detail.release_outcome],
      [en.approvals.detail.release_status_only, de.approvals.detail.release_status_only],
      [en.approvals.detail.deny, de.approvals.detail.deny],
      [en.approvals.deny.submit, de.approvals.deny.submit],
      [en.approvals.batch.confirm, de.approvals.batch.confirm],
      [en.approvals.batch.deny_selected, de.approvals.batch.deny_selected],
      [en.approvals.edit.submit, de.approvals.edit.submit],
    ];
    for (const [english, german] of keys) {
      expect(german.length, `${english} -> ${german}`).toBeLessThanOrEqual(1.5 * english.length + 4);
    }
  });

  it('dates_and_ages_follow_the_language', () => {
    expect(de.approvals.queue.age(30)).toBe('30 s');
    expect(de.approvals.queue.age(125)).toBe('2 min');
    expect(de.approvals.queue.age(7300)).toBe('2 Std.');
    expect(en.approvals.queue.age(7300)).toBe('2 h');
    expect(formatDecidedAt('2026-10-14T09:30:00.000Z')).toBe('2026-10-14 09:30 UTC');
    expect(formatDecidedAt('2026-10-14T09:30:00.000Z', 'de')).toBe('14.10.2026, 09:30 UTC');
    expect(formatDecidedAt('garbage', 'de')).toBe('garbage');
  });
});
