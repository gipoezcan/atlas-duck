import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { auditQuery } from '../shared/ipc/invoke';
import type { AuditPage } from '../shared/ipc/types';
import { EventList } from './EventList';
import { Incidents } from './Incidents';
import { errorText } from './text';
import { flush, header, status } from './testing';

vi.mock('../shared/ipc/invoke', () => ({ auditQuery: vi.fn(), auditAcknowledge: vi.fn() }));

const page = (rows: AuditPage['rows']): AuditPage => ({ rows, next: null, scanned: rows.length });

beforeEach(() => {
  vi.mocked(auditQuery).mockReset();
});

afterEach(() => {
  cleanup();
});

describe('the audit window in German (M15 T6)', () => {
  it('event_list_dates_german_utc: a record time reads DD.MM.YYYY, HH:MM UTC', async () => {
    vi.mocked(auditQuery).mockResolvedValue(page([header(5, { ts_utc: '1970-01-01T00:00:00.000Z' })]));
    render(
      <LangProvider lang="de">
        <EventList filter={{}} selected={null} onOpen={() => undefined} />
      </LangProvider>,
    );
    await flush();
    const list = screen.getByRole('list', { name: de.audit.list_label });
    expect(within(list).getAllByRole('listitem')).toHaveLength(1);
    expect(list.textContent).toContain('01.01.1970, 00:00 UTC');
    expect(list.textContent).not.toContain('1970-01-01T');
    expect(screen.getByText(de.audit.list_summary(1, 1))).toBeTruthy();
    expect(screen.getByText(de.audit.list_end)).toBeTruthy();
    expect(screen.getByRole('button', { name: de.audit.open_record(5) })).toBeTruthy();
    expect(screen.queryByRole('button', { name: en.audit.open_record(5) })).toBeNull();
  });

  it('event_list_dates_english_utc', async () => {
    vi.mocked(auditQuery).mockResolvedValue(page([header(5, { ts_utc: '1970-01-01T00:00:00.000Z' })]));
    render(<EventList filter={{}} selected={null} onOpen={() => undefined} />);
    await flush();
    expect(screen.getByRole('list', { name: en.audit.list_label }).textContent).toContain('1970-01-01 00:00 UTC');
  });

  it('incidents_and_errors_in_german', async () => {
    render(
      <LangProvider lang="de">
        <Incidents status={status({ incident_count: 2, open_incidents: [] })} failed={false} onRetry={() => undefined} onChanged={() => undefined} />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByText(de.audit.incident_count(2))).toBeTruthy();
    expect(errorText({ kind: 'busy' }, de)).toBe(de.audit.errors['busy']);
    expect(errorText({ kind: 'export', error: { kind: 'empty_range' } }, de)).toBe(de.audit.export_errors['empty_range']);
  });

  it('plurals_and_numbers_are_german', () => {
    expect(de.audit.incident_count(1)).toBe('1 offener Integritätsvorfall');
    expect(de.audit.deliveries(1)).toBe('Einmal zugestellt');
    expect(de.audit.deliveries(3)).toBe('3-mal zugestellt');
    expect(de.audit.list_summary(1234, 20099)).toBe('1.234 angezeigt, 20.099 geprüft');
    expect(de.audit.export_done('export-1', 1)).toContain('1 Datensatz im Ordner');
    expect(de.audit.export_done('export-1', 2)).toContain('2 Datensätze im Ordner');
  });
});