import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { backupTrigger, exportCancel, exportTrigger, auditTrail } from '../shared/ipc/invoke';
import { ExportBackup } from './ExportBackup';
import { flush, header } from './testing';
import { Trail } from './Trail';

vi.mock('../shared/ipc/invoke', () => ({
  exportTrigger: vi.fn(),
  exportCancel: vi.fn(),
  backupTrigger: vi.fn(),
  auditTrail: vi.fn(),
}));

const HEX = 'ab'.repeat(32);

beforeEach(() => {
  vi.mocked(exportTrigger).mockReset();
  vi.mocked(exportCancel).mockReset();
  vi.mocked(backupTrigger).mockReset();
  vi.mocked(auditTrail).mockReset();
});

afterEach(() => {
  cleanup();
});

describe('audit trail, export and backup in German (M15 T6 fix round 1)', () => {
  it('trail_in_german: label, deliveries, marks, times', async () => {
    vi.mocked(auditTrail).mockResolvedValue({
      headers: [header(13, { event_type: 'DELIVERED', decision: null, ts_utc: '2026-10-19T08:30:15.250Z', peer_origin_exe: '/tmp/other' })],
      deliveries: { count: 2, to_other_peer: true },
    });
    render(
      <LangProvider lang="de">
        <Trail requestId="req_0123456789abcdefghij" onOpen={() => undefined} />
      </LangProvider>,
    );
    await flush();
    const region = screen.getByRole('region', { name: 'Verlauf der Anfrage' });
    expect(within(region).getByText('2-mal zugestellt')).toBeTruthy();
    expect(within(region).getByText('mehrfach zugestellt')).toBeTruthy();
    expect(within(region).getByText('an ein anderes Programm zugestellt')).toBeTruthy();
    expect(within(region).getByText('19.10.2026, 08:30 UTC')).toBeTruthy();
    expect(within(region).getByRole('button', { name: 'Datensatz 13 öffnen' })).toBeTruthy();
  });

  it('export_in_german: the result and the recipient instruction', async () => {
    vi.mocked(exportTrigger).mockResolvedValue({ manifest_sha256: HEX, dir_name: 'export-1', rows: 40 });
    render(
      <LangProvider lang="de">
        <ExportBackup job={null} />
      </LangProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Exportieren…' }));
    await flush();
    const result = screen.getByRole('status');
    expect(result.textContent).toContain('Der Export ist abgeschlossen: 40 Datensätze im Ordner export-1 innerhalb des gewählten Ordners.');
    expect(result.textContent).toContain(`Geben Sie dem Empfänger diesen SHA-256 über einen anderen Kanal: ${HEX}.`);
    expect(screen.getByRole('button', { name: 'Jetzt sichern…' })).toBeTruthy();
    expect(screen.getByLabelText('Export von (UTC)')).toBeTruthy();
  });
});