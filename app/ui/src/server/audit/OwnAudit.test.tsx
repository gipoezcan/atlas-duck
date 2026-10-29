import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { flush, header, status } from '../../audit/testing';
import { on } from '../../shared/ipc/events';
import { auditQuery, auditStatus, backupTrigger, exportTrigger, verifyNow } from '../../shared/ipc/invoke';
import { ServerLangRoot } from '../shell/ServerLangRoot';
import { OwnAudit } from './OwnAudit';

vi.mock('../../shared/ipc/invoke', () => ({
  verifyNow: vi.fn(),
  auditStatus: vi.fn(),
  auditQuery: vi.fn(),
  auditTrail: vi.fn(),
  auditPayload: vi.fn(),
  acknowledgeIncident: vi.fn(),
  exportTrigger: vi.fn(),
  exportCancel: vi.fn(),
  backupTrigger: vi.fn(),
}));
vi.mock('../../shared/ipc/events');

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(auditStatus).mockResolvedValue(status({ incident_count: 1 }));
  vi.mocked(auditQuery).mockResolvedValue({ rows: [header(7)], next: null, scanned: 1 });
  vi.mocked(on).mockResolvedValue(() => undefined);
});

describe('OwnAudit (server mode)', () => {
  // The shared Audit component has desktop help controls (they call `help_open`): they appear in
  // a desktop root and are absent under the server root.
  it('the desktop help controls are absent under the server root only', async () => {
    const { unmount } = render(<OwnAudit exportPanel={null} />);
    await flush();
    expect(screen.getByRole('button', { name: 'Help' })).toBeTruthy();
    unmount();
    render(
      <ServerLangRoot>
        <OwnAudit exportPanel={null} />
      </ServerLangRoot>,
    );
    await flush();
    expect(screen.queryByRole('button', { name: 'Help' })).toBeNull();
    expect(screen.queryByRole('link', { name: /^Help: / })).toBeNull();
  });

  it('shows the records and hides every desktop-only control', async () => {
    render(<OwnAudit exportPanel={<p>export panel slot</p>} />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Audit');
    expect(screen.getByRole('region', { name: 'Records' })).toBeTruthy();
    expect(vi.mocked(auditQuery)).toHaveBeenCalled();
    // No verification, no incidents, no desktop export or backup.
    expect(screen.queryByRole('region', { name: 'Verification' })).toBeNull();
    expect(screen.queryByRole('button', { name: /Verify/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Export/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Back up|Backup/ })).toBeNull();
    // The server's own export panel takes the export's place.
    expect(screen.getByText('export panel slot')).toBeTruthy();
    // Nothing desktop-only is asked of the server: no status read, no job events, no triggers.
    expect(vi.mocked(auditStatus)).not.toHaveBeenCalled();
    expect(vi.mocked(on)).not.toHaveBeenCalled();
    expect(vi.mocked(verifyNow)).not.toHaveBeenCalled();
    expect(vi.mocked(exportTrigger)).not.toHaveBeenCalled();
    expect(vi.mocked(backupTrigger)).not.toHaveBeenCalled();
  });
});
