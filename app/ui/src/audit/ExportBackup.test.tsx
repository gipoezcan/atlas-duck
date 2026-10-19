import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { backupTrigger, exportCancel, exportTrigger } from '../shared/ipc/invoke';
import type { AuditJobEvent, ExportDone, RemovalBackupAnswer } from '../shared/ipc/types';
import { ExportBackup } from './ExportBackup';
import { deferred, flush } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  exportTrigger: vi.fn(),
  exportCancel: vi.fn(),
  backupTrigger: vi.fn(),
}));

const HEX = 'ab'.repeat(32);
const NAME = 'atlas-duck-export-chain-1-1-40-20261019T120000Z';
const RECIPIENT = `Give the recipient this SHA-256 by another channel: ${HEX}. They verify with: atlas-duck verify-export <dir> --manifest-sha256 ${HEX} [--anchor-dir <dir>]`;

const exportButton = () => screen.getByRole('button', { name: 'Export…' }) as HTMLButtonElement;
const backupButton = () => screen.getByRole('button', { name: 'Back up now…' }) as HTMLButtonElement;

beforeEach(() => {
  vi.mocked(exportTrigger).mockReset();
  vi.mocked(exportCancel).mockReset();
  vi.mocked(backupTrigger).mockReset();
});

describe('Audit export and backup (spec 8.10, PD-161, PD-181)', () => {
  it('export_shows_hash_and_recipient_instructions', async () => {
    vi.mocked(exportTrigger).mockResolvedValueOnce({ manifest_sha256: HEX, dir_name: NAME, rows: 40 });
    render(<ExportBackup job={null} />);
    // Both fields empty: the whole log.
    fireEvent.click(exportButton());
    await flush();
    expect(exportTrigger).toHaveBeenCalledWith(null, null);
    const result = screen.getByRole('status');
    expect(result.textContent).toContain(
      `The export is complete: 40 records in the folder ${NAME} inside the folder you chose.`,
    );
    expect(result.textContent).toContain(RECIPIENT);
    // The hash is also shown on its own, to copy.
    expect(screen.getAllByText(HEX, { exact: true }).length).toBeGreaterThan(0);

    // A range: the typed UTC fields, inclusive.
    vi.mocked(exportTrigger).mockResolvedValueOnce({ manifest_sha256: HEX, dir_name: NAME, rows: 1 });
    fireEvent.change(screen.getByLabelText('Export from (UTC)'), { target: { value: '2026-10-01T00:00' } });
    fireEvent.change(screen.getByLabelText('Export to (UTC)'), { target: { value: '2026-10-02T12:30:05' } });
    fireEvent.click(exportButton());
    await flush();
    expect(exportTrigger).toHaveBeenLastCalledWith('2026-10-01T00:00:00.000Z', '2026-10-02T12:30:05.000Z');
    expect(screen.getByRole('status').textContent).toContain('1 record in the folder');
  });

  it('a complete export left under its .partial name shows the hash and the rename, and is not retried', async () => {
    vi.mocked(exportTrigger).mockRejectedValueOnce({
      kind: 'export',
      error: { kind: 'not_renamed', manifest_sha256: HEX, dir_name: `${NAME}.partial`, rows: 40 },
    });
    render(<ExportBackup job={null} />);
    fireEvent.click(exportButton());
    await flush();
    expect(exportTrigger).toHaveBeenCalledTimes(1);
    const shown = screen.getByRole('alert').textContent ?? '';
    expect(shown).toContain(`but its folder kept the name ${NAME}.partial`);
    expect(shown).toContain('removing ".partial" from the end');
    expect(shown).toContain('do not export again');
    expect(shown).toContain(RECIPIENT);
    expect(screen.queryByRole('button', { name: /try again/i })).toBeNull();
  });

  it('export_progress_and_cancel_rendered: row counts from audit_job, Cancel, the outcome from Rust', async () => {
    const run = deferred<ExportDone>();
    vi.mocked(exportTrigger).mockReturnValueOnce(run.promise);
    const { rerender } = render(<ExportBackup job={null} />);
    fireEvent.click(exportButton());
    await flush();
    expect(exportButton().disabled).toBe(true);
    expect(backupButton().disabled).toBe(true);
    // Before the first batch: running, no count yet.
    expect(screen.getByText('Starting the export')).toBeTruthy();
    rerender(<ExportBackup job={{ job: 'export', phase: 'progress', done: 10_000, total: 25_000 }} />);
    const bar = screen.getByRole('progressbar', { name: 'An export is running' }) as HTMLProgressElement;
    expect(bar.getAttribute('value')).toBe('10000');
    expect(bar.getAttribute('max')).toBe('25000');
    expect(screen.getByText('10000 of 25000 records written')).toBeTruthy();

    vi.mocked(exportCancel).mockResolvedValueOnce({ cancelled: true });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel export' }));
    await flush();
    expect(exportCancel).toHaveBeenCalledTimes(1);
    // The cancel's answer is not the outcome: the export may still finish.
    expect(screen.getByText('Cancel requested: the export stops and removes its folder.')).toBeTruthy();
    expect(screen.getByRole('progressbar')).toBeTruthy();

    run.reject({ kind: 'cancelled' });
    rerender(<ExportBackup job={{ job: 'export', phase: 'cancelled' }} />);
    await flush();
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Cancel export' })).toBeNull();
    expect(screen.getByRole('status').textContent).toBe('Cancelled: no export was made.');
    expect(exportButton().disabled).toBe(false);
  });

  it('a partial folder that could not be removed is shown whatever was pressed', async () => {
    vi.mocked(exportTrigger).mockRejectedValueOnce({
      kind: 'export',
      error: { kind: 'leftover', dir_name: `${NAME}.partial` },
    });
    render(<ExportBackup job={null} />);
    fireEvent.click(exportButton());
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(
      `The export did not complete and its unfinished folder ${NAME}.partial could not be removed. It holds decrypted data: delete it from the folder you chose.`,
    );
  });

  it('the other export refusals are fixed sentences', async () => {
    const cases: [unknown, string][] = [
      [{ kind: 'export', error: { kind: 'empty_range' } }, 'No records in this time range: nothing was exported.'],
      [{ kind: 'export', error: { kind: 'exists' } }, 'The folder you chose already holds an export of that name: try again in a moment.'],
      [{ kind: 'export', error: { kind: 'failed' } }, 'The export failed.'],
      [{ kind: 'invalid_argument', field: 'to_utc' }, 'Check the time range: "From" is after "To".'],
      [{ kind: 'busy' }, 'Another export, backup or restore is running: wait for it to end, then try again.'],
      [{ kind: 'not_ready' }, 'The audit log is not open yet: try again in a moment.'],
    ];
    render(<ExportBackup job={null} />);
    for (const [error, text] of cases) {
      vi.mocked(exportTrigger).mockRejectedValueOnce(error);
      fireEvent.click(exportButton());
      await flush();
      expect(screen.getByRole('alert').textContent).toBe(text);
    }
  });

  it('a reversed range is refused before Rust is asked', async () => {
    render(<ExportBackup job={null} />);
    fireEvent.change(screen.getByLabelText('Export from (UTC)'), { target: { value: '2026-10-02T00:00' } });
    fireEvent.change(screen.getByLabelText('Export to (UTC)'), { target: { value: '2026-10-01T00:00' } });
    fireEvent.click(exportButton());
    await flush();
    expect(exportTrigger).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toBe('Check the time range: "From" is after "To".');
  });

  it('audit_job_indeterminate_rendered: a backup has no counts, only "running", then its result', async () => {
    const run = deferred<RemovalBackupAnswer>();
    vi.mocked(backupTrigger).mockReturnValueOnce(run.promise);
    const { rerender } = render(<ExportBackup job={null} />);
    expect(screen.getByText('A backup never contains stored tokens. Backups are outside retention and crypto-shredding.')).toBeTruthy();
    fireEvent.click(backupButton());
    fireEvent.click(backupButton());
    await flush();
    expect(backupTrigger).toHaveBeenCalledTimes(1);
    const bar = screen.getByRole('progressbar', { name: 'A backup is running' });
    // Indeterminate: no value, so no count is claimed.
    expect(bar.hasAttribute('value')).toBe(false);
    expect(exportButton().disabled).toBe(true);
    rerender(<ExportBackup job={{ job: 'backup', phase: 'started' }} />);
    expect(screen.getAllByRole('progressbar')).toHaveLength(1);
    run.resolve({ saved: true });
    rerender(<ExportBackup job={{ job: 'backup', phase: 'done' }} />);
    await flush();
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.getByRole('status').textContent).toBe('The backup was saved.');
    expect(backupButton().disabled).toBe(false);
  });

  it('a job another window started (a restore, a backup) is shown running and blocks the triggers', () => {
    const jobs: [AuditJobEvent, string][] = [
      [{ job: 'restore', phase: 'started' }, 'A restore is running. Requests wait while the restore runs'],
      [{ job: 'backup', phase: 'started' }, 'A backup is running'],
    ];
    for (const [job, text] of jobs) {
      const { unmount } = render(<ExportBackup job={job} />);
      const bar = screen.getByRole('progressbar');
      expect(bar.hasAttribute('value')).toBe(false);
      expect(screen.getAllByText(text).length).toBeGreaterThan(0);
      expect(exportButton().disabled).toBe(true);
      expect(backupButton().disabled).toBe(true);
      unmount();
    }
    // An export another window started (Settings' removal export) can be cancelled here too.
    render(<ExportBackup job={{ job: 'export', phase: 'started' }} />);
    expect(screen.getByRole('button', { name: 'Cancel export' })).toBeTruthy();
  });

  it('backup answers and refusals', async () => {
    const cases: [unknown, string, 'status' | 'alert'][] = [
      [{ saved: false }, 'No backup was made.', 'status'],
      [{ kind: 'backup' }, 'The backup failed. Nothing needs to be undone.', 'alert'],
      [{ kind: 'removal', error: { kind: 'running' } }, 'A "Prepare for removal" step is running: wait for it to end, then try again.', 'alert'],
      [{ kind: 'cancelled' }, 'Cancelled: no backup was made.', 'status'],
      [{ kind: 'busy' }, 'Another export, backup or restore is running: wait for it to end, then try again.', 'alert'],
    ];
    render(<ExportBackup job={null} />);
    for (const [answer, text, role] of cases) {
      if ('saved' in (answer as object)) vi.mocked(backupTrigger).mockResolvedValueOnce(answer as RemovalBackupAnswer);
      else vi.mocked(backupTrigger).mockRejectedValueOnce(answer);
      fireEvent.click(backupButton());
      await flush();
      expect(screen.getByRole(role).textContent).toBe(text);
    }
  });
});
