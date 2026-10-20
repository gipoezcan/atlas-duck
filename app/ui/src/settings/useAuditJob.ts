import { useEffect, useState } from 'react';

import { on } from '../shared/ipc/events';
import type { AuditJobEvent, AuditJobKind } from '../shared/ipc/types';
import { isAuditJobEvent } from '../shared/ipc/validate';

/**
 * The latest `audit_job` event addressed to this window (an export, a backup or a restore; Rust runs
 * one job at a time), or `null` before any. The payload is checked with `isAuditJobEvent` before it
 * is used; a section reads only the jobs of its own `job` kind.
 */
export function useAuditJob(): AuditJobEvent | null {
  const [job, setJob] = useState<AuditJobEvent | null>(null);
  useEffect(() => {
    const off = on<unknown>(
      'audit_job',
      (payload) => {
        if (isAuditJobEvent(payload)) setJob(payload);
      },
      { thisWindow: true },
    );
    return () => {
      void off.then((f) => f()).catch(() => undefined);
    };
  }, []);
  return job;
}

/** A job of `kind` that has started and not ended. */
export function running(job: AuditJobEvent | null, kind: AuditJobKind): boolean {
  return job !== null && job.job === kind && (job.phase === 'started' || job.phase === 'progress');
}
