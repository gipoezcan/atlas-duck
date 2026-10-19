// Test helpers of the Audit window's tests (not shipped: only *.test.tsx import this).
import { act } from '@testing-library/react';

import type { AuditStatus, EventHeader } from '../shared/ipc/types';

/** Lets the mocked command promises and React's updates settle (a bounded number of turns). */
export async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

/** A promise the test settles itself. */
export function deferred<T>(): {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
} {
  let resolve: (v: T) => void = () => undefined;
  let reject: (e: unknown) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** One header with every column; `over` replaces some. */
export function header(seq: number, over: Partial<EventHeader> = {}): EventHeader {
  return {
    seq,
    ts_utc: '2026-10-19T08:30:00.125Z',
    epoch: '2026-10-19',
    chain_id: 'chain-1',
    event_type: 'READ_RELEASED',
    request_id: 'req_0123456789abcdefghij',
    op_id: 'jira.issue.get',
    op_class: 'read',
    instance_id: 'inst-1',
    target: 'PROJ-7',
    decision: 'release',
    flags: [],
    agent_name: 'agent-a',
    agent_name_source: 'flag',
    client_kind: 'cli',
    connection_id: 'c-1',
    peer_pid: 4242,
    peer_exe: 'C:\\Tools\\atlas-duck.exe',
    peer_origin_exe: 'C:\\Tools\\agent.exe',
    os_user: 'alice',
    atlassian_user: 'jdoe',
    atlassian_user_key: 'JIRAUSER10100',
    payload_len: 100,
    key_id: 1,
    ...over,
  };
}

const HEALTH: AuditStatus['health'] = {
  storage_low: false,
  anchor_write_failing: false,
  anchor_thread_dead: false,
  anchors_blocked: false,
  open_incidents: 0,
  prune_backlog_days: 0,
  prune_backlog: null,
  last_prune_failed: false,
  shred_checkpoint_pending: false,
  settings_unreadable: false,
  anchor_dir_write_failing: false,
  anchor_dir_lines_pending: 0,
  anchors_missing: null,
  re_anchor_offered: false,
};

/** An `audit_status` answer; `over` replaces some keys, `health` some health keys. */
export function status(
  over: Partial<AuditStatus> = {},
  health: Partial<AuditStatus['health']> = {},
): AuditStatus {
  return {
    open_incidents: [],
    incident_count: 0,
    anchor_dir: null,
    ...over,
    health: { ...HEALTH, ...health },
  };
}
