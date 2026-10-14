import { invoke } from '@tauri-apps/api/core';

import type { QueueItem, StatusLine } from './types';
import { arrayOf, isQueueItem, isStatusLine, toCommandError, type Validator } from './validate';

/**
 * Every command goes through here. The invoke body is the argument struct
 * itself (Task 3 arg contract): no `args` wrapper, no unknown keys. A rejected
 * call throws a `CommandError`; a response that fails validation throws
 * `internal` rather than reaching a component.
 */
export async function call<T>(
  cmd: string,
  args: Record<string, unknown>,
  validate: Validator<T>,
): Promise<T> {
  let raw: unknown;
  try {
    raw = await invoke(cmd, args);
  } catch (e) {
    throw toCommandError(e);
  }
  if (!validate(raw)) {
    throw toCommandError({ kind: 'internal' });
  }
  return raw;
}

export function queueList(): Promise<QueueItem[]> {
  return call('queue_list', {}, arrayOf(isQueueItem));
}

export function appStatus(): Promise<StatusLine[]> {
  return call('app_status', {}, arrayOf(isStatusLine));
}
