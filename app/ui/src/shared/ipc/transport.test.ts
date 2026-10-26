import { afterEach, describe, expect, it, vi } from 'vitest';

import { on } from './events';
import { call, queueList } from './invoke';
import { setTransportForTests, transport, type Transport } from './transport';

/** A transport that records every call and answers `answer`. */
function fake(answer: unknown): Transport & {
  invoked: [string, Record<string, unknown>][];
  listened: [string, { thisWindow?: boolean }][];
} {
  const invoked: [string, Record<string, unknown>][] = [];
  const listened: [string, { thisWindow?: boolean }][] = [];
  return {
    kind: 'http',
    invoked,
    listened,
    invoke(cmd, args) {
      invoked.push([cmd, args]);
      return Promise.resolve(answer);
    },
    listen(name, _handler, opts) {
      listened.push([name, opts]);
      return Promise.resolve(() => undefined);
    },
  };
}

afterEach(() => {
  setTransportForTests(null);
});

describe('transport seam', () => {
  it('defaults to the Tauri transport', () => {
    expect(transport().kind).toBe('tauri');
  });

  it('routes call() through the selected transport with the body unchanged', async () => {
    const t = fake([]);
    setTransportForTests(t);
    await expect(queueList()).resolves.toEqual([]);
    expect(t.invoked).toEqual([['queue_list', {}]]);
  });

  it('still answers internal when the response fails validation', async () => {
    setTransportForTests(fake({ not: 'a list' }));
    await expect(queueList()).rejects.toEqual({ kind: 'internal' });
  });

  it('passes a rejection through toCommandError', async () => {
    const t = fake(null);
    t.invoke = () => Promise.reject({ kind: 'not_found' });
    setTransportForTests(t);
    const anything = (v: unknown): v is unknown => v !== undefined;
    await expect(call('queue_get', { request_id: 'x' }, anything)).rejects.toEqual({
      kind: 'not_found',
    });
  });

  it('routes on() through the selected transport with its options', async () => {
    const t = fake(null);
    setTransportForTests(t);
    const handler = vi.fn();
    const off = await on('queue_changed', handler, { thisWindow: true });
    off();
    await on('attention', handler);
    expect(t.listened).toEqual([
      ['queue_changed', { thisWindow: true }],
      ['attention', {}],
    ]);
  });

  it('restores the build transport with null', () => {
    setTransportForTests(fake(null));
    expect(transport().kind).toBe('http');
    setTransportForTests(null);
    expect(transport().kind).toBe('tauri');
  });
});
