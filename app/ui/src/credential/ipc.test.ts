import { afterEach, describe, expect, it, vi } from 'vitest';

import { invoke, listen } from './ipc';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('credential invoke', () => {
  it('rejects, never throws, when __TAURI_INTERNALS__ is missing', async () => {
    let promise: Promise<unknown> | undefined;
    expect(() => {
      promise = invoke('credential_context');
    }).not.toThrow();
    await expect(promise).rejects.toThrow('ipc unavailable');
  });

  it('passes the argument struct as the whole body', async () => {
    const internals = { invoke: vi.fn().mockResolvedValue('ok') };
    vi.stubGlobal('__TAURI_INTERNALS__', internals);
    await expect(invoke('credential_context', { a: 1 })).resolves.toBe('ok');
    expect(internals.invoke).toHaveBeenCalledWith('credential_context', { a: 1 });
  });
});

describe('credential listen', () => {
  it('registers a callback with the event plugin and unlistens by event id', async () => {
    let cb: ((e: unknown) => void) | undefined;
    const internals = {
      transformCallback: vi.fn((f: (e: unknown) => void) => {
        cb = f;
        return 7;
      }),
      invoke: vi.fn().mockResolvedValue(42),
    };
    vi.stubGlobal('__TAURI_INTERNALS__', internals);
    const seen = vi.fn();
    const unlisten = await listen('credential_context_changed', seen);
    expect(internals.invoke).toHaveBeenCalledWith('plugin:event|listen', {
      event: 'credential_context_changed',
      target: { kind: 'Any' },
      handler: 7,
    });
    cb?.({ payload: 'ignored' });
    expect(seen).toHaveBeenCalledWith();
    unlisten();
    expect(internals.invoke).toHaveBeenLastCalledWith('plugin:event|unlisten', {
      event: 'credential_context_changed',
      eventId: 42,
    });
  });

  it('rejects when __TAURI_INTERNALS__ is missing', async () => {
    await expect(listen('x', () => undefined)).rejects.toThrow('ipc unavailable');
  });
});