import { afterEach, describe, expect, it, vi } from 'vitest';

import { invoke } from './ipc';

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