// Credential window IPC (PD-71). Deliberately not @tauri-apps/api: importing it
// would put the same module into both this bundle and the main one, and the
// credential bundle must share no chunk (spec 10.3, ci/check-credential-bundle).
// The isolation pattern wraps __TAURI_INTERNALS__.invoke, so this is the same
// channel the API package uses.

interface TauriInternals {
  invoke(cmd: string, args?: Record<string, unknown>): Promise<unknown>;
}

function internals(): TauriInternals {
  const t = (globalThis as { __TAURI_INTERNALS__?: TauriInternals }).__TAURI_INTERNALS__;
  if (!t) {
    throw new Error('ipc unavailable');
  }
  return t;
}

/**
 * The whole invoke body is the argument struct (Task 3 arg contract). Async, so a missing
 * `__TAURI_INTERNALS__` is a rejected promise, never a synchronous throw.
 */
export async function invoke(cmd: string, args: Record<string, unknown> = {}): Promise<unknown> {
  return internals().invoke(cmd, args);
}
