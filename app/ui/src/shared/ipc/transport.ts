import { tauriTransport } from './transport-tauri';

/**
 * How the shared IPC layer reaches the backend (SM-10 "transport abstraction", PD-218): Tauri IPC
 * in the desktop app, HTTP + SSE in server mode. `call()` and `on()` go through `transport()`
 * only, so every page and its validators are the same code in both modes.
 */
export interface Transport {
  readonly kind: 'tauri' | 'http';
  /** Sends one command; the body is the argument struct itself. Rejects with the raw error. */
  invoke(cmd: string, args: Record<string, unknown>): Promise<unknown>;
  /** Subscribes to a backend event; resolves to the unsubscribe function. */
  listen<E>(
    name: string,
    handler: (payload: E) => void,
    opts: { thisWindow?: boolean },
  ): Promise<() => void>;
}

let forTests: Transport | null = null;

/**
 * The transport of this build, selected once at build time (PD-218): Tauri unless the server
 * build sets `VITE_ATLAS_DUCK_TRANSPORT=http` (the HTTP transport arrives with M12 Task 7).
 */
export function transport(): Transport {
  return forTests ?? tauriTransport;
}

/** Replaces the transport inside tests only (`null` restores the build's own). */
export function setTransportForTests(t: Transport | null): void {
  if (import.meta.env.MODE !== 'test') {
    throw new Error('setTransportForTests is for tests only');
  }
  forTests = t;
}
