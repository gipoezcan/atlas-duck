import { httpTransport } from './transport-http';
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
let forPage: Transport | null = null;

/**
 * The transport of this build, selected once at build time (PD-218): Tauri unless the server
 * build sets `VITE_ATLAS_DUCK_TRANSPORT=http`. The condition is a build-time constant, so the
 * desktop bundle drops `transport-http` (checked by `ci/check-desktop-bundle-no-http.mjs`).
 */
const BUILD_TRANSPORT: Transport =
  import.meta.env.VITE_ATLAS_DUCK_TRANSPORT === 'http' ? httpTransport : tauriTransport;

export function transport(): Transport {
  return forTests ?? forPage ?? BUILD_TRANSPORT;
}

/**
 * M14 PD-257: the server auditor page sends every command of the reused audit components to the
 * selected user's scoped endpoint (`httpTransportFor`); `null` restores the build's own.
 */
export function setPageTransport(t: Transport | null): void {
  forPage = t;
}

/** Replaces the transport inside tests only (`null` restores the build's own). */
export function setTransportForTests(t: Transport | null): void {
  if (import.meta.env.MODE !== 'test') {
    throw new Error('setTransportForTests is for tests only');
  }
  forTests = t;
}
