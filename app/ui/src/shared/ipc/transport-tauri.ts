import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';

import type { Transport } from './transport';

/** The desktop transport: Tauri IPC commands and Tauri events (the code `call`/`on` used before). */
export const tauriTransport: Transport = {
  kind: 'tauri',
  invoke(cmd, args) {
    return invoke(cmd, args);
  },
  listen<E>(name: string, handler: (payload: E) => void, opts: { thisWindow?: boolean }) {
    return listen<E>(
      name,
      (event) => handler(event.payload),
      // Without a target the listener takes `EventTarget::Any`, which Tauri also hands the events
      // another window was sent (`emit_to`).
      opts.thisWindow === true ? { target: getCurrentWindow().label } : undefined,
    );
  },
};
