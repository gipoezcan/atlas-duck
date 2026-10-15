import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';

export type Unlisten = () => void;

export interface OnOptions {
  /**
   * Only events sent to this window or to every window. Without it the listener targets
   * `EventTarget::Any`, which Tauri also hands the events another window was sent (`emit_to`).
   */
  thisWindow?: boolean;
}

/**
 * Subscribes to a backend event. The payload type is the caller's claim: event
 * payloads are Rust-built, and a handler must still treat every string in one
 * as data to render as text.
 */
export async function on<E>(
  name: string,
  handler: (payload: E) => void,
  options: OnOptions = {},
): Promise<Unlisten> {
  return listen<E>(
    name,
    (event) => handler(event.payload),
    options.thisWindow === true ? { target: getCurrentWindow().label } : undefined,
  );
}
