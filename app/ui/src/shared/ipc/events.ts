import { listen } from '@tauri-apps/api/event';

export type Unlisten = () => void;

/**
 * Subscribes to a backend event. The payload type is the caller's claim: event
 * payloads are Rust-built, and a handler must still treat every string in one
 * as data to render as text.
 */
export function on<E>(name: string, handler: (payload: E) => void): Promise<Unlisten> {
  return listen<E>(name, (event) => handler(event.payload));
}