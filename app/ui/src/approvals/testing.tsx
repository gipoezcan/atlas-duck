// Shared helpers of the decision-control tests (Decision.test.tsx, keyboard.test.tsx). Each test
// file mocks '../shared/ipc/invoke' and '../shared/ipc/events' itself (vi.mock is per file).
import { act, fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';

import previewFixture from '../shared/ipc/fixtures/preview.json';
import queueFixture from '../shared/ipc/fixtures/queue_item.json';
import { on } from '../shared/ipc/events';
import { appStatus, decide, previewFetch, queueList, recentList } from '../shared/ipc/invoke';
import type {
  CandidateRev,
  Preview,
  PreviewFetchResponse,
  QueueItem,
  RedactionContext,
} from '../shared/ipc/types';
import { App } from './App';

export const items: readonly QueueItem[] = queueFixture satisfies QueueItem[];
/** The first item in the queue's display order (a read) and the second (a write). */
export const [READ, WRITE] = items as [QueueItem, QueueItem];
const previews: readonly Preview[] = previewFixture as unknown as Preview[];

/** The fixture preview of `kind` for `item`'s revision, approvable and not blocked unless `over` says. */
export function previewOf(
  item: QueueItem,
  kind: string,
  over: Partial<Preview> = {},
  redaction: RedactionContext | null = null,
): PreviewFetchResponse {
  const base = previews.find((p) => p.body.kind === kind);
  if (base === undefined) throw new Error(`no ${kind} fixture`);
  return {
    preview: {
      ...base,
      approvable: true,
      candidate_rev: item.candidate_rev,
      header: { ...base.header, release_blocked: null },
      ...over,
    },
    srcdoc: '<!doctype html><p>preview</p>',
    redaction,
  };
}

export const nextRev = (rev: CandidateRev): CandidateRev => ({ ...rev, counter: rev.counter + 1 });

/** Runs pending promise callbacks (mocked IPC answers) without moving the fake clock. */
export async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

export function advance(ms: number): void {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

/** The listeners the window attached through `on`, by event name. */
export const listeners = new Map<string, { handler: (payload: unknown) => void; options: unknown }[]>();

export function emit(name: string, payload: unknown): void {
  act(() => {
    for (const l of listeners.get(name) ?? []) l.handler(payload);
  });
}

/** Mocks the window's commands and events: a two-item queue, previews per `answer`. */
export function mockWindow(queue: readonly QueueItem[] = items): void {
  listeners.clear();
  vi.mocked(on).mockImplementation((name, handler, options) => {
    listeners.set(name, [
      ...(listeners.get(name) ?? []),
      { handler: handler as (payload: unknown) => void, options },
    ]);
    return Promise.resolve(() => undefined);
  });
  vi.mocked(queueList).mockResolvedValue([...queue]);
  vi.mocked(recentList).mockResolvedValue([]);
  vi.mocked(appStatus).mockResolvedValue([]);
  vi.mocked(previewFetch).mockImplementation((id) => {
    const item = queue.find((i) => i.request_id === id);
    if (item === undefined) return Promise.reject({ kind: 'not_found' });
    return Promise.resolve(previewOf(item, item.class === 'write' ? 'transition' : 'jira_issue'));
  });
  vi.mocked(decide).mockImplementation((args) =>
    Promise.resolve({ request_id: args.request_id, status: args.decision === 'deny' ? 'denied' : 'released' }),
  );
}

export async function renderWindow() {
  const view = render(<App />);
  await flush();
  return view;
}

/** The positive button of the decision group by its text, or null when the card has none. */
export function positive(name: string): HTMLButtonElement | null {
  return screen.queryByRole('button', { name }) as HTMLButtonElement | null;
}

const KEYS = {
  Control: { key: 'Control', code: 'ControlLeft' },
  Shift: { key: 'Shift', code: 'ShiftLeft' },
  Enter: { key: 'Enter', code: 'Enter' },
  D: { key: 'D', code: 'KeyD' },
  Down: { key: 'ArrowDown', code: 'ArrowDown' },
  Up: { key: 'ArrowUp', code: 'ArrowUp' },
  Escape: { key: 'Escape', code: 'Escape' },
  X: { key: 'x', code: 'KeyX' },
} as const;
export type KeyName = keyof typeof KEYS;

/**
 * A keyboard that sends what a browser sends: modifier flags follow the keys held, events go to
 * the focused element. Each call returns `fireEvent`'s result (false = default prevented).
 */
export class Keyboard {
  private readonly held = new Set<KeyName>();

  private init(name: KeyName, repeat: boolean) {
    return {
      ...KEYS[name],
      ctrlKey: this.held.has('Control'),
      shiftKey: this.held.has('Shift'),
      metaKey: false,
      altKey: false,
      repeat,
    };
  }

  private target(): Element {
    return document.activeElement ?? document.body;
  }

  down(name: KeyName, repeat = false): boolean {
    this.held.add(name);
    return fireEvent.keyDown(this.target(), this.init(name, repeat));
  }

  up(name: KeyName): boolean {
    this.held.delete(name);
    return fireEvent.keyUp(this.target(), this.init(name, false));
  }

  /** Presses and releases a key alone. */
  tap(name: KeyName): boolean {
    const r = this.down(name);
    this.up(name);
    return r;
  }

  /** Ctrl+Shift+`main`, every key released afterwards. */
  chord(main: KeyName): boolean {
    this.down('Control');
    this.down('Shift');
    const r = this.down(main);
    this.up(main);
    this.up('Shift');
    this.up('Control');
    return r;
  }
}
