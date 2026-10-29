import type { QueueItem } from '../../shared/ipc/types';

/** The browser pieces the notifier uses (replaced in tests). */
export interface NotifyEnv {
  permission(): NotificationPermission | 'unsupported';
  request(): Promise<NotificationPermission>;
  hidden(): boolean;
  show(title: string, body: string, tag: string, onClick: () => void): void;
}

export const browserEnv: NotifyEnv = {
  permission: () => (typeof Notification === 'undefined' ? 'unsupported' : Notification.permission),
  request: () => Notification.requestPermission(),
  hidden: () => document.hidden,
  show(title, body, tag, onClick) {
    const n = new Notification(title, { body, tag });
    n.onclick = () => {
      window.focus();
      onClick();
      n.close();
    };
  },
};

/**
 * Tracks the pending ids seen so far and shows one notification per new id while the tab is
 * hidden and permission is granted. The first queue only seeds what was already there. The title
 * is read for every notification, so a language switch applies to the next one (PD-207: a fixed
 * title, the body is the registry op id, never agent text).
 */
export class Notifier {
  private seen: Set<string> | null = null;

  constructor(
    private readonly env: NotifyEnv,
    private readonly select: (requestId: string) => void,
    private readonly title: () => string,
  ) {}

  queue(items: readonly QueueItem[]): void {
    const ids = new Set(items.map((i) => i.request_id));
    const before = this.seen;
    this.seen = ids;
    if (before === null) return;
    if (this.env.permission() !== 'granted' || !this.env.hidden()) return;
    for (const item of items) {
      if (before.has(item.request_id)) continue;
      const id = item.request_id;
      this.env.show(this.title(), item.op_id, id, () => this.select(id));
    }
  }
}
