import { describe, expect, it, vi } from 'vitest';

import queueFixture from '../../shared/ipc/fixtures/queue_item.json';
import type { QueueItem } from '../../shared/ipc/types';
import { de, en } from '../../shared/i18n/dict';
import { Notifier, type NotifyEnv } from './notify';

const items: QueueItem[] = queueFixture satisfies QueueItem[];
const [A, B] = items as [QueueItem, QueueItem];

function env(over: Partial<{ perm: NotificationPermission; hidden: boolean }> = {}) {
  const shown: { title: string; body: string; tag: string; click: () => void }[] = [];
  const e: NotifyEnv = {
    permission: () => over.perm ?? 'granted',
    request: () => Promise.resolve('granted'),
    hidden: () => over.hidden ?? true,
    show: (title, body, tag, click) => shown.push({ title, body, tag, click }),
  };
  return { e, shown };
}

describe('Notifier', () => {
  it('notifies_new_ids_only_with_a_fixed_title_and_the_op_id', () => {
    const { e, shown } = env();
    const select = vi.fn();
    const n = new Notifier(e, select, () => en.server.notify.title);
    n.queue([A]);
    expect(shown).toEqual([]);
    n.queue([A, { ...B, reason_excerpt: 'agent text <b>', session_label: 'agent · x' }]);
    expect(shown).toHaveLength(1);
    expect(shown[0]?.title).toBe(en.server.notify.title);
    expect(shown[0]?.body).toBe(B.op_id);
    expect(shown[0]?.tag).toBe(B.request_id);
    shown[0]?.click();
    expect(select).toHaveBeenCalledWith(B.request_id);
    n.queue([A, B]);
    expect(shown).toHaveLength(1);
  });

  it('stays_silent_while_visible_or_without_permission', () => {
    for (const over of [{ hidden: false }, { perm: 'default' as const }, { perm: 'denied' as const }]) {
      const { e, shown } = env(over);
      const n = new Notifier(e, vi.fn(), () => en.server.notify.title);
      n.queue([]);
      n.queue([A, B]);
      expect(shown, JSON.stringify(over)).toEqual([]);
    }
  });

  it('notification_title_follows_language: the title is read for every notification', () => {
    const { e, shown } = env();
    let lang: 'en' | 'de' = 'en';
    const n = new Notifier(e, vi.fn(), () => (lang === 'de' ? de.server.notify.title : en.server.notify.title));
    n.queue([]);
    n.queue([A]);
    lang = 'de';
    n.queue([A, B]);
    expect(shown.map((s) => s.title)).toEqual(['atlas-duck: approval needed', 'atlas-duck: Freigabe erforderlich']);
    expect(shown[1]?.body).toBe(B.op_id);
  });
});
