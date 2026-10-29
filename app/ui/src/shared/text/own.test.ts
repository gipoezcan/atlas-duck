import { describe, expect, it } from 'vitest';

import { de, en } from '../i18n/dict';
import { own } from './own';

describe('own', () => {
  it('finds an own entry and nothing a table inherits', () => {
    const CLASS_LABELS = en.approvals.class_labels;
    const STATUS_LABELS = en.approvals.status_labels;
    expect(own(CLASS_LABELS, 'read')).toBe('Read');
    expect(own(de.approvals.class_labels, 'read')).toBe('Lesen');
    for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
      expect(own(CLASS_LABELS, name)).toBeUndefined();
      expect(own(STATUS_LABELS, name)).toBeUndefined();
    }
    expect(own({}, 'nothing')).toBeUndefined();
  });
});
