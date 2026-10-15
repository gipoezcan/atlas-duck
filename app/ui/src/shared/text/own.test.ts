import { describe, expect, it } from 'vitest';

import { CLASS_LABELS, STATUS_LABELS } from '../strings';
import { own } from './own';

describe('own', () => {
  it('finds an own entry and nothing a table inherits', () => {
    expect(own(CLASS_LABELS, 'read')).toBe('Read');
    for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
      expect(own(CLASS_LABELS, name)).toBeUndefined();
      expect(own(STATUS_LABELS, name)).toBeUndefined();
    }
    expect(own({}, 'nothing')).toBeUndefined();
  });
});
