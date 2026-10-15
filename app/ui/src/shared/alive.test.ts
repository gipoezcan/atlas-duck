import { describe, expect, it } from 'vitest';

import { ALIVE_ATTR, markAlive } from './alive';

describe('markAlive', () => {
  it('sets the marker on the root element and nothing else', () => {
    const doc = document.implementation.createHTMLDocument('t');
    expect(doc.documentElement.hasAttribute(ALIVE_ATTR)).toBe(false);
    markAlive(doc);
    expect(doc.documentElement.getAttribute(ALIVE_ATTR)).toBe('1');
    expect(doc.documentElement.getAttributeNames()).toEqual([ALIVE_ATTR]);
    expect(doc.body.attributes.length).toBe(0);
  });

  it('is idempotent', () => {
    const doc = document.implementation.createHTMLDocument('t');
    markAlive(doc);
    markAlive(doc);
    expect(doc.documentElement.getAttribute(ALIVE_ATTR)).toBe('1');
  });
});
