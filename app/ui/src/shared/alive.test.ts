import { describe, expect, it } from 'vitest';

import { ALIVE_ATTR, VIOLATIONS_ATTR, markAlive } from './alive';

function fire(doc: Document): void {
  // jsdom has no SecurityPolicyViolationEvent constructor guarantee: a plain Event has the same type.
  doc.dispatchEvent(new Event('securitypolicyviolation'));
}

describe('markAlive', () => {
  it('sets the markers on the root element and nothing else', () => {
    const doc = document.implementation.createHTMLDocument('t');
    expect(doc.documentElement.hasAttribute(ALIVE_ATTR)).toBe(false);
    markAlive(doc);
    expect(doc.documentElement.getAttribute(ALIVE_ATTR)).toBe('1');
    expect(doc.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('0');
    expect(doc.documentElement.getAttributeNames().sort()).toEqual([ALIVE_ATTR, VIOLATIONS_ATTR].sort());
    expect(doc.body.attributes.length).toBe(0);
  });

  it('is idempotent: a second call neither resets nor double-counts', () => {
    const doc = document.implementation.createHTMLDocument('t');
    markAlive(doc);
    fire(doc);
    markAlive(doc);
    fire(doc);
    expect(doc.documentElement.getAttribute(ALIVE_ATTR)).toBe('1');
    expect(doc.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('2');
  });

  it('counts every securitypolicyviolation event of its own document only', () => {
    const a = document.implementation.createHTMLDocument('a');
    const b = document.implementation.createHTMLDocument('b');
    markAlive(a);
    markAlive(b);
    fire(a);
    fire(a);
    b.dispatchEvent(new Event('error'));
    expect(a.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('2');
    expect(b.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('0');
  });
});
