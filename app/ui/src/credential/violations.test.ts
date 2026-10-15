import { describe, expect, it } from 'vitest';

import { VIOLATIONS_ATTR, countViolations } from './violations';

function fire(doc: Document): void {
  // jsdom has no SecurityPolicyViolationEvent constructor guarantee: a plain Event has the same type.
  doc.dispatchEvent(new Event('securitypolicyviolation'));
}

describe('countViolations', () => {
  it('starts at zero and counts every violation event', () => {
    const doc = document.implementation.createHTMLDocument('t');
    countViolations(doc);
    expect(doc.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('0');
    fire(doc);
    fire(doc);
    expect(doc.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('2');
  });

  it('counts per document and ignores other events', () => {
    const a = document.implementation.createHTMLDocument('a');
    const b = document.implementation.createHTMLDocument('b');
    countViolations(a);
    countViolations(b);
    fire(a);
    b.dispatchEvent(new Event('error'));
    expect(a.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('1');
    expect(b.documentElement.getAttribute(VIOLATIONS_ATTR)).toBe('0');
  });
});
