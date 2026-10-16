/**
 * The markers the E2E flows read back (M6 T32): the page's own startup code sets them, so a payload
 * that took over the page (a replaced document, a reloaded frame) shows as a window without
 * `data-alive`, and a blocked or refused load shows in `data-csp-violations`. Read through the
 * WebDriver attribute endpoint; no test hook runs in the page and nothing goes over IPC.
 */
export const ALIVE_ATTR = 'data-alive';
export const VIOLATIONS_ATTR = 'data-csp-violations';

/**
 * Counts `securitypolicyviolation` events into `data-csp-violations` on the root element. The same
 * counter as `credential/violations.ts`, copied on purpose: nothing under src/credential/ may share
 * a module (so a chunk) with the main windows (PD-71).
 *
 * Limitation: this runs from the page's module script at the end of `<body>`, after Tauri's init
 * scripts (the isolation frame among them) ran. A violation raised before that (a blocked
 * isolation frame, anything in `<head>`) is never counted; the observable for those is the page
 * failing to show its first call's result. The attribute counts violations after page start only.
 */
function countViolations(doc: Document): void {
  const root = doc.documentElement;
  if (root.hasAttribute(VIOLATIONS_ATTR)) return;
  let count = 0;
  root.setAttribute(VIOLATIONS_ATTR, '0');
  doc.addEventListener('securitypolicyviolation', () => {
    count += 1;
    root.setAttribute(VIOLATIONS_ATTR, String(count));
  });
}

export function markAlive(doc: Document = document): void {
  doc.documentElement.setAttribute(ALIVE_ATTR, '1');
  countViolations(doc);
}
