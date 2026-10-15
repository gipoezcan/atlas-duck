/**
 * The marker the E2E flow S-06 reads back (M6 T32): the page's own startup code sets it, so a
 * payload that took over the page (a replaced document, a reloaded frame) shows as a window
 * without it. Read through the WebDriver attribute endpoint; no test hook runs in the page.
 */
export const ALIVE_ATTR = 'data-alive';

export function markAlive(doc: Document = document): void {
  doc.documentElement.setAttribute(ALIVE_ATTR, '1');
}
