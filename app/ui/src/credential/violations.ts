// The credential page's CSP violation counter (M6 T32, spec 13 `credential_page_meta_csp_enforced`).
//
// The page counts `securitypolicyviolation` events and shows the number in a `data-csp-violations`
// attribute of its root element. No IPC and no text: the E2E flow reads the attribute through
// WebDriver, 0 in normal use. Vanilla on purpose (PD-71): nothing here imports from src/shared/.

export const VIOLATIONS_ATTR = 'data-csp-violations';

export function countViolations(doc: Document = document): void {
  const root = doc.documentElement;
  let count = 0;
  root.setAttribute(VIOLATIONS_ATTR, '0');
  doc.addEventListener('securitypolicyviolation', () => {
    count += 1;
    root.setAttribute(VIOLATIONS_ATTR, String(count));
  });
}
