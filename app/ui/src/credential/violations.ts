// The credential page's CSP violation counter (M6 T32, spec 13 `credential_page_meta_csp_enforced`).
//
// The page counts `securitypolicyviolation` events and shows the number in a `data-csp-violations`
// attribute of its root element. No IPC and no text: the E2E flow reads the attribute through
// WebDriver, 0 in normal use. Vanilla on purpose (PD-71): nothing here imports from src/shared/.
// It starts from the page's module script at the end of `<body>`, after Tauri's init scripts (the
// isolation frame) ran: a violation raised before that is not counted.

export const VIOLATIONS_ATTR = 'data-csp-violations';

/** The directive and the blocked resource (query and fragment cut, 120 characters) of the last violation: what the failing flow prints. */
export const LAST_VIOLATION_ATTR = 'data-csp-last';

export function countViolations(doc: Document = document): void {
  const root = doc.documentElement;
  let count = 0;
  root.setAttribute(VIOLATIONS_ATTR, '0');
  doc.addEventListener('securitypolicyviolation', (e) => {
    count += 1;
    root.setAttribute(VIOLATIONS_ATTR, String(count));
    const v = e as Partial<SecurityPolicyViolationEvent>;
    const blocked = String(v.blockedURI ?? '').split(/[?#]/)[0];
    root.setAttribute(LAST_VIOLATION_ATTR, `${v.effectiveDirective ?? v.violatedDirective ?? '?'} ${blocked}`.slice(0, 120));
  });
}
