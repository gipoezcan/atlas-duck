import { useEffect, useState } from 'react';
import { useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';
import { en } from '../shared/i18n/dict';

import { PreviewFrame } from '../approvals/PreviewFrame';
import { auditPayload } from '../shared/ipc/invoke';
import type { AuditPayload } from '../shared/ipc/types';
import { kinds } from './text';

function failureText(e: unknown, t: Dict = en): string {
  const { kind, inner, field } = kinds(e);
  if (kind === 'audit' && inner === 'unreadable') return t.audit.payload_unreadable;
  if (kind === 'not_found') return t.audit.payload_gone;
  if (kind === 'invalid_argument' && field === 'page') return t.audit.errors['page'] ?? t.audit.payload_failed;
  return t.audit.payload_failed;
}

/**
 * A record's decrypted payload (spec 8.10, PD-67, PD-68), one page at a time. The page reaches the
 * window only as the document Rust built (`srcdoc`: a JSON tree of text nodes, or the page as
 * text, invisible characters escaped) inside the sandboxed preview frame (`PreviewFrame`, the one
 * place an iframe document is set); Rust's `display` text is not put into this window's DOM.
 * Above it, a `CREDENTIAL_CHANGED` record with a failed keychain step gets its fixed line (L126,
 * from Rust's closed `credential_change`, never payload text). Mounted only when the user asks for
 * the payload.
 */
export function PayloadView({ seq }: { seq: number }) {
  const t = useText();
  const [page, setPage] = useState(0);
  const [data, setData] = useState<AuditPayload | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setFailed(null);
    auditPayload(seq, page).then(
      (p) => {
        if (live) setData(p);
      },
      (e: unknown) => {
        if (live) setFailed(failureText(e, t));
      },
    );
    return () => {
      live = false;
    };
  }, [seq, page]);

  const loaded = data !== null && data.page === page && failed === null ? data : null;
  const count = Math.max(1, data?.page_count ?? 1);
  // L126: Rust's closed word for a failed keychain step, shown as the plan's fixed line.
  const credential = loaded?.credential_change ?? null;
  return (
    <section className="audit-payload" aria-label={t.audit.payload}>
      <h4>{t.audit.payload}</h4>
      {credential === null ? null : (
        <p className="audit-credential-line">
          <strong>{t.audit.credential_change[credential]}</strong>
        </p>
      )}
      <div className="raw-nav">
        <button type="button" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
          {t.audit.payload_previous}
        </button>
        <span role="status">{data === null ? null : t.audit.payload_page(data.page + 1, count, data.total_bytes)}</span>
        <button type="button" disabled={data === null || page + 1 >= count} onClick={() => setPage((p) => p + 1)}>
          {t.audit.payload_next}
        </button>
      </div>
      {failed === null ? null : <p role="alert">{failed}</p>}
      {loaded === null ? (
        failed === null ? (
          <p>{t.audit.loading}</p>
        ) : null
      ) : (
        <PreviewFrame srcdoc={loaded.srcdoc} title={t.audit.payload_title(seq)} />
      )}
    </section>
  );
}
