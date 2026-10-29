import { useEffect, useState } from 'react';

import { rawPage } from '../shared/ipc/invoke';
import type { CandidateRev, RawPage } from '../shared/ipc/types';
import { useText } from '../shared/i18n/context';

interface RawPagerProps {
  requestId: string;
  /** The revision whose bytes are paged; a new revision remounts the pager (the parent keys it). */
  candidateRev: CandidateRev;
}

/**
 * The Raw tab (spec 6.1, PD-68): one page of the exact candidate at a time, fetched on demand.
 * It shows `display` (Rust's marked projection) and never decodes `bytes_b64`.
 */
export function RawPager({ requestId, candidateRev }: RawPagerProps) {
  const t = useText();
  const [page, setPage] = useState(0);
  const [data, setData] = useState<RawPage | null>(null);
  const [failed, setFailed] = useState(false);

  const { counter, candidate_hash: hash } = candidateRev;
  useEffect(() => {
    let live = true;
    setFailed(false);
    rawPage(requestId, { counter, candidate_hash: hash }, page).then(
      (p) => {
        if (live) setData(p);
      },
      () => {
        if (live) setFailed(true);
      },
    );
    return () => {
      live = false;
    };
  }, [requestId, counter, hash, page]);

  const loaded = data !== null && data.page === page ? data : null;
  const count = data?.page_count ?? 1;
  return (
    <section className="raw-pager" aria-label={t.approvals.raw.label}>
      <div className="raw-nav">
        <button type="button" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
          {t.approvals.raw.previous}
        </button>
        <span role="status">
          {data === null
            ? t.approvals.raw.loading
            : t.approvals.raw.page_status(data.page + 1, Math.max(1, data.page_count), data.total_bytes)}
        </span>
        <button
          type="button"
          disabled={data === null || page + 1 >= count}
          onClick={() => setPage((p) => p + 1)}
        >
          {t.approvals.raw.next}
        </button>
      </div>
      {failed ? <p role="alert">{t.approvals.raw.load_failed}</p> : null}
      {loaded === null ? (
        failed ? null : <p>{t.approvals.raw.loading}</p>
      ) : (
        <>
          {loaded.display === '' ? <p>{t.approvals.raw.empty}</p> : null}
          <pre className="raw-text" tabIndex={0}>
            {loaded.display}
          </pre>
        </>
      )}
    </section>
  );
}
