// The redaction panel's state that the decision path needs (Task 17), kept in `Detail` so a tab
// switch loses nothing and `send()` can check a release against it: the candidate tree's text, the
// ops Release would send, and Rust's `redaction_preview` report for exactly those ops.

import { useEffect, useState } from 'react';

import { rawPage, redactionPreview } from '../../shared/ipc/invoke';
import type {
  CandidateRev,
  RedactionContext,
  RedactionOp,
  RedactionReport,
  UrlMode,
} from '../../shared/ipc/types';
import { CANDIDATE_MAX_BYTES, fromBase64, readCandidate, type Candidate } from './json';
import { canonical, isMask, ordered, urlFieldOp, type RoundOp } from './paths';

/** plan text (Task 17, T7 handoff): `redaction_preview` runs this long after the last change. */
export const PREVIEW_DEBOUNCE_MS = 200;

/** The ops a Release would send for the displayed revision. */
export interface Draft {
  ops: RedactionOp[];
  /** `canonical(ops)`: what a report and a confirmation are bound to. */
  key: string;
  /** The ops differ from the revision's own: Release makes a new revision (`release_redacted`). */
  unsent: boolean;
}

/** The URL mode the revision's ops already choose (the last `url_field` wins, as in Rust). */
export function baseUrlMode(base: readonly RedactionOp[]): UrlMode | null {
  let mode: UrlMode | null = null;
  for (const op of base) if ('url_field' in op) mode = op.url_field.mode;
  return mode;
}

/**
 * What Release sends. The revision shows the source with its own ops applied, and a new set of ops
 * replaces the old one (core `decide`), so the round, built on what the revision shows, goes after
 * the revision's ops, never alone. "Remove all" sends no ops (a revision with the full candidate).
 * A round with a mask ends with the URL-field choice (Rust: without one, a mask hit in a link field
 * blocks the release).
 */
export function draftOf(
  context: RedactionContext,
  round: readonly RoundOp[],
  urlChoice: UrlMode | null,
  removeAll: boolean,
): Draft {
  const base = context.ops;
  const baseMode = baseUrlMode(base);
  let ops: RedactionOp[];
  if (removeAll) {
    ops = [];
  } else {
    ops = [...base, ...ordered(round)];
    const masks = round.some((r) => isMask(r.op));
    if (masks || (urlChoice !== null && urlChoice !== baseMode)) {
      ops.push(urlFieldOp(urlChoice ?? baseMode ?? 'replace_whole'));
    }
  }
  const key = canonical(ops);
  return { ops, key, unsent: key !== canonical(base) };
}

/** Rust's verdict on one set of ops of one revision, or that the check failed. */
export type ReportState =
  | { rev: string; key: string; report: RedactionReport }
  | { rev: string; key: string; failed: true };

/**
 * Whether Release may send `draft` now (spec 5.3): nothing unsent (a plain release of what is
 * shown), or Rust's report for exactly these ops of this revision has arrived, blocks nothing, and
 * any "N other occurrences remain" was confirmed for these very ops.
 */
export function releaseReady(
  draft: Draft,
  rev: string,
  report: ReportState | null,
  confirmedKey: string | null,
): boolean {
  if (!draft.unsent) return true;
  if (report === null || report.rev !== rev || report.key !== draft.key || !('report' in report)) {
    return false;
  }
  if (report.report.blocked.length > 0) return false;
  return report.report.other_occurrences === 0 || confirmedKey === draft.key;
}

export const revKey = (rev: CandidateRev): string => `${rev.counter}:${rev.candidate_hash}`;

/**
 * `redaction_preview` of `draft`'s ops, `PREVIEW_DEBOUNCE_MS` after the last change. Only the
 * answer to the newest request is kept (an older one arriving late is dropped), and each answer
 * carries the ops and revision it was computed for: the caller compares, never assumes.
 */
export function useRedactionReport(
  requestId: string,
  rev: CandidateRev | null,
  draft: Draft | null,
): ReportState | null {
  const [state, setState] = useState<ReportState | null>(null);
  const want = rev !== null && draft !== null && draft.unsent ? draft : null;
  const counter = rev?.counter ?? 0;
  const hash = rev?.candidate_hash ?? '';
  const key = want?.key ?? null;
  useEffect(() => {
    if (key === null) return undefined;
    let live = true;
    const r = `${counter}:${hash}`;
    // The key is the ops' canonical JSON: the ops checked are the ones the key names.
    const ops = JSON.parse(key) as RedactionOp[];
    const timer = setTimeout(() => {
      redactionPreview(requestId, { counter, candidate_hash: hash }, ops).then(
        (report) => {
          if (live) setState({ rev: r, key, report });
        },
        () => {
          if (live) setState({ rev: r, key, failed: true });
        },
      );
    }, PREVIEW_DEBOUNCE_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [requestId, counter, hash, key]);
  return state;
}

export type CandidateState =
  | { state: 'loading' }
  | { state: 'unavailable' }
  /** A `raw_page` call failed: `retry` reads the pages again. */
  | { state: 'failed'; retry: () => void }
  | { state: 'ready'; candidate: Candidate };

/**
 * The displayed revision's exact candidate, read page by page through `raw_page` (plan Task 17:
 * the tree is built from the concatenated pages), once per revision while `enabled` (again after
 * a failed read on `retry`). Rust checks every page against the revision's hash; a candidate over
 * the release cap is not read.
 */
export function useCandidate(
  requestId: string,
  rev: CandidateRev | null,
  enabled: boolean,
): CandidateState | null {
  const [loaded, setLoaded] = useState<{ rev: string; value: CandidateState } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const counter = rev?.counter ?? 0;
  const hash = rev?.candidate_hash ?? '';
  const want = rev === null ? null : `${requestId}:${counter}:${hash}:${attempt}`;
  const have = loaded !== null && loaded.rev === want;
  useEffect(() => {
    if (!enabled || want === null || have) return undefined;
    let live = true;
    const r = { counter, candidate_hash: hash };
    const done = (value: CandidateState) => {
      if (live) setLoaded({ rev: want, value });
    };
    void (async () => {
      try {
        const first = await rawPage(requestId, r, 0);
        if (first.total_bytes > CANDIDATE_MAX_BYTES) return done({ state: 'unavailable' });
        const parts = [fromBase64(first.bytes_b64)];
        for (let page = 1; page < first.page_count; page++) {
          if (!live) return;
          parts.push(fromBase64((await rawPage(requestId, r, page)).bytes_b64));
        }
        const total = parts.reduce((n, p) => n + p.length, 0);
        if (total !== first.total_bytes) return done({ state: 'unavailable' });
        const bytes = new Uint8Array(total);
        let at = 0;
        for (const p of parts) {
          bytes.set(p, at);
          at += p.length;
        }
        const candidate = readCandidate(bytes);
        done(candidate === null ? { state: 'unavailable' } : { state: 'ready', candidate });
      } catch {
        done({ state: 'failed', retry: () => setAttempt((a) => a + 1) });
      }
    })();
    return () => {
      live = false;
    };
  }, [requestId, counter, hash, want, enabled, have]);
  if (want === null) return null;
  return have ? loaded.value : { state: 'loading' };
}
