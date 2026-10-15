import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';

import { decide, previewFetch, type DecideArgs } from '../shared/ipc/invoke';
import type { PreviewFetchResponse, QueueItem } from '../shared/ipc/types';
import { CLASS_LABELS, DETAIL_TEXT, STATUS_LABELS } from '../shared/strings';
import { PreviewFrame } from './PreviewFrame';
import { RawPager } from './RawPager';
import { RequestTab } from './RequestTab';

type TabId = 'preview' | 'structured' | 'raw' | 'request';

const TABS: readonly { id: TabId; label: string }[] = [
  { id: 'preview', label: DETAIL_TEXT.tab_preview },
  { id: 'structured', label: DETAIL_TEXT.tab_structured },
  { id: 'raw', label: DETAIL_TEXT.tab_raw },
  { id: 'request', label: DETAIL_TEXT.tab_request },
];

/** The redaction a "Release status only" sends (I-38): core's own preset, no text from the UI. */
const STATUS_ONLY: Record<string, unknown>[] = [{ preset: 'status_only' }];

/** Body kinds whose card allows Deny only; Approve is shown disabled (spec 6.3, 5.4 step 2). */
const DENY_ONLY_KINDS: ReadonlySet<string> = new Set([
  'enrichment_error',
  'unresolved_name',
  'conflict',
]);

type OpenState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'failed' }
  /** The candidate could not be built (M5 M-11): Rust's banner text, Deny only. */
  | { kind: 'blocked'; text: string }
  | { kind: 'open'; response: PreviewFetchResponse };

export interface StructuredSlotProps {
  item: QueueItem;
  response: PreviewFetchResponse;
}

interface DetailProps {
  item: QueueItem;
  /**
   * Bumped only by an explicit user open (a row click): each change opens the preview. Selection
   * and queue re-reads never change it, so they never fetch (spec 5.6 "Opened").
   */
  openToken?: number;
  /** The request left the queue (decided, expired, cancelled): `item` is its last known row and nothing can be opened. */
  gone?: boolean;
  /** The Structured tab body (reads: redaction controls, writes: the edit form). */
  renderStructured?: (props: StructuredSlotProps) => ReactNode;
}

/** The text of a `release_blocked` rejection, which Rust generates; every other error is one fixed text. */
function blockedText(e: unknown): string | null {
  if (typeof e === 'object' && e !== null && 'kind' in e && e.kind === 'release_blocked') {
    const text = (e as { text?: unknown }).text;
    return typeof text === 'string' ? text : null;
  }
  return null;
}

/**
 * The Approvals detail pane: Preview / Structured / Raw / Request tabs and the card actions of the
 * opened revision. Nothing here fetches a preview except `open()`, which runs on the Open button or
 * an `openToken` bump. Decision controls beyond the card buttons (opened flag gating, inert
 * periods, chords, the deny dialog) are Task 15.
 */
export function Detail({ item, openToken = 0, gone = false, renderStructured }: DetailProps) {
  const [tab, setTab] = useState<TabId>('preview');
  const [state, setState] = useState<OpenState>({ kind: 'idle' });
  const [actionFailed, setActionFailed] = useState(false);
  const [decided, setDecided] = useState<string | null>(null);
  /** A `decide` is in flight: every decision button is disabled until it answers. */
  const [busy, setBusy] = useState(false);
  const latest = useRef(0);

  const open = useCallback(() => {
    const mine = ++latest.current;
    setState({ kind: 'loading' });
    setActionFailed(false);
    setDecided(null);
    previewFetch(item.request_id).then(
      (response) => {
        if (mine !== latest.current) return;
        setState({ kind: 'open', response });
      },
      (e: unknown) => {
        if (mine !== latest.current) return;
        const text = blockedText(e);
        setState(text === null ? { kind: 'failed' } : { kind: 'blocked', text });
      },
    );
  }, [item.request_id]);

  useEffect(() => {
    if (openToken > 0) open();
  }, [openToken, open]);

  // A new revision of the request clears "opened": its preview must be opened again.
  const shown =
    state.kind === 'open' &&
    state.response.preview.candidate_rev.counter === item.candidate_rev.counter &&
    state.response.preview.candidate_rev.candidate_hash === item.candidate_rev.candidate_hash
      ? state.response
      : null;
  const stale = state.kind === 'open' && shown === null;

  const send = (args: Omit<DecideArgs, 'request_id' | 'candidate_rev'>) => {
    const rev = shown?.preview.candidate_rev ?? item.candidate_rev;
    if (busy) return;
    setBusy(true);
    setActionFailed(false);
    decide({ request_id: item.request_id, candidate_rev: rev, ...args }).then(
      (outcome) => {
        setBusy(false);
        if (outcome.status === 'pending') {
          // A redaction made a new revision (I-38). Ruling (T14 review I3): the fetch below
          // follows the user's own "Release status only" press, so it is not a navigation the user
          // did not ask for; the new revision is displayed, and the second press of the same button
          // sends that displayed revision. T15's inert window must cover this candidate change.
          open();
        } else {
          // No auto-advance: the decided item stays selected, its preview is cleared, nothing is fetched.
          latest.current++;
          setState({ kind: 'idle' });
          setDecided(outcome.status);
        }
      },
      (e: unknown) => {
        setBusy(false);
        const text = blockedText(e);
        if (text !== null) setState({ kind: 'blocked', text });
        else setActionFailed(true);
      },
    );
  };

  const kind = shown?.preview.body.kind;
  const releaseBlocked =
    state.kind === 'blocked' ? state.text : (shown?.preview.header.release_blocked ?? null);
  const approvable = shown?.preview.approvable === true;
  const isWrite = shown?.preview.header.class === 'write';
  const status =
    shown !== null && typeof shown.preview.body.status === 'number' ? shown.preview.body.status : null;

  const denyButton = (
    <button type="button" disabled={busy} onClick={() => send({ decision: 'deny' })}>
      {DETAIL_TEXT.deny}
    </button>
  );
  const lines = (...parts: (string | null)[]) => (
    <ul className="consequences">
      {parts.map((p) => (p === null ? null : <li key={p}>{p}</li>))}
    </ul>
  );
  const withStatus = (s: string) => s.replace('<status>', String(status ?? ''));

  let actions: ReactNode;
  if (gone) {
    actions = null;
  } else if (releaseBlocked !== null) {
    actions = denyButton;
  } else if (shown === null || gone) {
    actions = null;
  } else if (kind === 'upstream_error') {
    actions = (
      <>
        <button
          type="button"
          disabled={!approvable || busy}
          onClick={() => send({ decision: 'release' })}
        >
          {DETAIL_TEXT.release}
        </button>
        <button
          type="button"
          disabled={!approvable || busy}
          onClick={() => send({ decision: 'release_redacted', redactions: STATUS_ONLY })}
        >
          {DETAIL_TEXT.release_status_only}
        </button>
        {denyButton}
        {lines(
          withStatus(DETAIL_TEXT.consequence_release),
          withStatus(DETAIL_TEXT.consequence_status_only),
          DETAIL_TEXT.consequence_deny,
        )}
      </>
    );
  } else if (kind === 'outcome') {
    actions = (
      <>
        <button
          type="button"
          disabled={!approvable || busy}
          onClick={() => send({ decision: 'release' })}
        >
          {DETAIL_TEXT.release_outcome}
        </button>
        {denyButton}
        {lines(DETAIL_TEXT.consequence_release_outcome, DETAIL_TEXT.consequence_deny)}
      </>
    );
  } else if (kind !== undefined && DENY_ONLY_KINDS.has(kind)) {
    actions = (
      <>
        <button type="button" disabled>
          {DETAIL_TEXT.approve}
        </button>
        {denyButton}
      </>
    );
  } else {
    actions = (
      <>
        <button
          type="button"
          disabled={!approvable || busy}
          onClick={() => send({ decision: isWrite ? 'approve' : 'release' })}
        >
          {isWrite ? DETAIL_TEXT.approve : DETAIL_TEXT.release}
        </button>
        {denyButton}
      </>
    );
  }

  const needsOpen = shown === null && state.kind !== 'loading';
  const panel = (): ReactNode => {
    if (tab === 'request') return <RequestTab requestId={item.request_id} />;
    if (shown === null) {
      if (state.kind === 'loading') return <p role="status">{DETAIL_TEXT.loading}</p>;
      if (state.kind === 'failed') return <p role="alert">{DETAIL_TEXT.load_failed}</p>;
      return <p>{DETAIL_TEXT.not_opened}</p>;
    }
    if (tab === 'preview') return <PreviewFrame srcdoc={shown.srcdoc} />;
    if (tab === 'raw') {
      const rev = shown.preview.candidate_rev;
      return (
        <RawPager
          key={`${rev.counter}-${rev.candidate_hash}`}
          requestId={item.request_id}
          candidateRev={rev}
        />
      );
    }
    return renderStructured ? (
      renderStructured({ item, response: shown })
    ) : (
      <p>{DETAIL_TEXT.structured_pending}</p>
    );
  };

  return (
    <article className="detail" aria-label={DETAIL_TEXT.heading}>
      <h2>{DETAIL_TEXT.heading}</h2>
      <p className="detail-summary">
        <span className="op-id">{item.op_id}</span> <span className="alias">{item.instance_alias}</span>{' '}
        <span className="target">{item.target_display}</span>{' '}
        <span className="class">{CLASS_LABELS[item.class] ?? item.class}</span>
      </p>
      {releaseBlocked === null ? null : (
        <div className="caution-strip" role="alert">
          <strong>{DETAIL_TEXT.caution_prefix}</strong> {releaseBlocked}
        </div>
      )}
      {!gone && (stale || needsOpen) ? (
        <button type="button" onClick={open}>
          {DETAIL_TEXT.open}
        </button>
      ) : null}
      {decided === null ? null : <p role="status">{`${DETAIL_TEXT.decided}: ${STATUS_LABELS[decided] ?? decided}`}</p>}
      {actionFailed ? <p role="alert">{DETAIL_TEXT.action_failed}</p> : null}
      <div className="detail-actions" role="group" aria-label={DETAIL_TEXT.actions_label}>
        {actions}
      </div>
      <div role="tablist" aria-label={DETAIL_TEXT.tabs_label}>
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" className="detail-panel">
        {panel()}
      </div>
    </article>
  );
}
