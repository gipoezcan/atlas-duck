import {
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
  type ReactNode,
  type Ref,
} from 'react';

import { decide, previewFetch, type DenyDetails } from '../shared/ipc/invoke';
import type { PreviewFetchResponse, QueueItem } from '../shared/ipc/types';
import { CLASS_LABELS, DETAIL_TEXT, EDIT_TEXT, STATUS_LABELS } from '../shared/strings';
import { cardOf, DecisionBar, type DecisionArgs } from './DecisionBar';
import { DenyDialog } from './DenyDialog';
import { buildEdits, EditForm, type Draft, type Drafts } from './EditForm';
import { candidateKey, useInert } from './inert';
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

/** What the window's chords run on the displayed request (`useChords` in `App`). */
export interface DetailHandle {
  /** The card's first positive action, under the same checks as its button. */
  approve: () => void;
  /** Opens the deny reason field (or focuses it again). */
  deny: () => void;
}

interface DetailProps {
  item: QueueItem;
  /**
   * Bumped only by an explicit user open (a row click, next/prev): each change opens the preview.
   * Selection and queue re-reads never change it, so they never fetch (spec 5.6 "Opened").
   */
  openToken?: number;
  /** The request left the queue (decided, expired, cancelled): `item` is its last known row and nothing can be opened. */
  gone?: boolean;
  /** The Structured tab body (reads: redaction controls, writes: the edit form). */
  renderStructured?: (props: StructuredSlotProps) => ReactNode;
  ref?: Ref<DetailHandle>;
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
 * Core's message of a refused edit (`DecisionError::EditRejected`, the validator's app-generated
 * text, bounded and display-escaped by Rust), `''` when it carried none; null for any other error.
 */
function editRejection(e: unknown): string | null {
  if (typeof e !== 'object' || e === null || !('kind' in e) || e.kind !== 'decision') return null;
  const core = (e as { error?: { kind?: unknown; error?: { message?: unknown } } }).error;
  if (core?.kind !== 'edit_rejected') return null;
  const message = core.error?.message;
  if (typeof message !== 'string') return '';
  // By code points, so a surrogate pair is never split; the ellipsis says the text was cut.
  const points = Array.from(message);
  return points.length > 300 ? `${points.slice(0, 300).join('')}…` : message;
}

/**
 * The Approvals detail pane: Preview / Structured / Raw / Request tabs and the decision controls
 * of the opened revision. Nothing here fetches a preview except `open()`, which runs on the Open
 * button or an `openToken` bump. Every decision goes through `send()`, which re-checks what the
 * controls show (spec 5.6): a positive decision needs the displayed revision opened, approvable
 * per Rust, not inert, and nothing in flight. Rust checks all of it again (spec 2.4).
 *
 * Writes (task 16): the Structured tab is the edit form. "Edit & approve" is a `decide
 * {approve_edited, edits}` through `send()` like every decision; it makes a new revision (PD-20), and
 * the pane then shows that revision unopened: opening it is the user's next click, then the inert
 * period, then approve. While the form holds unsent changes the revision's own Approve is off:
 * approving it would silently leave the changes out.
 */
export function Detail({ item, openToken = 0, gone = false, renderStructured, ref }: DetailProps) {
  const [tab, setTab] = useState<TabId>('preview');
  const [state, setState] = useState<OpenState>({ kind: 'idle' });
  const [actionFailed, setActionFailed] = useState(false);
  const [decided, setDecided] = useState<string | null>(null);
  /** A `decide` is in flight: every decision control is disabled until it answers. */
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [denyOpen, setDenyOpen] = useState(false);
  const [denyFocus, setDenyFocus] = useState(0);
  /** The edit form's text, kept here so a tab switch does not lose it; cleared on every open. */
  const [drafts, setDrafts] = useState<Drafts>({});
  const [rejection, setRejection] = useState<string | null>(null);
  /** An edit made a new revision that has not been opened yet. */
  const [edited, setEdited] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const latest = useRef(0);

  const open = useCallback(() => {
    const mine = ++latest.current;
    setState({ kind: 'loading' });
    setActionFailed(false);
    setDecided(null);
    setDenyOpen(false);
    setDrafts({});
    setRejection(null);
    setEdited(false);
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
  const displayed = candidateKey(
    item.request_id,
    shown === null ? null : shown.preview.candidate_rev,
  );
  const inert = useInert(displayed);

  const releaseBlocked =
    state.kind === 'blocked' ? state.text : (shown?.preview.header.release_blocked ?? null);
  const card = gone || shown === null ? null : cardOf(shown.preview);
  const canDeny = !gone && (shown !== null || releaseBlocked !== null);
  const form = shown?.preview.edit_form ?? null;
  const built = form === null ? null : buildEdits(form, drafts);
  /** The form holds changes that are not sent: an approve would leave them out. */
  const unsentEdits = built?.changed ?? false;
  const positiveEnabled =
    shown !== null &&
    shown.preview.approvable &&
    !busy &&
    !denyOpen &&
    !unsentEdits &&
    !inert.approveInert;
  /** The edit button: not an approval, so a preview that is not approvable can still be edited. */
  const editEnabled =
    form !== null &&
    releaseBlocked === null &&
    !gone &&
    !busy &&
    !denyOpen &&
    !inert.approveInert;

  const send = (args: DecisionArgs) => {
    if (inFlight.current || gone) return;
    const isEdit = args.decision === 'approve_edited';
    if (args.decision === 'deny') {
      if (!canDeny) return;
    } else if (isEdit) {
      // `approve_edited` without edits would approve the revision as it is: never from here.
      if (
        args.edits === undefined ||
        form === null ||
        releaseBlocked !== null ||
        denyOpen ||
        inert.approveInertNow()
      ) {
        return;
      }
    } else if (
      shown === null ||
      !shown.preview.approvable ||
      releaseBlocked !== null ||
      denyOpen ||
      unsentEdits ||
      inert.approveInertNow()
    ) {
      return;
    }
    setRejection(null);
    const rev = shown?.preview.candidate_rev ?? item.candidate_rev;
    inFlight.current = true;
    setBusy(true);
    setActionFailed(false);
    decide({ request_id: item.request_id, candidate_rev: rev, ...args }).then(
      (outcome) => {
        inFlight.current = false;
        setBusy(false);
        setDenyOpen(false);
        if (outcome.status === 'pending' && isEdit) {
          // An edit made a new revision (PD-20). Unlike the "Release status only" case below the
          // user asked for a change, not to look at it: the pane shows the new revision unopened.
          // Opening it is the user's next click, which fetches it and starts the inert period.
          latest.current++;
          setState({ kind: 'idle' });
          setDrafts({});
          setEdited(true);
        } else if (outcome.status === 'pending') {
          // A redaction made a new revision (I-38). Ruling (T14 review I3): the fetch below
          // follows the user's own "Release status only" press, so it is not a navigation the user
          // did not ask for. The new revision is displayed once the queue re-read brings it, and
          // `useInert` starts the inert period then, as for any displayed candidate change.
          open();
        } else {
          // No auto-advance: the decided item stays selected, its preview is cleared, nothing is fetched.
          latest.current++;
          setState({ kind: 'idle' });
          setDecided(outcome.status);
        }
      },
      (e: unknown) => {
        inFlight.current = false;
        setBusy(false);
        const text = blockedText(e);
        const refused = isEdit ? editRejection(e) : null;
        if (text !== null) setState({ kind: 'blocked', text });
        else if (refused !== null) setRejection(refused);
        else setActionFailed(true);
      },
    );
  };

  const onDraft = (path: string, draft: Draft) => {
    setRejection(null);
    setDrafts((d) => ({ ...d, [path]: draft }));
  };

  const submitEdit = () => {
    if (built === null || Object.keys(built.errors).length > 0 || built.oversize || !built.changed) return;
    send({ decision: 'approve_edited', edits: built.edits });
  };

  const openDeny = () => {
    if (!canDeny) return;
    setDenyOpen(true);
    setDenyFocus((n) => n + 1);
  };

  const sendDeny = (reason: string | undefined, details: DenyDetails | undefined) => {
    send({
      decision: 'deny',
      ...(reason === undefined ? {} : { reason }),
      ...(details === undefined ? {} : { deny_details: details }),
    });
  };

  const cancelDeny = () => {
    setDenyOpen(false);
    heading.current?.focus();
  };

  // The chord runs the first positive action through `send()`, the same gate as the button.
  useImperativeHandle(ref, () => ({
    approve: () => {
      const primary = card?.positives[0];
      if (primary !== undefined) send(primary.args);
    },
    deny: openDeny,
  }));

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
    if (renderStructured) return renderStructured({ item, response: shown });
    if (form !== null) {
      return (
        <EditForm
          form={form}
          drafts={drafts}
          onDraft={onDraft}
          onReset={() => {
            setRejection(null);
            setDrafts({});
          }}
          onSubmit={submitEdit}
          canSubmit={editEnabled}
          rejection={rejection}
        />
      );
    }
    return <p>{DETAIL_TEXT.structured_pending}</p>;
  };

  return (
    <article className="detail" aria-label={DETAIL_TEXT.heading}>
      <h2 ref={heading} tabIndex={-1}>
        {DETAIL_TEXT.heading}
      </h2>
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
      {edited ? <p role="status">{EDIT_TEXT.applied}</p> : null}
      {unsentEdits ? <p role="status">{EDIT_TEXT.unsent}</p> : null}
      {actionFailed ? <p role="alert">{DETAIL_TEXT.action_failed}</p> : null}
      <DecisionBar
        card={card}
        canDeny={canDeny}
        positiveEnabled={positiveEnabled}
        busy={busy}
        onPositive={send}
        onDeny={openDeny}
        denyDialog={
          denyOpen && canDeny ? (
            <DenyDialog
              key={displayed ?? 'blocked'}
              offers={shown?.preview.deny_offers ?? []}
              prefill={shown?.preview.deny_prefill ?? null}
              busy={busy}
              focusToken={denyFocus}
              onSubmit={sendDeny}
              onCancel={cancelDeny}
            />
          ) : null
        }
      />
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
