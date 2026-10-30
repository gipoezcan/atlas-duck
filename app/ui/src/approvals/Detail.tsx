import {
  useCallback,
  useEffect,
  useId,
  useImperativeHandle,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type Ref,
} from 'react';

import { own } from '../shared/text/own';
import { decide, previewFetch, type DenyDetails } from '../shared/ipc/invoke';
import type { PreviewFetchResponse, QueueItem, UrlMode } from '../shared/ipc/types';
import { cardOf, DecisionBar, STATUS_ONLY, type DecisionArgs } from './DecisionBar';
import { DenyDialog } from './DenyDialog';
import { buildEdits, EditForm, type Draft, type Drafts } from './EditForm';
import { candidateKey, useInert } from './inert';
import { PreviewFrame } from './PreviewFrame';
import { RawPager } from './RawPager';
import { Panel } from './redaction/Panel';
import { canonical, type RoundOp } from './redaction/paths';
import {
  draftOf,
  preselectedRound,
  releaseReady,
  revKey,
  useCandidate,
  useFlagged,
  useRedactionReport,
} from './redaction/state';
import { RequestTab } from './RequestTab';
import { useText } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';

type TabId = 'preview' | 'structured' | 'raw' | 'request';

const TAB_IDS: readonly TabId[] = ['preview', 'structured', 'raw', 'request'];

type OpenState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  /** `error`: the rejection's kinds only (`errorCode`), for the alert's `data-error`. */
  | { kind: 'failed'; error: string }
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
  /** Reports whether this request's card holds unsent edits or redactions (false again when they go or the card unmounts). */
  onUnsentChange?: (requestId: string, unsent: boolean) => void;
}

/** The text of a `release_blocked` rejection, which Rust generates; every other error is one fixed text. */
function blockedText(e: unknown): string | null {
  if (typeof e === 'object' && e !== null && 'kind' in e && e.kind === 'release_blocked') {
    const text = (e as { text?: unknown }).text;
    return typeof text === 'string' ? text : null;
  }
  return null;
}

/** A Rust error kind: a short snake_case identifier, never text. */
const KIND = /^[a-z_]{1,40}$/;

function kindOf(e: unknown): string {
  if (typeof e !== 'object' || e === null || !('kind' in e)) return 'unknown';
  const kind = (e as { kind?: unknown }).kind;
  return typeof kind === 'string' && KIND.test(kind) ? kind : 'unknown';
}

/**
 * The kinds of a rejected call as `kind` or `decision/<core kind>`, `unknown` for anything that is
 * not an identifier. No text of the error: a test driver, which cannot read the console, reads it
 * from the failed-load alert's `data-error`.
 */
function errorCode(e: unknown): string {
  const kind = kindOf(e);
  if (kind !== 'decision') return kind;
  return `decision/${kindOf((e as { error?: unknown }).error)}`;
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
  // Shown whole: Rust cuts the escaped path on a boundary (`cap_path`), a cut here could split an
  // escape or an emoji sequence.
  return typeof message === 'string' ? message : '';
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
export function Detail({ item, openToken = 0, gone = false, renderStructured, ref, onUnsentChange }: DetailProps) {
  const t = useText();
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
  /** Reads (task 17): the redaction round built on the displayed revision, kept across tabs. */
  const [round, setRound] = useState<RoundOp[]>([]);
  const [urlChoice, setUrlChoice] = useState<UrlMode | null>(null);
  const [removeAll, setRemoveAll] = useState(false);
  /** The ops whose "N other occurrences remain" the user confirmed (bound to those exact ops). */
  const [confirmedKey, setConfirmedKey] = useState<string | null>(null);
  /** Text typed for a mask and not added yet. */
  const [pendingInput, setPendingInput] = useState(false);
  const [redactionApplied, setRedactionApplied] = useState(false);
  const panelRef = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const tabBase = useId();
  // Arrow keys, Home and End move between the tabs (WAI-ARIA tabs pattern, automatic activation).
  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
    const i = TAB_IDS.indexOf(tab);
    const n = TAB_IDS.length;
    const next = { ArrowRight: (i + 1) % n, ArrowLeft: (i - 1 + n) % n, Home: 0, End: n - 1 }[e.key];
    const id = next === undefined ? undefined : TAB_IDS[next];
    if (id === undefined) return;
    e.preventDefault();
    setTab(id);
    document.getElementById(`${tabBase}-${id}`)?.focus();
  };
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
    setRound([]);
    setUrlChoice(null);
    setRemoveAll(false);
    setConfirmedKey(null);
    setRedactionApplied(false);
    previewFetch(item.request_id).then(
      (response) => {
        if (mine !== latest.current) return;
        setState({ kind: 'open', response });
        // A preview can pre-select a redaction (spec 9.5): the round starts with it, an ordinary
        // unsent round that the panel lists and the approver can remove.
        setRound(preselectedRound(response.preview.preselect, response.redaction));
      },
      (e: unknown) => {
        if (mine !== latest.current) return;
        const text = blockedText(e);
        setState(text === null ? { kind: 'failed', error: errorCode(e) } : { kind: 'blocked', text });
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

  const blockedRaw =
    state.kind === 'blocked' ? state.text : (shown?.preview.header.release_blocked ?? null);
  // M15 T10: core's one release-blocked sentence in the UI language; any other text as Rust sent it.
  const releaseBlocked =
    blockedRaw === en.approvals.release_blocked_internal ? t.approvals.release_blocked_internal : blockedRaw;
  const card = gone || shown === null ? null : cardOf(shown.preview, t);
  const canDeny = !gone && (shown !== null || releaseBlocked !== null);
  const form = shown?.preview.edit_form ?? null;
  const built = form === null ? null : buildEdits(form, drafts, t);
  /** The form holds changes that are not sent: an approve would leave them out. */
  const unsentEdits = built?.changed ?? false;
  // Reads and scripts (task 17): the redaction round and what Release would send. The revision
  // shows the source with its own ops applied; the round is built on what it shows.
  const context = shown?.redaction ?? null;
  // M-11 (M8 T19c): a candidate the 5.3 mirror check blocks arrives with its banner and a redaction
  // context (a candidate that cannot be rebuilt at all has no preview, so it is not this). Its tree is
  // offered so the flagged entries can be dropped; only a release of those redactions is open.
  // The banner and a context are not enough (a revision with ops that failed at release time has
  // both): the item is mirror-blocked only when Rust's probe lists at least one mirror-flagged entry.
  // Without that, a fail-closed preview keeps the old behaviour: no panel, no tree, no release.
  const readable = context !== null && shown !== null && !gone && shown.preview.body.kind !== 'outcome';
  const mirrorProbe = readable && releaseBlocked !== null;
  const shownRev = shown?.preview.candidate_rev ?? null;
  const shownRevKey = shownRev === null ? '' : revKey(shownRev);
  const flagged = useFlagged(
    item.request_id,
    mirrorProbe ? shownRev : null,
    context?.ops ?? [],
    mirrorProbe && tab === 'structured',
  );
  const mirrorBlocked = mirrorProbe && flagged !== null && 'flagged' in flagged && flagged.flagged.length > 0;
  const redactable = readable && (releaseBlocked === null || mirrorBlocked);
  const draft = redactable ? draftOf(context, round, urlChoice, removeAll) : null;
  /** Redactions the user built and has not released: every other positive control is off. */
  const unsentRedactions = (draft?.unsent ?? false) || pendingInput;
  const report = useRedactionReport(item.request_id, redactable ? shownRev : null, draft);
  const candidate = useCandidate(item.request_id, redactable ? shownRev : null, redactable && tab === 'structured');
  const reportShown =
    report !== null && draft !== null && report.rev === shownRevKey && report.key === draft.key ? report : null;
  /** The redaction panel's Release (spec 5.3): the report for exactly these ops, nothing blocked, others confirmed. */
  const redactionReleaseOk =
    draft !== null && !pendingInput && releaseReady(draft, shownRevKey, report, confirmedKey);

  const positiveEnabled =
    shown !== null &&
    shown.preview.approvable &&
    !busy &&
    !denyOpen &&
    !unsentEdits &&
    !unsentRedactions &&
    !inert.approveInert;
  // A mirror-blocked revision is not approvable: only a release of drops that clear the flagged
  // entries (Rust's report for exactly those ops blocks nothing) goes through, never its own release.
  const panelReleaseEnabled =
    shown !== null &&
    (shown.preview.approvable || (mirrorBlocked && draft !== null && draft.unsent)) &&
    !busy &&
    !denyOpen &&
    !inert.approveInert &&
    redactionReleaseOk;
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
    // The one positive decision a mirror-blocked revision takes: the panel's redactions (checked below).
    const mirrorSend =
      mirrorBlocked && args.decision === 'release_redacted' && args.redactions !== undefined && draft !== null && draft.unsent;
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
      (!shown.preview.approvable && !mirrorSend) ||
      (releaseBlocked !== null && !mirrorSend) ||
      denyOpen ||
      unsentEdits ||
      inert.approveInertNow()
    ) {
      return;
    } else if (args.redactions !== undefined) {
      // A release with ops is either the panel's (exactly the ops Rust's last report was computed
      // for on this revision, nothing blocked, others confirmed) or the card's one-click "Release
      // status only" with no unreleased round. Anything else is not what the approver saw checked.
      const sent = canonical(args.redactions);
      const fromPanel =
        draft !== null &&
        draft.unsent &&
        sent === draft.key &&
        !pendingInput &&
        releaseReady(draft, shownRevKey, report, confirmedKey);
      const statusOnly =
        !unsentRedactions &&
        sent === canonical(STATUS_ONLY) &&
        card !== null &&
        card.positives.some((p) => p.args.redactions !== undefined && canonical(p.args.redactions) === sent);
      if (!fromPanel && !statusOnly) return;
    } else if (unsentRedactions) {
      // A plain release would leave the unreleased redactions out.
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
        } else if (outcome.status === 'pending' && args.redactions !== undefined) {
          // A redaction made a new revision (I-38). Ruling (T14 review I3): the fetch below
          // follows the user's own "Release status only" press, so it is not a navigation the user
          // did not ask for. The new revision is displayed once the queue re-read brings it, and
          // `useInert` starts the inert period then, as for any displayed candidate change.
          // Task 17: the panel's release with ops takes the same path; the round is cleared by the
          // open, the new revision's own ops come with its preview.
          open();
          setRedactionApplied(true);
        } else {
          // No auto-advance: the decided item stays selected, its preview is cleared, nothing is fetched.
          // Only a redaction makes a new revision: any other `pending` is an approved write that has
          // not started yet (core's stale check runs first), recorded like every other decision.
          latest.current++;
          setState({ kind: 'idle' });
          setDecided(
            outcome.status === 'pending'
              ? t.approvals.detail.decided_approved
              : (own(t.approvals.status_labels, outcome.status) ?? outcome.status),
          );
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

  const releaseFromPanel = () => {
    if (draft === null) return;
    send(draft.unsent ? { decision: 'release_redacted', redactions: draft.ops } : { decision: 'release' });
  };

  /**
   * Focus or a text selection in the redaction panel: the user is building redactions there, so a
   * window-wide approve chord must not release past them (the panel's Release button still works).
   */
  const panelHolds = (): boolean => {
    const el = panelRef.current;
    if (el === null) return false;
    if (el.contains(document.activeElement)) return true;
    const sel = window.getSelection();
    return (
      sel !== null && !sel.isCollapsed && (el.contains(sel.anchorNode) || el.contains(sel.focusNode))
    );
  };

  // The window learns of unsent edits or redactions, so a batch does not decide this request
  // without them (its own Approve/Release is off for the same reason).
  const unsent = !gone && (unsentEdits || unsentRedactions);
  const requestId = item.request_id;
  useEffect(() => {
    if (!unsent) return;
    onUnsentChange?.(requestId, true);
    return () => onUnsentChange?.(requestId, false);
  }, [unsent, requestId, onUnsentChange]);

  // The chord runs the first positive action through `send()`, the same gate as the button.
  useImperativeHandle(ref, () => ({
    approve: () => {
      if (panelHolds()) return;
      const primary = card?.positives[0];
      if (primary !== undefined) send(primary.args);
    },
    deny: openDeny,
  }));

  const needsOpen = shown === null && state.kind !== 'loading';
  const panel = (): ReactNode => {
    if (tab === 'request') return <RequestTab requestId={item.request_id} />;
    if (shown === null) {
      if (state.kind === 'loading') return <p role="status">{t.approvals.detail.loading}</p>;
      if (state.kind === 'failed') {
        return (
          <p role="alert" data-error={state.error}>
            {t.approvals.detail.load_failed}
          </p>
        );
      }
      return <p>{t.approvals.detail.not_opened}</p>;
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
    if (redactable && draft !== null && context !== null) {
      return (
        <Panel
          ref={panelRef}
          candidate={candidate}
          context={context}
          appliedAlsoAppearsIn={shown.preview.also_appears_in}
          round={round}
          onRound={(next) => {
            setRemoveAll(false);
            setRound(next);
          }}
          urlChoice={urlChoice}
          onUrlChoice={setUrlChoice}
          removeAll={removeAll}
          onRemoveAll={(on) => {
            setRound([]);
            setRemoveAll(on);
          }}
          draft={draft}
          report={reportShown}
          confirmed={confirmedKey === draft.key}
          onConfirm={(on) => setConfirmedKey(on ? draft.key : null)}
          upstreamError={shown.preview.body.kind === 'upstream_error'}
          script={shown.preview.header.class === 'script'}
          mirrorBlocked={mirrorBlocked}
          flagged={flagged}
          canRelease={panelReleaseEnabled}
          onRelease={releaseFromPanel}
          onPendingInput={setPendingInput}
        />
      );
    }
    // A probe that failed fails closed: no panel (so no drop offer and no release path), only the way out.
    if (mirrorProbe && flagged !== null && 'failed' in flagged) return <p role="alert">{t.approvals.redaction.flagged_missing}</p>;
    return <p>{t.approvals.redaction.nothing}</p>;
  };

  return (
    <article className="detail" aria-label={t.approvals.detail.heading}>
      <h2 ref={heading} tabIndex={-1} className="detail-heading">
        {t.approvals.detail.heading}
      </h2>
      <p className="detail-summary">
        <span className="op-id">{item.op_id}</span>{' '}
        <span className="class">{own(t.approvals.class_labels, item.class) ?? item.class}</span>{' '}
        <span className="alias">{item.instance_alias}</span>{' '}
        <span className="target">{item.target_display}</span>
      </p>
      {releaseBlocked === null ? null : (
        <div className="caution-strip" role="alert">
          <strong>{t.approvals.detail.caution_prefix}</strong> {releaseBlocked}
        </div>
      )}
      {!gone && (stale || needsOpen) ? (
        <button type="button" onClick={open}>
          {t.approvals.detail.open}
        </button>
      ) : null}
      {decided === null ? null : <p role="status">{`${t.approvals.detail.decided}: ${decided}`}</p>}
      {edited ? <p role="status">{t.approvals.edit.applied}</p> : null}
      {unsentEdits ? <p role="status">{t.approvals.edit.unsent}</p> : null}
      {redactionApplied ? <p role="status">{t.approvals.redaction.applied}</p> : null}
      {unsentRedactions ? <p role="status">{t.approvals.redaction.unsent}</p> : null}
      {actionFailed ? <p role="alert">{t.approvals.detail.action_failed}</p> : null}
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
      <div role="tablist" aria-label={t.approvals.detail.tabs_label} onKeyDown={onTabKey}>
        {TAB_IDS.map((id) => (
          <button
            key={id}
            id={`${tabBase}-${id}`}
            type="button"
            role="tab"
            aria-selected={tab === id}
            aria-controls={`${tabBase}-panel`}
            tabIndex={tab === id ? 0 : -1}
            onClick={() => setTab(id)}
          >
            {t.approvals.detail[`tab_${id}`]}
          </button>
        ))}
      </div>
      <div role="tabpanel" tabIndex={0} id={`${tabBase}-panel`} aria-labelledby={`${tabBase}-${tab}`} className="detail-panel">
        {panel()}
      </div>
    </article>
  );
}
