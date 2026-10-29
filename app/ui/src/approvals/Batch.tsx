import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';

import { own } from '../shared/text/own';
import { decideBatch, denyBatch, denySession } from '../shared/ipc/invoke';
import type { BatchItem } from '../shared/ipc/invoke';
import type { QueueItem } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { sessionLabel } from './Queue';
import { useInert } from './inert';
import { useText } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';
import type { Dict } from '../shared/i18n';

/** plan text (PD-66): a reason is at most 1 000 characters; Rust re-validates. */
const REASON_MAX = 1_000;

/** What the UI mirrors of Rust's batch pre-check (`decision/batch.rs`); Rust re-checks every rule. */
export function isFlagged(item: QueueItem): boolean {
  return item.possible_duplicate_of !== null || item.similar_to !== null;
}

export interface BatchSplit {
  /** Opened in its current revision, approvable, unflagged: the batch's items. */
  eligible: QueueItem[];
  /** Flagged "possible duplicate" / "similar request": never in a batch, decided individually. */
  flagged: QueueItem[];
  /** Unflagged but not opened or not approvable: they keep the whole batch disabled. */
  blocked: { item: QueueItem; why: 'unopened' | 'not_approvable' | 'unsent' }[];
}

export function splitSelection(selected: readonly QueueItem[], unsentId: string | null = null): BatchSplit {
  const out: BatchSplit = { eligible: [], flagged: [], blocked: [] };
  for (const item of selected) {
    if (isFlagged(item)) out.flagged.push(item);
    else if (item.request_id === unsentId) out.blocked.push({ item, why: 'unsent' });
    else if (!item.opened) out.blocked.push({ item, why: 'unopened' });
    else if (!item.approvable) out.blocked.push({ item, why: 'not_approvable' });
    else out.eligible.push(item);
  }
  return out;
}

/** Everything a batch decision depends on, so that any change of it closes an open confirmation. */
function signature(selected: readonly QueueItem[], unsentId: string | null): string | null {
  if (selected.length === 0) return null;
  return selected
    .map((i) =>
      [
        i.request_id,
        i.candidate_rev.counter,
        i.candidate_rev.candidate_hash,
        i.opened,
        i.approvable,
        i.possible_duplicate_of,
        i.similar_to,
        i.class,
        i.request_id === unsentId,
      ].join(':'),
    )
    .join('|');
}

/** "release 2 reads, approve 1 write": the classes of the items the confirmation names. */
export function classSummary(items: readonly QueueItem[], t: Dict = en): string {
  const count = (cls: string) => items.filter((i) => i.class === cls).length;
  const reads = count('read');
  const scripts = count('script');
  // Like the native dialog: every request that is neither a read nor a script counts as a write.
  const writes = items.length - reads - scripts;
  return t.approvals.batch.class_summary(items.length, reads, scripts, writes);
}
/** What one panel is open: the confirmation of a batch approve/release, or a deny reason field. */
type Panel =
  | { kind: 'confirm'; sig: string; items: BatchItem[]; shown: QueueItem[] }
  | { kind: 'deny'; sig: string; scope: { session: string | null } };

/** What the user saw per request id when the call was made: a decided item has left the queue by the time the answer shows. */
type Names = ReadonlyMap<string, string>;

type Result =
  | { kind: 'decided'; items: { request_id: string; status: string }[]; names: Names }
  | { kind: 'denied'; count: number }
  | { kind: 'nothing_pending' }
  | { kind: 'rejected'; failed: { request_id: string; code: string }[] | null; names: Names }
  | { kind: 'cancelled' }
  | { kind: 'failed'; deny: boolean };

/** `batch_rejected`'s failed list (`[[request_id, code], ...]`), or null when the error is another. */
function rejectedFailures(e: unknown): { request_id: string; code: string }[] | null | undefined {
  if (typeof e !== 'object' || e === null || (e as { kind?: unknown }).kind !== 'decision') return undefined;
  const inner = (e as { error?: unknown }).error;
  if (typeof inner !== 'object' || inner === null || (inner as { kind?: unknown }).kind !== 'batch_rejected') {
    return undefined;
  }
  const failed = (inner as { failed?: unknown }).failed;
  if (!Array.isArray(failed)) return null;
  const out: { request_id: string; code: string }[] = [];
  for (const f of failed) {
    if (!Array.isArray(f) || typeof f[0] !== 'string' || typeof f[1] !== 'string') return null;
    out.push({ request_id: f[0], code: f[1] });
  }
  return out;
}

const isCancelled = (e: unknown): boolean => {
  if (typeof e !== 'object' || e === null || (e as { kind?: unknown }).kind !== 'decision') return false;
  const inner = (e as { error?: unknown }).error;
  return typeof inner === 'object' && inner !== null && (inner as { kind?: unknown }).kind === 'cancelled';
};

interface BatchProps {
  /** The queue as the window shows it now. */
  items: readonly QueueItem[];
  /** The ids `Queue` reports as selected; an id the queue no longer holds is ignored. */
  selectedIds: readonly string[];
  /** The open request whose card holds unsent edits or redactions: a batch would drop them, so it is blocked. */
  unsentId?: string | null;
  /** Whether a panel is open or a batch call is running (the window then ignores its approve chord). */
  onEngagedChange?: (engaged: boolean) => void;
}

/**
 * Batch decisions on the selected queue rows (spec 5.6, L43). The UI mirrors Rust's rules and never
 * decides them: Rust re-checks every item, shows its native confirmation and answers per item.
 *
 * - Approve/release is offered only when every selected, unflagged row is opened in its current
 *   revision and approvable; flagged rows are listed as "approve individually" and left out.
 * - It takes two steps (a confirmation that names the count and the classes), both inert for
 *   `INERT_MS` after the selection or any fact a batch depends on changes, plus the window's periods.
 *   The confirmation closes when anything it was built from changes, and the call carries the
 *   revisions the confirmation showed.
 * - Deny (of the selection, or of a whole session) takes one reason and has no dialog.
 * - A call in flight blocks every other one; nothing advances on its own.
 */
export function Batch({ items, selectedIds, unsentId = null, onEngagedChange }: BatchProps) {
  const t = useText();
  const selected = useMemo(() => {
    const ids = new Set(selectedIds);
    return items.filter((i) => ids.has(i.request_id));
  }, [items, selectedIds]);
  const sig = useMemo(() => signature(selected, unsentId), [selected, unsentId]);
  const split = useMemo(() => splitSelection(selected, unsentId), [selected, unsentId]);

  const [panel, setPanel] = useState<Panel | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [reason, setReason] = useState('');
  const [reasonMissing, setReasonMissing] = useState(false);

  // Anything the open panel was built from changing closes it: a confirmation never outlives the
  // selection and revisions it showed, and a typed reason never goes to another set of requests.
  if (panel !== null && panel.sig !== sig) {
    setPanel(null);
    setReason('');
    setReasonMissing(false);
  }
  const open = panel !== null && panel.sig === sig ? panel : null;

  // The inert period restarts when the selection or a fact the batch depends on changes, and when
  // the confirmation opens; the confirm and the first-step buttons both follow it.
  const inert = useInert(sig === null ? null : `${sig}#${open?.kind === 'confirm' ? 'c' : '-'}`);

  const engaged = open !== null || busy;
  const notify = useRef(onEngagedChange);
  useEffect(() => {
    notify.current = onEngagedChange;
  });
  useEffect(() => {
    notify.current?.(engaged);
    return () => notify.current?.(false);
  }, [engaged]);

  const reasonField = useRef<HTMLInputElement>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const openKind = open?.kind ?? null;
  useEffect(() => {
    if (openKind === 'deny') reasonField.current?.focus();
    // Focus the safe button: a stray Enter after the confirmation opens must not confirm.
    else if (openKind === 'confirm') cancelButton.current?.focus();
  }, [openKind]);

  const ids = useId();

  const canBatch = split.blocked.length === 0 && split.eligible.length > 0;

  const openConfirm = () => {
    if (!canBatch || inFlight.current || sig === null || inert.approveInertNow()) return;
    setResult(null);
    setPanel({
      kind: 'confirm',
      sig,
      // The revisions of the rows the user has just seen; they are what the call carries.
      items: split.eligible.map((i) => ({
        request_id: i.request_id,
        candidate_rev: { counter: i.candidate_rev.counter, candidate_hash: i.candidate_rev.candidate_hash },
      })),
      shown: split.eligible,
    });
  };

  const confirm = () => {
    if (open === null || open.kind !== 'confirm' || open.sig !== sig) return;
    if (inFlight.current || inert.approveInertNow()) return;
    inFlight.current = true;
    setBusy(true);
    setResult(null);
    const sent: BatchItem[] = open.items;
    const names: Names = new Map(open.shown.map((i) => [i.request_id, `${i.op_id} ${i.target_display}`]));
    decideBatch(sent).then(
      (outcome) => {
        inFlight.current = false;
        setBusy(false);
        setPanel(null);
        setResult({ kind: 'decided', items: outcome.items, names });
      },
      (e: unknown) => {
        inFlight.current = false;
        setBusy(false);
        setPanel(null);
        const failures = rejectedFailures(e);
        if (failures !== undefined) setResult({ kind: 'rejected', failed: failures, names });
        else if (isCancelled(e)) setResult({ kind: 'cancelled' });
        else setResult({ kind: 'failed', deny: false });
      },
    );
  };

  const openDeny = (session: string | null) => {
    if (inFlight.current || sig === null) return;
    setResult(null);
    setReason('');
    setReasonMissing(false);
    setPanel({ kind: 'deny', sig, scope: { session } });
  };

  const sendDeny = () => {
    if (open === null || open.kind !== 'deny' || open.sig !== sig || inFlight.current) return;
    const text = reason.trim();
    if (text === '') {
      setReasonMissing(true);
      return;
    }
    inFlight.current = true;
    setBusy(true);
    setResult(null);
    const call =
      open.scope.session === null
        ? denyBatch(
            selected.map((i) => i.request_id),
            text,
          )
        : denySession(open.scope.session, text);
    call.then(
      (r) => {
        inFlight.current = false;
        setBusy(false);
        setPanel(null);
        setReason('');
        setResult({ kind: 'denied', count: r.denied });
      },
      (e: unknown) => {
        inFlight.current = false;
        setBusy(false);
        setPanel(null);
        const none = open.scope.session !== null && (e as { kind?: unknown } | null)?.kind === 'not_found';
        setResult(none ? { kind: 'nothing_pending' } : { kind: 'failed', deny: true });
      },
    );
  };

  // No single key decides (T15, spec 5.6): Enter never activates Confirm, so one held or typed Enter
  // cannot pass this step and the native dialog that opens under it. Space acts on key-up, after the
  // key is up; auto-repeat is ignored for every key.
  const onConfirmKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'Enter' || e.repeat) e.preventDefault();
  };

  const onReasonKey = (e: KeyboardEvent<HTMLInputElement>) => {
    const plain = !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey;
    if (e.key === 'Enter') {
      e.preventDefault();
      const composing = e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229;
      if (plain && !e.repeat && !composing) sendDeny();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setPanel(null);
    }
  };

  // One "deny all pending from this session" per session among the selected rows.
  const sessions = useMemo(() => {
    const seen = new Map<string, { label: string; unusual: boolean }>();
    for (const i of selected) {
      const s = seen.get(i.session_id);
      seen.set(i.session_id, { label: sessionLabel(i, t), unusual: (s?.unusual ?? false) || i.unusual });
    }
    return [...seen.entries()];
  }, [selected, t]);

  const reviewDisabled = !canBatch || busy || inert.approveInert;
  const confirmDisabled = busy || inert.approveInert;

  if (selected.length === 0 && result === null) return null;

  return (
    <section className="batch" aria-label={t.approvals.batch.label}>
      <h2>{t.approvals.batch.label}</h2>
      {selected.length > 0 ? (
        <>
          <p role="status">{t.approvals.batch.selected(selected.length)}</p>
          {split.flagged.length > 0 ? (
            <div className="batch-excluded">
              <p>{t.approvals.batch.excluded}</p>
              <ul>
                {split.flagged.map((i) => (
                  <li key={i.request_id}>
                    {i.op_id} {i.target_display}: {t.approvals.batch.individually}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {split.blocked.length > 0 ? (
            <div className="batch-blocked" role="note">
              <p>{t.approvals.batch.blocked}</p>
              <ul>
                {split.blocked.map(({ item, why }) => (
                  <li key={item.request_id}>
                    {item.op_id} {item.target_display}:{' '}
                    {why === 'unopened'
                      ? t.approvals.batch.blocked_unopened
                      : why === 'unsent'
                        ? t.approvals.batch.blocked_unsent
                        : t.approvals.batch.blocked_not_approvable}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="batch-actions">
            <button type="button" disabled={reviewDisabled} onClick={openConfirm}>
              {t.approvals.batch.review(split.eligible.length)}
            </button>
            <button type="button" disabled={busy} onClick={() => openDeny(null)}>
              {t.approvals.batch.deny_selected}
            </button>
          </div>
          {sessions.map(([sessionId, s]) => (
            <div key={sessionId} className="batch-session" role="group" aria-labelledby={`${ids}-${sessionId}`}>
              <span id={`${ids}-${sessionId}`}>
                {t.approvals.batch.session} <AgentText value={s.label} unusual={s.unusual} />
              </span>{' '}
              <button type="button" disabled={busy} onClick={() => openDeny(sessionId)}>
                {t.approvals.batch.deny_session}
              </button>
            </div>
          ))}
        </>
      ) : null}
      {open?.kind === 'confirm' ? (
        <div className="batch-confirm" role="group" aria-label={t.approvals.batch.confirm_title}>
          <p>{t.approvals.batch.confirm_summary(classSummary(open.shown, t))}</p>
          <ul>
            {open.shown.map((i) => (
              <li key={i.request_id}>
                {own(t.approvals.class_labels, i.class) ?? i.class} {i.op_id} {i.instance_alias} {i.target_display}
              </li>
            ))}
          </ul>
          <p>{t.approvals.batch.confirm_note}</p>
          <button type="button" disabled={confirmDisabled} onClick={confirm} onKeyDown={onConfirmKey}>
            {t.approvals.batch.confirm}
          </button>
          <button type="button" ref={cancelButton} disabled={busy} onClick={() => setPanel(null)}>
            {t.approvals.batch.cancel}
          </button>
        </div>
      ) : null}
      {open?.kind === 'deny' ? (
        <div
          className="deny-dialog"
          role="group"
          aria-label={
            open.scope.session === null ? t.approvals.batch.deny_selected_title(selected.length) : t.approvals.batch.deny_session_title
          }
        >
          {open.scope.session === null ? (
            <p>{t.approvals.batch.deny_selected_title(selected.length)}</p>
          ) : (
            <p>
              {t.approvals.batch.deny_session_title}. {t.approvals.batch.deny_session_note}
            </p>
          )}
          <label htmlFor={`${ids}-reason`}>{t.approvals.batch.deny_reason}</label>
          <input
            id={`${ids}-reason`}
            ref={reasonField}
            type="text"
            value={reason}
            maxLength={REASON_MAX}
            aria-invalid={reasonMissing}
            onChange={(e) => {
              setReason(e.currentTarget.value);
              setReasonMissing(false);
            }}
            onKeyDown={onReasonKey}
          />
          {reasonMissing ? <span role="alert">{t.approvals.batch.deny_reason_required}</span> : null}
          <button type="button" disabled={busy} onClick={sendDeny}>
            {t.approvals.batch.deny_send}
          </button>
          <button type="button" onClick={() => setPanel(null)}>
            {t.approvals.batch.cancel}
          </button>
        </div>
      ) : null}
      <ResultView result={result} />
    </section>
  );
}

/** An approved write answers `pending` until it starts (its stale check runs first): said as the
 * Detail card says it, not as the raw status. */
function itemStatus(status: string, t: Dict): string {
  return status === 'pending' ? `${t.approvals.detail.decided}: ${t.approvals.detail.decided_approved}` : status;
}

function ResultView({ result }: { result: Result | null }) {
  const t = useText();
  if (result === null) return null;
  switch (result.kind) {
    case 'decided':
      return (
        <div role="status">
          <p>{t.approvals.batch.decided(result.items.length)}</p>
          <ul>
            {result.items.map((i) => (
              <li key={i.request_id}>
                {result.names.get(i.request_id) ?? i.request_id}: {itemStatus(i.status, t)}
              </li>
            ))}
          </ul>
        </div>
      );
    case 'denied':
      return <p role="status">{t.approvals.batch.denied(result.count)}</p>;
    case 'nothing_pending':
      return <p role="status">{t.approvals.batch.nothing_pending}</p>;
    case 'cancelled':
      return <p role="status">{t.approvals.batch.cancelled}</p>;
    case 'rejected':
      return (
        <div role="alert">
          <p>{result.failed === null ? t.approvals.batch.rejected_unknown : t.approvals.batch.rejected}</p>
          <ul>
            {(result.failed ?? []).map((f) => (
              <li key={`${f.request_id}-${f.code}`}>
                {result.names.get(f.request_id) ?? f.request_id}: {own(t.approvals.batch_failure, f.code) ?? t.approvals.batch_failure_unknown}
              </li>
            ))}
          </ul>
        </div>
      );
    case 'failed':
      return <p role="alert">{result.deny ? t.approvals.batch.deny_failed : t.approvals.batch.failed}</p>;
  }
}
