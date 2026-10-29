import { Fragment, useId, type ReactNode } from 'react';

import type { DecideArgs } from '../shared/ipc/invoke';
import type { Preview, RedactionOp } from '../shared/ipc/types';
import { POSITIVE_ATTR } from './keyboard';
import { useText } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';
import type { Dict } from '../shared/i18n';

export type DecisionArgs = Omit<DecideArgs, 'request_id' | 'candidate_rev'>;

/** The redaction a "Release status only" sends (I-38): core's own preset, no text from the UI. */
export const STATUS_ONLY: readonly RedactionOp[] = [{ preset: 'status_only' }];

/** Body kinds whose card allows Deny only; Approve is shown disabled (spec 6.3, 5.4 step 2). */
const DENY_ONLY_KINDS: ReadonlySet<string> = new Set([
  'enrichment_error',
  'unresolved_name',
  'conflict',
]);

export interface Positive {
  label: string;
  args: DecisionArgs;
}

/** The positive actions of an opened revision's card, by body kind (spec 6.3). */
export interface Card {
  /** The first is what the approve/release chord runs. */
  positives: Positive[];
  /** A deny-only card shows Approve, disabled. */
  approveShownDisabled: boolean;
  /** Fixed consequence lines next to the actions. */
  lines: string[];
}

export function cardOf(preview: Preview, t: Dict = en): Card {
  const kind = preview.body.kind;
  const status = typeof preview.body.status === 'number' ? preview.body.status : null;
  const withStatus = (s: string) => s.replace('<status>', String(status ?? ''));
  if (preview.header.release_blocked !== null) {
    return { positives: [], approveShownDisabled: false, lines: [] };
  }
  if (kind === 'upstream_error') {
    return {
      positives: [
        { label: t.approvals.detail.release, args: { decision: 'release' } },
        {
          label: t.approvals.detail.release_status_only,
          args: { decision: 'release_redacted', redactions: [...STATUS_ONLY] },
        },
      ],
      approveShownDisabled: false,
      lines: [
        withStatus(t.approvals.detail.consequence_release),
        withStatus(t.approvals.detail.consequence_status_only),
        t.approvals.detail.consequence_deny,
      ],
    };
  }
  if (kind === 'outcome') {
    return {
      positives: [{ label: t.approvals.detail.release_outcome, args: { decision: 'release' } }],
      approveShownDisabled: false,
      lines: [t.approvals.detail.consequence_release_outcome, t.approvals.detail.consequence_deny],
    };
  }
  if (DENY_ONLY_KINDS.has(kind)) {
    return { positives: [], approveShownDisabled: true, lines: [] };
  }
  const isWrite = preview.header.class === 'write';
  return {
    positives: [
      isWrite
        ? { label: t.approvals.detail.approve, args: { decision: 'approve' } }
        : { label: t.approvals.detail.release, args: { decision: 'release' } },
    ],
    approveShownDisabled: false,
    lines: [],
  };
}

interface DecisionBarProps {
  /** The opened revision's card; null when nothing is opened (Deny may still be offered). */
  card: Card | null;
  /** Whether Deny is offered (an opened revision, or a candidate Rust could not build). */
  canDeny: boolean;
  /** Approve/release may be used: approvable, opened, not inert, nothing in flight. */
  positiveEnabled: boolean;
  busy: boolean;
  onPositive: (args: DecisionArgs) => void;
  onDeny: () => void;
  /** The open deny reason field, or null. */
  denyDialog: ReactNode;
}

/**
 * The card actions and the keyboard legend (PD-91). Positive buttons carry `POSITIVE_ATTR`, so
 * `useChords` drops Enter/Space on them (no single-key approval); they take a click or the chord.
 */
export function DecisionBar({
  card,
  canDeny,
  positiveEnabled,
  busy,
  onPositive,
  onDeny,
  denyDialog,
}: DecisionBarProps) {
  const t = useText();
  const marker = { [POSITIVE_ATTR]: '' };
  const legendId = useId();
  const several = (card?.positives.length ?? 0) > 1;
  return (
    <>
      <div className="detail-actions" role="group" aria-label={t.approvals.detail.actions_label}>
        {card?.positives.map((p, i) => (
          <Fragment key={p.label}>
            <button
              type="button"
              className="primary"
              {...marker}
              // Enter/Space do nothing on these buttons (single-key approval): the legend says why.
              aria-describedby={legendId}
              {...(i === 0 ? { 'aria-keyshortcuts': 'Control+Shift+Enter Meta+Shift+Enter' } : {})}
              disabled={!positiveEnabled}
              onClick={() => onPositive(p.args)}
            >
              {p.label}
            </button>
            {i === 0 && several ? (
              <span className="chord-marker">({t.approvals.keyboard.chord_runs})</span>
            ) : null}
          </Fragment>
        ))}
        {card?.approveShownDisabled === true ? (
          <button type="button" className="primary" {...marker} disabled>
            {t.approvals.detail.approve}
          </button>
        ) : null}
        {canDeny ? (
          <button type="button" className="danger" disabled={busy} aria-expanded={denyDialog !== null} onClick={onDeny}>
            {t.approvals.detail.deny}
          </button>
        ) : null}
        {card === null || card.lines.length === 0 ? null : (
          <ul className="consequences">
            {card.lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
      </div>
      {denyDialog}
      <ul className="keyboard-legend" aria-label={t.approvals.keyboard.legend_label}>
        <li id={legendId}>{t.approvals.keyboard.approve}</li>
        <li>{t.approvals.keyboard.deny}</li>
        <li>{t.approvals.keyboard.navigate}</li>
      </ul>
    </>
  );
}
