import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';

import type { DenyDetails } from '../shared/ipc/invoke';
import type { DenyOffer, DenyOfferKind } from '../shared/ipc/types';
import { useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';

/** plan text (PD-66): a reason is at most 1 000 characters; Rust re-validates. */
const REASON_MAX = 1_000;

/** The label of each offer and of its optional part (PD-70). */
function offerText(t: Dict): Record<DenyOfferKind, { label: string; detail: string | null }> {
  return {
  upstream_http: { label: t.approvals.deny.upstream_http, detail: t.approvals.deny.upstream_http_detail },
  outcome_hint: { label: t.approvals.deny.outcome_hint, detail: null },
  resolution_failed: {
    label: t.approvals.deny.resolution_failed,
    detail: t.approvals.deny.resolution_failed_detail,
  },
  missing_fields: { label: t.approvals.deny.missing_fields, detail: t.approvals.deny.missing_fields_detail },
  };
}

/** The `deny_details` wire value of an offer kind, its optional part ticked or not. */
export function denyDetailsOf(kind: DenyOfferKind, withDetail: boolean): DenyDetails {
  switch (kind) {
    case 'upstream_http':
      return { upstream_http: { include_messages: withDetail } };
    case 'outcome_hint':
      return 'outcome_hint';
    case 'resolution_failed':
      return { resolution_failed: { include_candidates: withDetail } };
    case 'missing_fields':
      return { missing_fields: { include_allowed_values: withDetail } };
  }
}

interface DenyDialogProps {
  /** Exactly the hints Rust accepts for this revision (`preview.deny_offers`); empty without a preview. */
  offers: readonly DenyOffer[];
  /** Rust's pre-filled reason (a conflict hold), editable. */
  prefill: string | null;
  busy: boolean;
  /** Bumped when the deny chord is pressed again while the field is open: focus returns to it. */
  focusToken: number;
  onSubmit: (reason: string | undefined, details: DenyDetails | undefined) => void;
  onCancel: () => void;
}

/**
 * The deny reason field (spec 5.6): it opens focused, Enter sends the deny, Esc cancels. A hint is
 * attached only when ticked, at most one (`decide` carries one `deny_details`), and only from
 * `offers`; the optional Atlassian-derived part is off until ticked (spec 5.4 step 2).
 */
export function DenyDialog({ offers, prefill, busy, focusToken, onSubmit, onCancel }: DenyDialogProps) {
  const [reason, setReason] = useState(prefill ?? '');
  const [chosen, setChosen] = useState<DenyOfferKind | null>(null);
  const [withDetail, setWithDetail] = useState(false);
  const field = useRef<HTMLInputElement>(null);
  const ids = useId();
  const t = useText();
  const OFFER_TEXT = offerText(t);

  useEffect(() => {
    field.current?.focus();
  }, [focusToken]);

  const submit = () => {
    const offer = offers.find((o) => o.kind === chosen);
    const details =
      offer === undefined
        ? undefined
        : denyDetailsOf(offer.kind, offer.has_optional_detail && withDetail);
    onSubmit(reason.trim() === '' ? undefined : reason, details);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    const plain = !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey;
    if (e.key === 'Enter') {
      e.preventDefault();
      // The Enter that commits an IME composition is not a submit (WebKit reports keyCode 229).
      const composing = e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229;
      if (plain && !e.repeat && !composing) submit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  };

  const choose = (kind: DenyOfferKind, on: boolean) => {
    setChosen(on ? kind : null);
    setWithDetail(false);
  };

  return (
    <div className="deny-dialog" role="group" aria-label={t.approvals.deny.label}>
      <label htmlFor={`${ids}-reason`}>{t.approvals.deny.reason}</label>
      <input
        id={`${ids}-reason`}
        ref={field}
        type="text"
        value={reason}
        maxLength={REASON_MAX}
        aria-describedby={`${ids}-keys`}
        onChange={(e) => setReason(e.currentTarget.value)}
        onKeyDown={onKeyDown}
      />
      <span id={`${ids}-keys`} className="deny-keys">
        {t.approvals.deny.keys}
      </span>
      {offers.length === 0 ? null : (
        <fieldset className="deny-offers" aria-describedby={`${ids}-one`}>
          <legend>{t.approvals.deny.offers}</legend>
          <span id={`${ids}-one`} className="deny-keys">
            {t.approvals.deny.offers_one}
          </span>
          {offers.map((offer) => {
            const text = OFFER_TEXT[offer.kind];
            const on = chosen === offer.kind;
            return (
              <div key={offer.kind}>
                <label>
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={(e) => choose(offer.kind, e.currentTarget.checked)}
                  />
                  {text.label}
                </label>
                {offer.has_optional_detail && text.detail !== null ? (
                  <label className="deny-offer-detail">
                    <input
                      type="checkbox"
                      checked={on && withDetail}
                      disabled={!on}
                      onChange={(e) => setWithDetail(e.currentTarget.checked)}
                    />
                    {text.detail}
                  </label>
                ) : null}
              </div>
            );
          })}
        </fieldset>
      )}
      <button type="button" disabled={busy} onClick={submit}>
        {t.approvals.deny.submit}
      </button>
      <button type="button" onClick={onCancel}>
        {t.approvals.deny.cancel}
      </button>
    </div>
  );
}
