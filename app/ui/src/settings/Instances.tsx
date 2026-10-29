import { Fragment, useId, useState } from 'react';
import { useLang, useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';
import { en } from '../shared/i18n/dict';
import { formatIsoDate } from '../shared/i18n/format';

import {
  credentialWindowOpen,
  instanceAcceptUrlChange,
  instanceChangeUrl,
  instanceConfirmConfig,
  instanceSetProxy,
  retestToken,
} from '../shared/ipc/invoke';
import type { InstanceView, RetestOutcome } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';
import { Guard } from './Guard';
import { Cfg, expiryWarningText, own } from './text';
import { useAction } from './useAction';

const HEADER_STATES = ['identity_header_missing', 'identity_header_mismatch'];

interface InstancesProps {
  instances: readonly InstanceView[];
  /** Re-reads the window's state after a command changed something. */
  onChanged: () => void;
  /** config.toml is read-only: the controls that write it are off, token and re-test stay on. */
  readOnly: boolean;
}

/** The instances table (spec 7.1): one row per instance, its actions, the pending URL change. */
export function Instances({ instances, onChanged, readOnly }: InstancesProps) {
  const t = useText();
  if (instances.length === 0) return <p>{t.settings.no_instances}</p>;
  return (
    <div className="table-scroll">
    <table className="instances">
      <caption>{t.settings.instances}</caption>
      <thead>
        <tr>
          <th scope="col">{t.settings.col_alias}</th>
          <th scope="col">{t.settings.col_product}</th>
          <th scope="col">{t.settings.col_origin}</th>
          <th scope="col">{t.settings.col_state}</th>
          <th scope="col">{t.settings.col_executes_as}</th>
          <th scope="col">{t.settings.col_expiry}</th>
          <th scope="col">{t.settings.col_proxy}</th>
          <th scope="col">{t.settings.col_actions}</th>
        </tr>
      </thead>
      <tbody>
        {instances.map((inst) => (
          <InstanceRow key={inst.alias} inst={inst} onChanged={onChanged} readOnly={readOnly} />
        ))}
      </tbody>
    </table>
    </div>
  );
}

function stateLabel(state: string, t: Dict = en) {
  const known = own(t.settings.states, state);
  return known === undefined ? <Cfg value={state} /> : <>{known}</>;
}

function InstanceRow({
  inst,
  onChanged,
  readOnly,
}: {
  inst: InstanceView;
  onChanged: () => void;
  readOnly: boolean;
}) {
  const t = useText();
  const lang = useLang();
  // The repeated per-row controls point at the alias cell, so a reader hears which instance.
  const aliasId = useId();
  const warning = expiryWarningText(inst, t);
  const headerState = HEADER_STATES.includes(inst.state);
  return (
    <Fragment>
      <tr>
        <th scope="row" id={aliasId}>
          <Cfg value={inst.alias} />
        </th>
        <td>{t.settings.product[inst.product]}</td>
        <td>{inst.origin === null ? t.settings.no_origin : <Cfg value={inst.origin} />}</td>
        <td>
          {stateLabel(inst.state, t)}
          {inst.state === 'insecure_scheme' ? <p>{t.settings.https_required_hint}</p> : null}
          {headerState ? <p>{t.settings.identity_header_hint}</p> : null}
          {inst.note !== null && !headerState ? (
            <p>
              <AgentText value={inst.note} unusual={unusual(inst.note)} />
            </p>
          ) : null}
        </td>
        <td>{inst.executes_as === null ? t.settings.none : <AgentText value={inst.executes_as} unusual={unusual(inst.executes_as)} />}</td>
        <td>
          {inst.expires_at === null ? t.settings.none : <Cfg value={formatIsoDate(lang, inst.expires_at)} />}
          {warning === null ? null : (
            <p className="expiry-warning">
              {warning}. {t.settings.expiry_note}
            </p>
          )}
        </td>
        <td>
          {inst.proxy_effective === null ? t.settings.proxy_os : <Cfg value={inst.proxy_effective} />}
          {inst.pac_configured ? <p>{t.settings.pac_hint}</p> : null}
        </td>
        <td>
          <RowActions inst={inst} onChanged={onChanged} readOnly={readOnly} aliasId={aliasId} />
        </td>
      </tr>
      {inst.pending_url_change === null ? null : (
        <tr className="url-change">
          <td colSpan={8}>
            <PendingUrlChange
              inst={inst}
              url={inst.pending_url_change}
              onChanged={onChanged}
              readOnly={readOnly}
            />
          </td>
        </tr>
      )}
    </Fragment>
  );
}

function PendingUrlChange({
  inst,
  url,
  onChanged,
  readOnly,
}: {
  inst: InstanceView;
  url: string;
  onChanged: () => void;
  readOnly: boolean;
}) {
  const t = useText();
  const accept = useAction();
  return (
    <div role="note">
      <p>
        {t.settings.url_change} <Cfg value={inst.alias} />
      </p>
      <p>
        {t.settings.url_change_requested} <Cfg value={url} />
      </p>
      <Guard disabled={readOnly}>
        <button
          type="button"
          disabled={accept.pending}
          onClick={() =>
            void accept.run(() => instanceAcceptUrlChange(inst.alias)).then((v) => {
              if (v !== undefined) onChanged();
            })
          }
        >
          {t.settings.url_change_accept}
        </button>
      </Guard>
      {accept.error === null ? null : <p role="alert">{accept.error}</p>}
    </div>
  );
}

function RetestResult({ outcome }: { outcome: RetestOutcome }) {
  const t = useText();
  if ('ok' in outcome) {
    const { atlassian_user: user, product, version, warnings } = outcome.ok;
    return (
      <div role="status">
        <p>
          {t.settings.retest_connected} <AgentText value={user} unusual={unusual(user)} />
          {', '}
          {product === 'jira' || product === 'confluence' ? t.settings.product[product] : null}{' '}<AgentText value={version} unusual={unusual(version)} />
        </p>
        {warnings.length === 0 ? null : (
          <>
            <p>{t.settings.retest_warnings}</p>
            <ul>
              {warnings.map((w, i) => (
                <li key={i}>
                  <AgentText value={w} unusual={unusual(w)} />
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    );
  }
  // An unrecognized class is shown as fixed text only: the wire name is not echoed.
  const known = own(t.settings.retest_classes, outcome.failed.class) ?? t.settings.retest_class_unknown;
  return (
    <p role="status">
      {t.settings.retest_failed} {known}
    </p>
  );
}

function RowActions({
  inst,
  onChanged,
  readOnly,
  aliasId,
}: {
  inst: InstanceView;
  onChanged: () => void;
  readOnly: boolean;
  aliasId: string;
}) {
  const t = useText();
  const confirm = useAction();
  const retest = useAction();
  const token = useAction();
  const [outcome, setOutcome] = useState<RetestOutcome | null>(null);
  const done = (v: unknown) => {
    if (v !== undefined) onChanged();
  };
  const unconfirmed = inst.state === 'instance_unconfirmed';
  const retestable = inst.state === 'needs_token' || HEADER_STATES.includes(inst.state);
  // The replace button is not offered while the identity header is lost: a new token does not help.
  const tokenable = (inst.state === 'needs_token' || inst.state === 'ok');
  const adds = inst.executes_as === null;
  const tokenLabel = adds ? t.settings.add_token : t.settings.replace_token;
  return (
    <div className="instance-actions">
      {unconfirmed ? (
        <>
          <p>{t.settings.confirm_hint}</p>
          <Guard disabled={readOnly}>
            <button
              type="button"
              disabled={confirm.pending}
              aria-describedby={aliasId}
              onClick={() => void confirm.run(() => instanceConfirmConfig(inst.alias)).then(done)}
            >
              {t.settings.confirm}
            </button>
          </Guard>
          {confirm.error === null ? null : <p role="alert">{confirm.error}</p>}
        </>
      ) : null}
      {retestable ? (
        <button
          type="button"
          disabled={retest.pending}
          aria-describedby={aliasId}
          onClick={() =>
            void retest.run(() => retestToken(inst.alias)).then((v) => {
              if (v !== undefined) {
                setOutcome(v);
                onChanged();
              }
            })
          }
        >
          {t.settings.retest}
        </button>
      ) : null}
      {tokenable ? (
        <button
          type="button"
          disabled={token.pending}
          aria-describedby={aliasId}
          onClick={() =>
            void token.run(() =>
              credentialWindowOpen(inst.alias, adds ? 'add_pat' : 'replace_pat'),
            )
          }
        >
          {tokenLabel}
        </button>
      ) : null}
      {retest.error === null ? null : <p role="alert">{retest.error}</p>}
      {token.error === null ? null : <p role="alert">{token.error}</p>}
      {outcome === null ? null : <RetestResult outcome={outcome} />}
      <EditConnection inst={inst} onChanged={onChanged} readOnly={readOnly} aliasId={aliasId} />
    </div>
  );
}

function EditConnection({
  inst,
  onChanged,
  readOnly,
  aliasId,
}: {
  inst: InstanceView;
  onChanged: () => void;
  readOnly: boolean;
  aliasId: string;
}) {
  const t = useText();
  const url = useAction();
  const proxy = useAction();
  const [newUrl, setNewUrl] = useState('');
  const [newProxy, setNewProxy] = useState<string | null>(null);
  // The field starts empty: the effective proxy may come from the OS, and Apply on it would turn
  // that into an explicit override. Apply stays off until the field was edited.
  const proxyShown = newProxy ?? '';
  return (
    <details>
      <summary aria-describedby={aliasId}>{t.settings.change_url}</summary>
      <Guard disabled={readOnly}>
      <label>
        {t.settings.change_url_label}
        <input type="text" value={newUrl} aria-describedby={aliasId} onChange={(e) => setNewUrl(e.target.value)} />
      </label>
      <button
        type="button"
        disabled={url.pending || newUrl === ''}
        aria-describedby={aliasId}
        onClick={() =>
          void url.run(() => instanceChangeUrl(inst.alias, newUrl)).then((v) => {
            if (v !== undefined) {
              setNewUrl('');
              onChanged();
            }
          })
        }
      >
        {t.settings.change_url_apply}
      </button>
      {url.error === null ? null : <p role="alert">{url.error}</p>}
      <label>
        {t.settings.proxy_label}
        <input type="text" value={proxyShown} aria-describedby={aliasId} onChange={(e) => setNewProxy(e.target.value)} />
      </label>
      <button
        type="button"
        disabled={proxy.pending || newProxy === null}
        aria-describedby={aliasId}
        onClick={() =>
          void proxy.run(() => instanceSetProxy(inst.alias, proxyShown)).then((v) => {
            if (v !== undefined) {
              setNewProxy(null);
              onChanged();
            }
          })
        }
      >
        {t.settings.proxy_apply}
      </button>
      {proxy.error === null ? null : <p role="alert">{proxy.error}</p>}
      </Guard>
    </details>
  );
}
