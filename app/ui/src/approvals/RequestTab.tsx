import { useEffect, useState } from 'react';

import { queueGet } from '../shared/ipc/invoke';
import type { QueueDetail } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { Badge } from '../shared/text/Badge';
import { formatAge } from './Queue';
import { useLang, useText } from '../shared/i18n/context';
import { formatTimestamp } from '../shared/i18n/format';

interface RequestTabProps {
  requestId: string;
}

/** The params as JSON text: a text node in a `<pre>`, never markup. */
export function paramsText(params: unknown): string {
  return JSON.stringify(params, null, 2) ?? 'null';
}

/** The limits a script asked for (`script.run` params `limits`), or null when it sent none. */
function limitsOf(params: unknown): unknown {
  if (typeof params !== 'object' || params === null || !('limits' in params)) return null;
  return (params as { limits?: unknown }).limits ?? null;
}

/**
 * The Request tab (spec 5.6): what the agent asked and who is asking. Everything is a text node:
 * agent strings go through `AgentText`, the rest (params, hashes, process paths, timestamps) are
 * plain text that Rust already display-escaped.
 */
export function RequestTab({ requestId }: RequestTabProps) {
  const t = useText();
  const lang = useLang();
  const [detail, setDetail] = useState<QueueDetail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    setFailed(false);
    queueGet(requestId).then(
      (d) => {
        if (live) setDetail(d);
      },
      () => {
        if (live) setFailed(true);
      },
    );
    return () => {
      live = false;
    };
  }, [requestId]);

  if (failed) return <p role="alert">{t.approvals.request.load_failed}</p>;
  if (detail === null) return <p role="status">{t.approvals.request.loading}</p>;

  const { item, request: r } = detail;
  const limits = limitsOf(r.params);
  const text = (v: string | number | null) => (v === null || v === '' ? t.approvals.request.none : String(v));
  return (
    <section className="request-tab" aria-label={t.approvals.request.connection}>
      <dl>
        <dt>{t.approvals.request.op}</dt>
        <dd>{item.op_id}</dd>
        <dt>{t.approvals.request.instance}</dt>
        <dd>{item.instance_alias}</dd>
        {item.class === 'script' ? (
          <>
            <dt>{t.approvals.request.target}</dt>
            <dd>
              <AgentText value={item.target_display} unusual={item.unusual} />
            </dd>
            <dt>{t.approvals.request.limits}</dt>
            <dd>
              {limits === null ? (
                t.approvals.request.limits_default
              ) : (
                <pre className="params-text" tabIndex={0}>
                  {paramsText(limits)}
                </pre>
              )}
            </dd>
          </>
        ) : null}
        <dt>{t.approvals.request.reason}</dt>
        <dd>
          {r.reason === null || r.reason === '' ? (
            <Badge label={t.approvals.queue.no_reason} />
          ) : (
            <AgentText value={r.reason} unusual={item.unusual} />
          )}
        </dd>
        <dt>{t.approvals.request.params}</dt>
        <dd>
          <pre className="params-text" tabIndex={0}>
            {paramsText(r.params)}
          </pre>
        </dd>
        <dt>{t.approvals.request.params_sha256}</dt>
        <dd>{r.params_sha256}</dd>
        <dt>{t.approvals.request.submitted_at}</dt>
        <dd>{formatTimestamp(lang, r.submitted_at)}</dd>
        <dt>{t.approvals.request.age}</dt>
        <dd>{formatAge(item.age_s, t)}</dd>
        <dt>{t.approvals.request.client_kind}</dt>
        <dd>{text(r.client_kind)}</dd>
        <dt>{t.approvals.request.agent_name}</dt>
        <dd>
          {r.agent_name === null ? (
            t.approvals.request.none
          ) : (
            <AgentText value={r.agent_name} unusual={item.unusual} />
          )}
        </dd>
        <dt>{t.approvals.request.agent_name_source}</dt>
        <dd>{text(r.agent_name_source)}</dd>
        <dt>{t.approvals.request.cwd_basename}</dt>
        <dd>
          <AgentText value={r.cwd_basename} unusual={item.unusual} />
        </dd>
        <dt>{t.approvals.request.connection_id}</dt>
        <dd>{text(r.connection_id)}</dd>
        <dt>{t.approvals.request.peer_pid}</dt>
        <dd>
          {text(r.peer_pid)} <Badge label={t.approvals.unverified} />
        </dd>
        <dt>{t.approvals.request.peer_exe}</dt>
        <dd>
          <bdi>{text(r.peer_exe)}</bdi> <Badge label={t.approvals.unverified} />
        </dd>
        <dt>{t.approvals.request.peer_origin_exe}</dt>
        <dd>
          <bdi>{text(r.peer_origin_exe)}</bdi> <Badge label={t.approvals.unverified} />
        </dd>
        <dt>{t.approvals.request.peer_chain}</dt>
        <dd>
          {r.peer_chain.length === 0 ? (
            t.approvals.request.none
          ) : (
            <ol className="peer-chain">
              {r.peer_chain.map((hop, i) => (
                <li key={i}>
                  <bdi>{hop}</bdi>
                </li>
              ))}
            </ol>
          )}{' '}
          <Badge label={t.approvals.unverified} />
        </dd>
      </dl>
    </section>
  );
}
