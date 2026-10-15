import { useEffect, useState } from 'react';

import { queueGet } from '../shared/ipc/invoke';
import type { QueueDetail } from '../shared/ipc/types';
import { QUEUE_TEXT, REQUEST_TEXT, UNVERIFIED } from '../shared/strings';
import { AgentText } from '../shared/text/AgentText';
import { Badge } from '../shared/text/Badge';
import { formatAge } from './Queue';

interface RequestTabProps {
  requestId: string;
}

/** The params as JSON text: a text node in a `<pre>`, never markup. */
export function paramsText(params: unknown): string {
  return JSON.stringify(params, null, 2) ?? 'null';
}

/**
 * The Request tab (spec 5.6): what the agent asked and who is asking. Everything is a text node:
 * agent strings go through `AgentText`, the rest (params, hashes, process paths, timestamps) are
 * plain text that Rust already display-escaped.
 */
export function RequestTab({ requestId }: RequestTabProps) {
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

  if (failed) return <p role="alert">{REQUEST_TEXT.load_failed}</p>;
  if (detail === null) return <p role="status">{REQUEST_TEXT.loading}</p>;

  const { item, request: r } = detail;
  const text = (v: string | number | null) => (v === null || v === '' ? REQUEST_TEXT.none : String(v));
  return (
    <section className="request-tab" aria-label={REQUEST_TEXT.connection}>
      <dl>
        <dt>{REQUEST_TEXT.op}</dt>
        <dd>{item.op_id}</dd>
        <dt>{REQUEST_TEXT.instance}</dt>
        <dd>{item.instance_alias}</dd>
        <dt>{REQUEST_TEXT.reason}</dt>
        <dd>
          {r.reason === null || r.reason === '' ? (
            <Badge label={QUEUE_TEXT.no_reason} />
          ) : (
            <AgentText value={r.reason} unusual={item.unusual} />
          )}
        </dd>
        <dt>{REQUEST_TEXT.params}</dt>
        <dd>
          <pre className="params-text" tabIndex={0}>
            {paramsText(r.params)}
          </pre>
        </dd>
        <dt>{REQUEST_TEXT.params_sha256}</dt>
        <dd>{r.params_sha256}</dd>
        <dt>{REQUEST_TEXT.submitted_at}</dt>
        <dd>{r.submitted_at}</dd>
        <dt>{REQUEST_TEXT.age}</dt>
        <dd>{formatAge(item.age_s)}</dd>
        <dt>{REQUEST_TEXT.client_kind}</dt>
        <dd>{text(r.client_kind)}</dd>
        <dt>{REQUEST_TEXT.agent_name}</dt>
        <dd>
          {r.agent_name === null ? (
            REQUEST_TEXT.none
          ) : (
            <AgentText value={r.agent_name} unusual={item.unusual} />
          )}
        </dd>
        <dt>{REQUEST_TEXT.agent_name_source}</dt>
        <dd>{text(r.agent_name_source)}</dd>
        <dt>{REQUEST_TEXT.cwd_basename}</dt>
        <dd>
          <AgentText value={r.cwd_basename} unusual={item.unusual} />
        </dd>
        <dt>{REQUEST_TEXT.connection_id}</dt>
        <dd>{text(r.connection_id)}</dd>
        <dt>{REQUEST_TEXT.peer_pid}</dt>
        <dd>
          {text(r.peer_pid)} <Badge label={UNVERIFIED} />
        </dd>
        <dt>{REQUEST_TEXT.peer_exe}</dt>
        <dd>
          <bdi>{text(r.peer_exe)}</bdi> <Badge label={UNVERIFIED} />
        </dd>
        <dt>{REQUEST_TEXT.peer_origin_exe}</dt>
        <dd>
          <bdi>{text(r.peer_origin_exe)}</bdi> <Badge label={UNVERIFIED} />
        </dd>
        <dt>{REQUEST_TEXT.peer_chain}</dt>
        <dd>
          {r.peer_chain.length === 0 ? (
            REQUEST_TEXT.none
          ) : (
            <ol className="peer-chain">
              {r.peer_chain.map((hop, i) => (
                <li key={i}>
                  <bdi>{hop}</bdi>
                </li>
              ))}
            </ol>
          )}{' '}
          <Badge label={UNVERIFIED} />
        </dd>
      </dl>
    </section>
  );
}
