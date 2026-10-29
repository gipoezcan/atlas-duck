import { instanceAcceptUrlChange, instanceConfirmConfig } from '../shared/ipc/invoke';
import type { InstanceView } from '../shared/ipc/types';
import { AgentText } from '../shared/text/AgentText';
import { unusual } from '../shared/text/unusual';
import { Cfg, own } from '../settings/text';
import { useAction } from '../settings/useAction';
import { useText } from '../shared/i18n/context';

/**
 * The instances of the wizard's instances step. The list comes from `wizard_state` (setup has no
 * `settings_get`), so this is a compact view: only what setup may do is offered, which is confirming
 * an instance's origin and accepting a pending URL change. Tokens, re-test and proxy are Settings.
 */
export function SetupInstances({
  instances,
  onChanged,
}: {
  instances: readonly InstanceView[];
  onChanged: () => void;
}) {
  const t = useText();
  if (instances.length === 0) return <p>{t.setup.instances_none}</p>;
  return (
    <table className="instances">
      <caption>{t.setup.instances_list}</caption>
      <thead>
        <tr>
          <th scope="col">{t.setup.col_alias}</th>
          <th scope="col">{t.setup.col_origin}</th>
          <th scope="col">{t.setup.col_state}</th>
        </tr>
      </thead>
      <tbody>
        {instances.map((inst) => (
          <Row key={inst.alias} inst={inst} onChanged={onChanged} />
        ))}
      </tbody>
    </table>
  );
}

function Row({ inst, onChanged }: { inst: InstanceView; onChanged: () => void }) {
  const t = useText();
  const confirm = useAction();
  const accept = useAction();
  const known = own(t.settings.states, inst.state);
  return (
    <tr>
      <th scope="row">
        <Cfg value={inst.alias} />
      </th>
      <td>{inst.origin === null ? t.setup.no_origin : <Cfg value={inst.origin} />}</td>
      <td>
        {known === undefined ? <Cfg value={inst.state} /> : known}
        {inst.note === null ? null : (
          <p>
            <AgentText value={inst.note} unusual={unusual(inst.note)} />
          </p>
        )}
        {inst.state === 'needs_token' ? <p>{t.setup.token_in_settings}</p> : null}
        {inst.state === 'instance_unconfirmed' ? (
          <>
            <p>{t.setup.confirm_hint}</p>
            <button
              type="button"
              disabled={confirm.pending}
              onClick={() =>
                void confirm.run(() => instanceConfirmConfig(inst.alias)).then((v) => {
                  if (v !== undefined) onChanged();
                })
              }
            >
              {t.setup.confirm}
            </button>
            {confirm.error === null ? null : <p role="alert">{confirm.error}</p>}
          </>
        ) : null}
        {inst.pending_url_change === null ? null : (
          <div role="note">
            <p>
              {t.setup.url_change} <Cfg value={inst.alias} />
            </p>
            <p>
              {t.setup.url_change_requested} <Cfg value={inst.pending_url_change} />
            </p>
            <button
              type="button"
              disabled={accept.pending}
              onClick={() =>
                void accept.run(() => instanceAcceptUrlChange(inst.alias)).then((v) => {
                  if (v !== undefined) onChanged();
                })
              }
            >
              {t.setup.url_change_accept}
            </button>
            {accept.error === null ? null : <p role="alert">{accept.error}</p>}
          </div>
        )}
      </td>
    </tr>
  );
}
