import { useCallback, useEffect, useRef, useState } from 'react';

import { on } from '../shared/ipc/events';
import { settingsGet } from '../shared/ipc/invoke';
import type { Confinement, SettingsGet } from '../shared/ipc/types';
import { SETTINGS_TEXT as T, WINDOW_TITLES } from '../shared/strings';
import { InstanceForm } from './InstanceForm';
import { Instances } from './Instances';
import { Limits } from './Limits';
import { Retention } from './Retention';
import { Cfg } from './text';
import { useWindowBusy, WindowBusyContext } from './useAction';

/**
 * The Settings window (spec 5.7). It reads `settings_get` on mount and on every `settings_changed`
 * (an event addressed to this window or to all), and never trusts an event payload as state.
 * Everything Rust refuses stays refused: the form only sends what the user typed.
 */
export function Settings() {
  const [data, setData] = useState<SettingsGet | null>(null);
  const [failed, setFailed] = useState(false);
  const [nonce, setNonce] = useState(0);
  const latest = useRef(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const busy = useWindowBusy();

  useEffect(() => {
    let live = true;
    const refresh = () => {
      const mine = ++latest.current;
      settingsGet().then(
        (v) => {
          if (live && mine === latest.current) {
            setData(v);
            setFailed(false);
          }
        },
        () => {
          if (live && mine === latest.current) setFailed(true);
        },
      );
    };
    const unlisten = on('settings_changed', refresh, { thisWindow: true });
    // Read once the listener is attached, so an event between a read and a listener is not lost.
    void Promise.allSettled([unlisten]).then(() => {
      if (live) refresh();
    });
    return () => {
      live = false;
      void unlisten.then((off) => off()).catch(() => undefined);
    };
  }, [nonce]);

  if (data === null) {
    return (
      <main>
        <h1>{WINDOW_TITLES.settings}</h1>
        {failed ? (
          <p role="alert">
            {T.load_failed}{' '}
            <button type="button" onClick={reload}>
              {T.retry}
            </button>
          </p>
        ) : (
          <p role="status">{T.loading}</p>
        )}
      </main>
    );
  }

  const { settings, instances, confinement, cli_installed: cliInstalled } = data;
  const banner = settings.config_read_only;
  const readOnly = banner !== null;
  return (
    <WindowBusyContext.Provider value={busy}>
    <main>
      <h1>{WINDOW_TITLES.settings}</h1>
      {failed ? (
        <p role="alert">
          {T.load_failed}{' '}
          <button type="button" onClick={reload}>
            {T.retry}
          </button>
        </p>
      ) : null}
      {banner === null ? null : (
        <p role="alert" className="caution-strip">
          <strong>{T.read_only_prefix}</strong> <Cfg value={banner.text} />
        </p>
      )}
      {/* A read-only config disables the controls that write config.toml (each section wraps them
          in a Guard). Re-test, Add/Replace token and the prune button stay on: core refuses
          ConfigReadOnly only for config-writing operations. */}
      <Instances instances={instances} onChanged={reload} readOnly={readOnly} />
      <InstanceForm onAdded={reload} readOnly={readOnly} />
      <Limits view={settings} onChanged={reload} readOnly={readOnly} />
      <Retention view={settings} onChanged={reload} readOnly={readOnly} />
      <ConfinementStatus confinement={confinement} />
      <CliSection installed={cliInstalled} />
      <RemovalSection />
    </main>
    </WindowBusyContext.Provider>
  );
}

function ConfinementStatus({ confinement }: { confinement: Confinement }) {
  const verdict =
    confinement.state === 'met'
      ? T.confinement_met
      : confinement.state === 'not_met'
        ? T.confinement_not_met
        : T.confinement_pending;
  return (
    <section aria-label={T.confinement}>
      <h2>{T.confinement}</h2>
      <p>{verdict}</p>
      {confinement.state === 'pending' ? null : (
        <p>
          {T.confinement_mode}: <Cfg value={confinement.mode} />
        </p>
      )}
      {confinement.failed.length === 0 ? null : (
        <p>
          {T.confinement_failed}:{' '}
          {confinement.failed.map((f, i) => (
            <span key={`${f}-${i}`}>
              {i > 0 ? ', ' : ''}
              <Cfg value={f} />
            </span>
          ))}
        </p>
      )}
      {confinement.extra_layers.length === 0 ? null : (
        <p>
          {T.confinement_layers}:{' '}
          {confinement.extra_layers.map((l, i) => (
            <span key={`${l.name}-${i}`}>
              {i > 0 ? ', ' : ''}
              <Cfg value={l.name} /> ({l.on ? T.layer_on : T.layer_off})
            </span>
          ))}
        </p>
      )}
    </section>
  );
}

/** The CLI install and removal buttons stay off until their commands exist (Task 27). */
function CliSection({ installed }: { installed: boolean }) {
  return (
    <section aria-label={T.cli}>
      <h2>{T.cli}</h2>
      <p>{installed ? T.cli_installed : T.cli_not_installed}</p>
      <button type="button" disabled>
        {installed ? T.cli_uninstall : T.cli_install}
      </button>
      <p>{T.cli_pending}</p>
    </section>
  );
}

/** "Prepare for removal" is wired by Task 28; until then the entry is shown off, with its reason. */
function RemovalSection() {
  return (
    <section aria-label={T.removal}>
      <h2>{T.removal}</h2>
      <button type="button" disabled>
        {T.removal_button}
      </button>
      <p>{T.removal_pending}</p>
    </section>
  );
}
