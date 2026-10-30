import { useCallback, useEffect, useRef, useState, type MouseEvent } from 'react';
import { HelpButton } from '../shared/HelpLink';
import { useText } from '../shared/i18n/context';

import { on } from '../shared/ipc/events';
import { settingsGet } from '../shared/ipc/invoke';
import type { Dict } from '../shared/i18n';
import type { ConfigBanner, Confinement, SettingsGet, SettingsView } from '../shared/ipc/types';
import { AnchorDir } from './AnchorDir';
import { InstanceForm } from './InstanceForm';
import { Cli } from './Cli';
import { Instances } from './Instances';
import { Language } from './Language';
import { Limits } from './Limits';
import { OldInstalls, Recovery } from './Recovery';
import { Removal } from './Removal';
import { Retention } from './Retention';
import { DegradedToggle, ScriptLimitsForm } from './Scripts';
import { Cfg } from './text';
import { useWindowBusy, WindowBusyContext } from './useAction';

/**
 * The Settings window (spec 5.7). It reads `settings_get` on mount and on every `settings_changed`
 * (an event addressed to this window or to all), and never trusts an event payload as state.
 * Everything Rust refuses stays refused: the form only sends what the user typed.
 */
export function Settings() {
  const t = useText();
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
      <main className="window window-settings">
        <h1>{t.approvals.window_titles.settings}</h1>
        <HelpButton window="settings" />
        {failed ? (
          <p role="alert">
            {t.settings.load_failed}{' '}
            <button type="button" onClick={reload}>
              {t.settings.retry}
            </button>
          </p>
        ) : (
          <p role="status">{t.settings.loading}</p>
        )}
      </main>
    );
  }

  const {
    settings,
    instances,
    confinement,
    cli_installed: cliInstalled,
    cli_removable: cliRemovable,
    cli_dir_on_path: cliDirOnPath,
    ui_lang: uiLang,
  } = data;
  const banner = settings.config_read_only;
  const readOnly = banner !== null;
  return (
    <WindowBusyContext.Provider value={busy}>
    <main className="window window-settings">
      <h1>{t.approvals.window_titles.settings}</h1>
      <HelpButton window="settings" />
      {failed ? (
        <p role="alert">
          {t.settings.load_failed}{' '}
          <button type="button" onClick={reload}>
            {t.settings.retry}
          </button>
        </p>
      ) : null}
      {banner === null ? null : (
        <p role="alert" className="caution-strip">
          <strong>{t.settings.read_only_prefix}</strong> <Cfg value={configBannerText(t, banner)} />
        </p>
      )}
      {/* A read-only config disables the controls that write config.toml (each section wraps them
          in a Guard). Re-test, Add/Replace token and the prune button stay on: core refuses
          ConfigReadOnly only for config-writing operations. */}
      {/* M15 T3: app-side, not in config.toml, so a read-only config does not disable it. */}
      <div className="settings-layout">
        <PageToc />
        <div className="settings-sections">
          <Language uiLang={uiLang} onChanged={reload} />
          <div id="settings-instances" tabIndex={-1}>
            <Instances instances={instances} onChanged={reload} readOnly={readOnly} />
          </div>
          <InstanceForm onAdded={reload} readOnly={readOnly} />
          <Limits view={settings} onChanged={reload} readOnly={readOnly} />
          <ScriptLimitsForm view={settings} onChanged={reload} readOnly={readOnly} />
          <Retention view={settings} onChanged={reload} readOnly={readOnly} />
          <Recovery onChanged={reload} />
          <AnchorDir view={settings} onChanged={reload} />
          <OldInstalls />
          <ConfinementStatus confinement={confinement} view={settings} onChanged={reload} />
          <Cli
            installed={cliInstalled}
            removable={cliRemovable}
            dirOnPath={cliDirOnPath}
            onChanged={reload}
          />
          <Removal onChanged={reload} />
        </div>
      </div>
    </main>
    </WindowBusyContext.Provider>
  );
}

function ConfinementStatus({
  confinement,
  view,
  onChanged,
}: {
  confinement: Confinement;
  view: SettingsView;
  onChanged: () => void;
}) {
  const t = useText();
  const verdict =
    confinement.state === 'met'
      ? t.settings.confinement_met
      : confinement.state === 'not_met'
        ? confinement.scripts === 'degraded'
          ? t.settings.confinement_not_met_degraded
          : t.settings.confinement_not_met
        : t.settings.confinement_pending;
  return (
    <section id="settings-confinement" aria-label={t.settings.confinement}>
      <h2 tabIndex={-1}>{t.settings.confinement}</h2>
      <p>{verdict}</p>
      <p>{t.settings.scripts_states[confinement.scripts]}</p>
      {confinement.state === 'pending' ? null : (
        <p>
          {t.settings.confinement_mode}: <Cfg value={confinement.mode} />
        </p>
      )}
      {confinement.failed.length === 0 ? null : (
        <p>
          {t.settings.confinement_failed}:{' '}
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
          {t.settings.confinement_layers}:{' '}
          {confinement.extra_layers.map((l, i) => (
            <span key={`${l.name}-${i}`}>
              {i > 0 ? ', ' : ''}
              <Cfg value={l.name} /> ({l.on ? t.settings.layer_on : t.settings.layer_off})
            </span>
          ))}
        </p>
      )}
      <DegradedToggle view={view} confinement={confinement} onChanged={onChanged} />
    </section>
  );
}

/**
 * M15 T10: the spec 7.7 banner in the UI language from its facts; a banner without them (an older
 * core) shows core's text as it is.
 */
function configBannerText(t: Dict, banner: ConfigBanner): string {
  if (typeof banner.parsed !== 'boolean') return banner.text;
  return t.settings.config_banner(banner.kind, banner.version ?? null, banner.parsed);
}

/** The sections in page order: the id each section carries and the heading text its link shows. */
function sections(t: Dict): { id: string; label: string }[] {
  return [
    { id: 'settings-language', label: t.common.language },
    { id: 'settings-instances', label: t.settings.instances },
    { id: 'settings-add-instance', label: t.settings.add_heading },
    { id: 'settings-limits', label: t.settings.limits },
    { id: 'settings-script-limits', label: t.settings.script_limits },
    { id: 'settings-retention', label: t.settings.retention },
    { id: 'settings-recovery', label: t.settings.recovery.recovery },
    { id: 'settings-anchor-dir', label: t.settings.recovery.anchor_dir },
    { id: 'settings-old-installs', label: t.settings.recovery.orphans },
    { id: 'settings-confinement', label: t.settings.confinement },
    { id: 'settings-cli', label: t.settings.cli },
    { id: 'settings-removal', label: t.settings.removal },
  ];
}

/**
 * M17: "On this page". A link scrolls to its section and moves focus to the section's heading (a
 * hash link alone would leave the focus where it was); the last one used is marked current.
 */
function PageToc() {
  const t = useText();
  const [current, setCurrent] = useState<string | null>(null);
  const go = (e: MouseEvent<HTMLAnchorElement>, id: string) => {
    const target = document.getElementById(id);
    if (target === null) return;
    e.preventDefault();
    const heading = target.querySelector<HTMLElement>('h2') ?? target;
    heading.focus({ preventScroll: true });
    target.scrollIntoView?.({ block: 'start' });
    setCurrent(id);
  };
  return (
    <nav className="page-toc" aria-label={t.settings.toc_label}>
      <ul>
        {sections(t).map((s) => (
          <li key={s.id}>
            <a href={`#${s.id}`} aria-current={current === s.id ? 'true' : undefined} onClick={(e) => go(e, s.id)}>
              {s.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}
