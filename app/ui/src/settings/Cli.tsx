import { useState } from 'react';
import { HelpLink } from '../shared/HelpLink';
import { useText } from '../shared/i18n/context';

import { cliInstall, cliUninstall } from '../shared/ipc/invoke';
import type { CliInstallAnswer } from '../shared/ipc/types';
import { useAction } from './useAction';

/**
 * "Install CLI to PATH" and its removal (spec 12.3). The button follows what Rust reports
 * (`cli_installed`); Rust decides where the CLI goes and the call carries nothing, so there is no
 * field to fill. The commands write no `config.toml`, so a read-only config does not turn them off.
 * The answer is a fixed word mapped to fixed text; a refusal is fixed text by error kind. Where
 * nothing can be removed (`cli_removable` is false: deb/rpm, the package owns the CLI) there is no
 * button, and the status is the "comes with the package" sentence.
 */
export function Cli({
  installed,
  removable,
  dirOnPath,
  onChanged,
}: {
  installed: boolean;
  removable: boolean;
  /** `cli_dir_on_path`: whether the CLI's folder is on the PATH; `null` when not known. */
  dirOnPath: boolean | null;
  onChanged: () => void;
}) {
  const t = useText();
  const action = useAction();
  const [outcome, setOutcome] = useState<CliInstallAnswer['outcome'] | null>(null);
  const click = () =>
    void action.run(() => (installed ? cliUninstall() : cliInstall())).then((answer) => {
      if (answer === undefined) {
        setOutcome(null);
        return;
      }
      setOutcome(answer.outcome);
      onChanged();
    });
  const packaged = installed && !removable;
  // The status line is path-aware: an installed CLI whose folder this app's PATH lacks is not
  // called "on your PATH", and a folder already on the PATH is not called "not on your PATH".
  const status = packaged
    ? t.settings.cli_outcomes.already_on_path
    : installed
      ? dirOnPath === false
        ? t.settings.cli_installed_dir_not_on_path
        : t.settings.cli_installed
      : dirOnPath === true
        ? t.settings.cli_not_installed_dir_on_path
        : t.settings.cli_not_installed;
  return (
    <section aria-label={t.settings.cli}>
      <h2>{t.settings.cli}</h2>
      <HelpLink section="settings/cli" />
      <p>{status}</p>
      {packaged ? null : (
        <button type="button" disabled={action.pending} onClick={click}>
          {installed ? t.settings.cli_uninstall : t.settings.cli_install}
        </button>
      )}
      {action.error === null ? null : <p role="alert">{action.error}</p>}
      {outcome === null ? null : <p role="status">{t.settings.cli_outcomes[outcome]}</p>}
    </section>
  );
}
