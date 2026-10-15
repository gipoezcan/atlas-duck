import { useState } from 'react';

import { cliInstall, cliUninstall } from '../shared/ipc/invoke';
import type { CliInstallAnswer } from '../shared/ipc/types';
import { SETTINGS_TEXT as T } from '../shared/strings';
import { useAction } from './useAction';

/**
 * "Install CLI to PATH" and its removal (spec 12.3). The button follows what Rust reports
 * (`cli_installed`); Rust decides where the CLI goes and the call carries nothing, so there is no
 * field to fill. The commands write no `config.toml`, so a read-only config does not turn them off.
 * The answer is a fixed word mapped to fixed text; a refusal is fixed text by error kind.
 */
export function Cli({ installed, onChanged }: { installed: boolean; onChanged: () => void }) {
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
  return (
    <section aria-label={T.cli}>
      <h2>{T.cli}</h2>
      <p>{installed ? T.cli_installed : T.cli_not_installed}</p>
      <button type="button" disabled={action.pending} onClick={click}>
        {installed ? T.cli_uninstall : T.cli_install}
      </button>
      {action.error === null ? null : <p role="alert">{action.error}</p>}
      {outcome === null ? null : <p role="status">{T.cli_outcomes[outcome]}</p>}
    </section>
  );
}
