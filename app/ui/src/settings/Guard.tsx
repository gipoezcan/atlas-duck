import type { ReactNode } from 'react';

/**
 * Disables the controls inside while config.toml is read-only (spec 7.7). Only the controls that
 * write config.toml go inside; token and re-test controls stay outside, because core refuses
 * `ConfigReadOnly` only for config-writing operations.
 */
export function Guard({ disabled, children }: { disabled: boolean; children: ReactNode }) {
  return (
    <fieldset disabled={disabled} className="settings-guard">
      {children}
    </fieldset>
  );
}
