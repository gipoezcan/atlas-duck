import { approvals as deApprovals } from './de/approvals';
import { audit as deAudit } from './de/audit';
import { common as deCommon } from './de/common';
import { errors as deErrors } from './de/errors';
import { onboarding as deOnboarding } from './de/onboarding';
import { running as deRunning } from './de/running';
import { settings as deSettings } from './de/settings';
import { setup as deSetup } from './de/setup';
import { approvals as enApprovals } from './en/approvals';
import { audit as enAudit } from './en/audit';
import { common as enCommon } from './en/common';
import { errors as enErrors } from './en/errors';
import { onboarding as enOnboarding } from './en/onboarding';
import { running as enRunning } from './en/running';
import { settings as enSettings } from './en/settings';
import { setup as enSetup } from './en/setup';
import type { Dict } from './index';

/** English is the source: its shape defines `Dict`. */
export const en = {
  common: enCommon,
  errors: enErrors,
  approvals: enApprovals,
  settings: enSettings,
  setup: enSetup,
  onboarding: enOnboarding,
  audit: enAudit,
  running: enRunning,
} as const;

/** German must satisfy the widened English type; a missing key does not compile. */
export const de: Dict = {
  common: deCommon,
  errors: deErrors,
  approvals: deApprovals,
  settings: deSettings,
  setup: deSetup,
  onboarding: deOnboarding,
  audit: deAudit,
  running: deRunning,
};
