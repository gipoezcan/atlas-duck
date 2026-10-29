import { approvals as deApprovals } from './de/approvals';
import { common as deCommon } from './de/common';
import { errors as deErrors } from './de/errors';
import { approvals as enApprovals } from './en/approvals';
import { common as enCommon } from './en/common';
import { errors as enErrors } from './en/errors';
import type { Dict } from './index';

/** English is the source: its shape defines `Dict`. */
export const en = { common: enCommon, errors: enErrors, approvals: enApprovals } as const;

/** German must satisfy the widened English type; a missing key does not compile. */
export const de: Dict = { common: deCommon, errors: deErrors, approvals: deApprovals };
