import { common as deCommon } from './de/common';
import { common as enCommon } from './en/common';
import type { Dict } from './index';

/** English is the source: its shape defines `Dict`. */
export const en = { common: enCommon } as const;

/** German must satisfy the widened English type; a missing key does not compile. */
export const de: Dict = { common: deCommon };
