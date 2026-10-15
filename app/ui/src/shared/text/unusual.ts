/** Characters a reader cannot see or that reorder text (bidi controls, zero-width, other format and control characters). */
export const UNUSUAL = /(?![\n\t])[\p{Cc}\p{Cf}\u2028\u2029]/u;

/** Whether `text` holds a character `UNUSUAL` flags: `AgentText`'s "unusual characters" mark. */
export const unusual = (text: string): boolean => UNUSUAL.test(text);
