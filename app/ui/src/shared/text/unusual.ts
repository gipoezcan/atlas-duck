/** Characters a reader cannot see or that reorder text (bidi controls, zero-width, other format and control characters). */
export const UNUSUAL = /(?![\n\t])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** Whether `text` holds a character `UNUSUAL` flags: `AgentText`'s "unusual characters" mark. */
export const unusual = (text: string): boolean => UNUSUAL.test(text);

/** `UNUSUAL` and the rest of spec 6.4's invisible set (Default_Ignorable_Code_Point). */
const INVISIBLE = /(?![\n\t])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;

/**
 * `text` with every invisible character written as `⟨U+XXXX⟩`, as Rust's display marks them
 * (preview `invisible.rs`), so a reader sees what a text to mask has to hold.
 */
export const escapeInvisible = (text: string): string =>
  text.replace(INVISIBLE, (c) => `⟨U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}⟩`);
