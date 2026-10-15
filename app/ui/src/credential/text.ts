// Untrusted-text helper for the credential page (spec 10.3). Alias, product, URL, user, version
// and any unknown failure class come from the agent or the server: they are shown as text only,
// and anything a reader could mistake for something else is shown as a visible escape.
// Local on purpose: src/credential/ imports nothing from src/shared/ (PD-71).

// Control, format (zero width, bidi), line and paragraph separators, private use, unassigned.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}]/u;
const MAX_SHOWN = 256;

export interface Described {
  shown: string;
  unusual: boolean;
}

function escape(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  return `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
}

/**
 * `text` made safe to show. Invisible characters are always escaped. With `ascii` every
 * non-ASCII character is escaped too (hosts, aliases and users where a look-alike letter would
 * be a spoof). `unusual` is true when anything was escaped or the text was cut.
 */
export function describe(text: string, ascii: boolean): Described {
  let unusual = false;
  let out = '';
  let count = 0;
  for (const ch of text) {
    if (count === MAX_SHOWN) {
      out += '...';
      unusual = true;
      break;
    }
    count += 1;
    const cp = ch.codePointAt(0) ?? 0;
    if (INVISIBLE.test(ch) || (ascii && cp > 0x7e)) {
      out += escape(ch);
      unusual = true;
    } else {
      out += ch;
    }
  }
  return { shown: out, unusual };
}
