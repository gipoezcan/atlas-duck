// The candidate JSON for the redaction tree (Task 17): decoded from the exact Raw bytes, checked
// whole once, then read lazily, one container's members at a time, as the tree expands them.
// Strings and keys are decoded only when shown; numbers keep their text as the bytes spell it.

/** spec 5.2 step 4: the release cap. A candidate is never larger; anything larger is refused. */
export const CANDIDATE_MAX_BYTES = 16 * 1024 * 1024;

export type JsonKind = 'object' | 'array' | 'string' | 'number' | 'literal';

/** One value of the text: `text.slice(start, end)` is its JSON. */
export interface Span {
  kind: JsonKind;
  start: number;
  end: number;
}

/** A member of a container: an object key (decoded) or an array index. */
export interface Member {
  key: string | number;
  span: Span;
}

/** A whole candidate: the checked text and its root value. */
export interface Candidate {
  text: string;
  root: Span;
}

const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const LITERAL = /true|false|null/y;

function skipWs(text: string, i: number): number {
  let j = i;
  for (;;) {
    const c = text.charCodeAt(j);
    if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) j++;
    else return j;
  }
}

/** The end of the string starting at `i` (a `"`), past its closing quote. */
function stringEnd(text: string, i: number): number {
  let j = i + 1;
  for (;;) {
    const c = text.charCodeAt(j);
    if (Number.isNaN(c)) throw new Error('unterminated string');
    if (c === 0x5c) j += 2;
    else if (c === 0x22) return j + 1;
    else j++;
  }
}

/** The value starting at `i` (no leading whitespace). */
function spanAt(text: string, i: number): Span {
  const c = text[i];
  if (c === '"') return { kind: 'string', start: i, end: stringEnd(text, i) };
  if (c === '{' || c === '[') {
    let depth = 0;
    let j = i;
    for (;;) {
      const d = text[j];
      if (d === undefined) throw new Error('unterminated container');
      if (d === '"') {
        j = stringEnd(text, j);
        continue;
      }
      if (d === '{' || d === '[') depth++;
      else if (d === '}' || d === ']') {
        depth--;
        if (depth === 0) return { kind: c === '{' ? 'object' : 'array', start: i, end: j + 1 };
      }
      j++;
    }
  }
  for (const [re, kind] of [
    [NUMBER, 'number'],
    [LITERAL, 'literal'],
  ] as const) {
    re.lastIndex = i;
    const m = re.exec(text);
    if (m !== null) return { kind, start: i, end: i + m[0].length };
  }
  throw new Error('not a JSON value');
}

/**
 * The exact candidate bytes as a checked JSON text, or null when they are not one (not UTF-8, not
 * JSON, over the release cap): the tree then is not offered, nothing is guessed.
 */
export function readCandidate(bytes: Uint8Array): Candidate | null {
  if (bytes.length > CANDIDATE_MAX_BYTES) return null;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    // The whole text is checked once; the lazy reads below then only walk valid JSON.
    JSON.parse(text);
  } catch {
    return null;
  }
  const start = skipWs(text, 0);
  try {
    return { text, root: spanAt(text, start) };
  } catch {
    return null;
  }
}

/** The members of an object or array span, in the order the bytes list them. */
export function members(text: string, span: Span): Member[] {
  if (span.kind !== 'object' && span.kind !== 'array') return [];
  const out: Member[] = [];
  const close = span.kind === 'object' ? '}' : ']';
  let i = skipWs(text, span.start + 1);
  if (text[i] === close) return out;
  for (let index = 0; ; index++) {
    let key: string | number = index;
    if (span.kind === 'object') {
      const k = spanAt(text, i);
      key = stringOf(text, k);
      i = skipWs(text, k.end);
      if (text[i] !== ':') throw new Error('expected a colon');
      i = skipWs(text, i + 1);
    }
    const v = spanAt(text, i);
    out.push({ key, span: v });
    i = skipWs(text, v.end);
    if (text[i] === ',') i = skipWs(text, i + 1);
    else if (text[i] === close) return out;
    else throw new Error('expected a comma');
  }
}

/** A string span's decoded value. */
export function stringOf(text: string, span: Span): string {
  const v: unknown = JSON.parse(text.slice(span.start, span.end));
  if (typeof v !== 'string') throw new Error('not a string');
  return v;
}

/** A number's or literal's text as the bytes spell it (`1.0` stays `1.0`). */
export function scalarText(text: string, span: Span): string {
  return text.slice(span.start, span.end);
}

/** Base64 to bytes (the Raw pages' `bytes_b64`). */
export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
