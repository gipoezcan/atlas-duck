#!/usr/bin/env node
// CSS gate for the M11 visual design (plan 2026-10-26-atlas-duck-m11-ui-visual-design).
// Static checks over every *.css under the given src directory: tokens defined
// for both colour schemes, WCAG contrast of the token pairs, no colour literal
// outside the token blocks, visible focus, reduced motion, the queue/audit row
// height contract, no remote loads, and no new `style=` props in the TSX.
//
// Usage: node scripts/check-css.mjs <srcDir>
// Exit:  0 = clean, 1 = violations (one per stdout line), 2 = usage error.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TOKENS_FILE = 'shared/styles/tokens.css';
const BASE_FILE = 'shared/styles/base.css';
const CREDENTIAL_FILE = 'credential/credential.css';

export const REQUIRED_COLOR_TOKENS = [
  'bg', 'surface', 'surface-raised', 'surface-sunken',
  'text', 'text-muted', 'text-on-accent',
  'border', 'border-strong',
  'accent', 'accent-hover', 'accent-subtle',
  'danger', 'danger-hover', 'danger-subtle', 'text-on-danger',
  'warning', 'warning-subtle', 'warning-border',
  'success', 'success-subtle',
  'info', 'info-subtle',
  'focus', 'row-selected', 'row-hover', 'shadow-card',
];

// [foreground, [backgrounds], minimum ratio]; a pair is checked when both tokens exist in the source.
export const CONTRAST_PAIRS = [
  ['text', ['bg', 'surface', 'surface-raised', 'surface-sunken', 'row-selected', 'row-hover'], 4.5],
  ['text-muted', ['bg', 'surface', 'surface-raised'], 4.5],
  ['accent', ['bg', 'surface', 'surface-raised'], 4.5],
  ['text-on-accent', ['accent', 'accent-hover'], 4.5],
  ['text-on-danger', ['danger', 'danger-hover'], 4.5],
  ['danger', ['bg', 'surface', 'danger-subtle'], 4.5],
  ['warning', ['bg', 'warning-subtle'], 4.5],
  ['success', ['bg', 'success-subtle'], 4.5],
  ['info', ['info-subtle'], 4.5],
  ['text', ['warning-subtle', 'danger-subtle', 'success-subtle', 'info-subtle'], 4.5],
  ['border-strong', ['bg', 'surface', 'surface-raised'], 3],
  ['focus', ['bg', 'surface', 'surface-raised', 'accent-subtle'], 3],
  ['warning-border', ['bg', 'warning-subtle'], 3],
];

const NAMED_COLORS = `aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet
brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan
darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred
darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue
dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod gray
green greenyellow grey honeydew hotpink indianred indigo ivory khaki lavender lavenderblush lawngreen
lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey lightpink
lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime limegreen
linen magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue
mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy
oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip
peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown
seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen steelblue tan teal
thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen`.split(/\s+/);

const NAMED_COLOR_RE = new RegExp(`(?<![\\w-])(?:${NAMED_COLORS.join('|')})(?![\\w-])`, 'i');
const COLOR_FUNCTION_RE = /\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color-mix|color|light-dark)\s*\(/i;
const HEX_COLOR_RE = /#[0-9a-f]{3,8}\b/i;

// ---------------------------------------------------------------------------
// Minimal CSS parser: rules with their @media context, declarations, @-statements.

export function stripComments(css) {
  return css.replace(/\/\*[\s\S]*?\*\//g, '');
}

// Index of the closing character for the opener at `start`, skipping strings; -1 if unbalanced.
function matchClose(text, start, open, close) {
  let depth = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'") {
      i = skipString(text, i);
    } else if (c === open) {
      depth++;
    } else if (c === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function skipString(text, i) {
  const quote = text[i];
  for (i++; i < text.length && text[i] !== quote; i++) {
    if (text[i] === '\\') i++;
  }
  return i;
}

// Splits at `sep` outside parentheses, brackets and strings.
function splitTop(text, sep) {
  const parts = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'") i = skipString(text, i);
    else if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (c === sep && depth === 0) {
      parts.push(text.slice(from, i));
      from = i + 1;
    }
  }
  parts.push(text.slice(from));
  return parts;
}

function parseDeclarations(body) {
  const decls = [];
  for (const part of splitTop(body, ';')) {
    const colon = part.indexOf(':');
    if (colon < 0) continue;
    const prop = part.slice(0, colon).trim().toLowerCase();
    if (!prop) continue;
    const value = part.slice(colon + 1).trim().replace(/\s*!important$/i, '');
    decls.push({ prop, value });
  }
  return decls;
}

// -> { rules: [{ selector, decls, media }], statements: [{ name, text }], atBlocks: [{ name, prelude }] }
export function parseCss(source) {
  const css = stripComments(source);
  const out = { rules: [], statements: [], atBlocks: [] };
  const walk = (text, media) => {
    let i = 0;
    while (i < text.length) {
      while (i < text.length && /\s/.test(text[i])) i++;
      if (i >= text.length) break;
      let j = i;
      let depth = 0;
      while (j < text.length) {
        const c = text[j];
        if (c === '"' || c === "'") j = skipString(text, j);
        else if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (depth === 0 && (c === '{' || c === ';')) break;
        j++;
      }
      const head = text.slice(i, j).trim();
      if (j >= text.length || text[j] === ';') {
        if (head.startsWith('@')) out.statements.push({ name: /^@([\w-]+)/.exec(head)?.[1] ?? '', text: head });
        i = j + 1;
        continue;
      }
      const end = matchClose(text, j, '{', '}');
      const inner = text.slice(j + 1, end < 0 ? text.length : end);
      if (head.startsWith('@')) {
        const name = /^@([\w-]+)/.exec(head)?.[1] ?? '';
        const prelude = head.slice(name.length + 1).trim();
        out.atBlocks.push({ name, prelude });
        if (name === 'media' || name === 'supports' || name === 'layer') {
          walk(inner, name === 'media' ? [media, prelude].filter(Boolean).join(' and ') : media);
        }
      } else {
        out.rules.push({ selector: head, decls: parseDeclarations(inner), media: media || null });
      }
      i = end < 0 ? text.length : end + 1;
    }
  };
  walk(css, '');
  return out;
}

const selectorsOf = (rule) => splitTop(rule.selector, ',').map((s) => s.trim().replace(/\s+/g, ' '));
const isDarkMedia = (media) => !!media && /prefers-color-scheme\s*:\s*dark/i.test(media);
const isReduceMedia = (media) => !!media && /prefers-reduced-motion\s*:\s*reduce/i.test(media);
const isRootRule = (rule) => rule.selector.trim() === ':root';

// -> { light: Map<name, value>, dark: Map<name, value> } of the `--name` declarations of the `:root` rules.
export function parseTokens(css) {
  const light = new Map();
  const dark = new Map();
  for (const rule of parseCss(css).rules) {
    if (!isRootRule(rule)) continue;
    const target = isDarkMedia(rule.media) ? dark : rule.media ? null : light;
    if (!target) continue;
    for (const { prop, value } of rule.decls) {
      if (prop.startsWith('--')) target.set(prop.slice(2), value);
    }
  }
  return { light, dark };
}

// ---------------------------------------------------------------------------
// WCAG contrast

function parseHex(hex) {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) throw new Error(`not an opaque hex colour: ${hex}`);
  let h = m[1];
  if (h.length === 3) h = [...h].map((c) => c + c).join('');
  return [0, 2, 4].map((k) => parseInt(h.slice(k, k + 2), 16) / 255);
}

function luminance(hex) {
  const [r, g, b] = parseHex(hex).map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(hexA, hexB) {
  const [hi, lo] = [luminance(hexA), luminance(hexB)].sort((a, b) => b - a);
  return (hi + 0.05) / (lo + 0.05);
}

// ---------------------------------------------------------------------------
// Checks

const isColorValue = (v) => HEX_COLOR_RE.test(v) || COLOR_FUNCTION_RE.test(v);

function checkTokenSource(rel, css, { required }) {
  const violations = [];
  const { light, dark } = parseTokens(css);
  const colors = (map) => new Set([...map].filter(([, v]) => isColorValue(v)).map(([k]) => k));
  const lightColors = colors(light);
  const darkColors = colors(dark);
  if (required) {
    for (const name of REQUIRED_COLOR_TOKENS) {
      if (!lightColors.has(name)) violations.push(`${rel}: token --${name} missing in the light scheme`);
      if (!darkColors.has(name)) violations.push(`${rel}: token --${name} missing in the dark scheme`);
    }
  } else {
    for (const name of lightColors) {
      if (!darkColors.has(name)) violations.push(`${rel}: token --${name} missing in the dark scheme`);
    }
    for (const name of darkColors) {
      if (!lightColors.has(name)) violations.push(`${rel}: token --${name} missing in the light scheme`);
    }
  }
  if (lightColors.size === 0) violations.push(`${rel}: no light-scheme colour tokens in :root`);
  const rootRule = parseCss(css).rules.find((r) => isRootRule(r) && !r.media);
  const scheme = rootRule?.decls.find((d) => d.prop === 'color-scheme')?.value ?? '';
  if (!/light\s+dark/.test(scheme)) violations.push(`${rel}: :root must set color-scheme: light dark`);
  for (const [scheme, own] of [['light', light], ['dark', new Map([...light, ...dark])]]) {
    for (const [fg, bgs, min] of CONTRAST_PAIRS) {
      if (!own.has(fg)) continue;
      for (const bg of bgs) {
        if (!own.has(bg)) continue;
        let ratio;
        try {
          ratio = contrast(own.get(fg), own.get(bg));
        } catch (error) {
          violations.push(`${rel}: contrast --${fg} on --${bg} (${scheme}): ${error.message}`);
          continue;
        }
        if (ratio < min) {
          violations.push(`${rel}: contrast --${fg} on --${bg} (${scheme}) is ${ratio.toFixed(2)}, needs ${min}`);
        }
      }
    }
  }
  return violations;
}

function stripStrings(value) {
  return value.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
}

function checkColorLiterals(rel, parsed, isTokenFile) {
  const violations = [];
  for (const rule of parsed.rules) {
    const inTokenBlock = isTokenFile && isRootRule(rule);
    for (const { prop, value } of rule.decls) {
      if (inTokenBlock && prop.startsWith('--')) continue;
      const bare = stripStrings(value).replace(/var\(\s*--[\w-]+/gi, 'var(');
      const hit = HEX_COLOR_RE.exec(bare) ?? COLOR_FUNCTION_RE.exec(bare) ?? NAMED_COLOR_RE.exec(bare);
      if (hit) violations.push(`${rel}: colour literal "${hit[0]}" outside a token block: ${rule.selector} { ${prop}: ${value} }`);
    }
  }
  return violations;
}

const OUTLINE_OFF_RE = /^(?:none|0)(?:\s+(?:none|0))?$/i;

function checkFocus(rel, parsed) {
  const violations = [];
  const usesFocus = (rule) => rule.decls.some((d) => (d.prop === 'outline' || d.prop === 'box-shadow') && /var\(\s*--focus\b/.test(d.value));
  for (const rule of parsed.rules) {
    const off = rule.decls.find((d) => (d.prop === 'outline' || d.prop === 'outline-style') && OUTLINE_OFF_RE.test(d.value));
    if (!off) continue;
    if (usesFocus(rule) || rule.decls.some((d) => d.prop === 'outline' && !OUTLINE_OFF_RE.test(d.value))) continue;
    if (/:not\(\s*:focus-visible\s*\)/.test(rule.selector)) continue;
    // Programmatic focus targets (headings, sections, main and wrapper divs with tabindex="-1") are not interactive: no ring.
    if (selectorsOf(rule).every((s) => /^:is\(\s*(?:(?:h[1-6]|section|main|div)\s*,?\s*)+\)\[tabindex="-1"\]:focus$/.test(s))) continue;
    const ring = parsed.rules.some((other) => {
      if (!usesFocus(other)) return false;
      const bases = selectorsOf(rule).map((s) => s.replace(/:focus(?:-visible)?/g, ''));
      return selectorsOf(other).some((s) => /:focus-visible/.test(s) && bases.includes(s.replace(/:focus-visible/g, '')));
    });
    if (!ring) violations.push(`${rel}: "${rule.selector}" removes the outline without a :focus-visible replacement using --focus`);
  }
  return violations;
}

function hasReduceBlock(parsed) {
  const decls = parsed.rules.filter((r) => isReduceMedia(r.media)).flatMap((r) => r.decls.map((d) => d.prop));
  return decls.includes('transition-duration') && decls.includes('animation-duration');
}

const ROW_RULES = [
  ['.queue-line', 'height', '2rem'],
  ['.queue-flags', 'height', '3.5rem'],
  ['.audit-line', 'height', '2rem'],
];
const ROW_SELECTORS = ['.queue-line', '.queue-flags', '.audit-line', '.audit-row', '.windowed-row'];

function checkRowContract(allRules) {
  const violations = [];
  for (const [selector, prop, expected] of ROW_RULES) {
    const values = [];
    for (const { rel, rule } of allRules) {
      if (!selectorsOf(rule).includes(selector)) continue;
      for (const d of rule.decls) if (d.prop === prop) values.push({ rel, value: d.value });
    }
    if (!values.some((v) => v.value === expected)) violations.push(`row contract: ${selector} must set ${prop}: ${expected}`);
    for (const v of values) {
      if (v.value !== expected) violations.push(`${v.rel}: row contract: ${selector} ${prop} is ${v.value}, must be ${expected}`);
    }
  }
  for (const { rel, rule } of allRules) {
    for (const selector of selectorsOf(rule).filter((s) => ROW_SELECTORS.includes(s))) {
      for (const { prop, value } of rule.decls) {
        const spacing = /^(?:padding|margin)(?:-|$)/.test(prop) || /^border(?:-top)?(?:-|$)/.test(prop);
        const allowed = selector === '.windowed-row' && prop === 'border-bottom' && /^1px solid var\(--[\w-]+\)$/.test(value);
        if (spacing && !allowed) violations.push(`${rel}: row contract: ${selector} must not set ${prop} (fixed row heights)`);
      }
    }
    for (const selector of selectorsOf(rule)) {
      if ((selector === 'html' || selector === ':root') && rule.decls.some((d) => d.prop === 'font-size')) {
        violations.push(`${rel}: row contract: font-size must not be set on ${selector} (rem row heights)`);
      }
    }
  }
  return violations;
}

function checkRemote(rel, parsed) {
  const violations = [];
  const remote = (target) => /^(?:[a-z][a-z0-9+.-]*:|\/)/i.test(target.trim().replace(/^['"]|['"]$/g, ''));
  for (const s of parsed.statements) {
    if (s.name !== 'import') continue;
    const target = /^@import\s+(?:url\(\s*)?(['"]?)([^'")\s]+)\1/i.exec(s.text)?.[2] ?? '';
    if (remote(target)) violations.push(`${rel}: @import of a non-relative target: ${s.text}`);
  }
  for (const b of parsed.atBlocks) if (b.name === 'font-face') violations.push(`${rel}: @font-face is not allowed (system font stack only)`);
  for (const rule of parsed.rules) {
    for (const { value } of rule.decls) {
      for (const m of value.matchAll(/url\(\s*([^)]*)\)/gi)) {
        if (remote(m[1])) violations.push(`${rel}: url() to a non-relative target: ${m[0]}`);
      }
    }
  }
  return violations;
}

function walkFiles(dir, accept) {
  const found = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...walkFiles(full, accept));
    else if (accept(full)) found.push(full);
  }
  return found;
}

const STYLE_PROP_ALLOW = new Map([
  ['shared/list/Windowed.tsx', 3],
  ['approvals/redaction/Tree.tsx', 1],
]);

function checkStyleProps(srcDir) {
  const violations = [];
  const files = walkFiles(srcDir, (f) => f.endsWith('.tsx') && !f.endsWith('.test.tsx'));
  for (const file of files) {
    const rel = path.relative(srcDir, file).split(path.sep).join('/');
    const count = (readFileSync(file, 'utf8').match(/\bstyle\s*=/g) ?? []).length;
    const allowed = STYLE_PROP_ALLOW.get(rel) ?? 0;
    if (count !== allowed) violations.push(`${rel}: ${count} style= prop(s), allowed ${allowed} (CSP: no new inline styles)`);
  }
  for (const rel of STYLE_PROP_ALLOW.keys()) {
    if (!existsSync(path.join(srcDir, rel))) violations.push(`${rel}: expected file is missing (style= allow-list)`);
  }
  return violations;
}

function checkRowRem(srcDir) {
  const violations = [];
  for (const [rel, name, value] of [['approvals/Queue.tsx', 'QUEUE_ROW_REM', '7.5'], ['audit/EventList.tsx', 'ROW_REM', '4.25']]) {
    const file = path.join(srcDir, rel);
    if (!existsSync(file)) {
      violations.push(`${rel}: missing (row height contract)`);
      continue;
    }
    const m = new RegExp(`\\b${name}\\s*=\\s*([0-9.]+)`).exec(readFileSync(file, 'utf8'));
    if (!m || m[1] !== value) violations.push(`${rel}: ${name} must be ${value}, found ${m ? m[1] : 'nothing'}`);
  }
  return violations;
}

export function checkAll(srcDir) {
  const violations = [];
  const files = walkFiles(srcDir, (f) => f.endsWith('.css')).sort();
  const parsedFiles = files.map((file) => {
    const rel = path.relative(srcDir, file).split(path.sep).join('/');
    const text = readFileSync(file, 'utf8');
    return { rel, text, parsed: parseCss(text) };
  });
  const tokens = parsedFiles.find((f) => f.rel === TOKENS_FILE);
  const credential = parsedFiles.find((f) => f.rel === CREDENTIAL_FILE);
  if (tokens) violations.push(...checkTokenSource(tokens.rel, tokens.text, { required: true }));
  else violations.push(`${TOKENS_FILE}: missing`);
  if (credential) violations.push(...checkTokenSource(credential.rel, credential.text, { required: false }));
  else violations.push(`${CREDENTIAL_FILE}: missing`);

  const base = parsedFiles.find((f) => f.rel === BASE_FILE);
  const sharedReduce = !!base && hasReduceBlock(base.parsed);

  for (const f of parsedFiles) {
    const isTokenFile = f.rel === TOKENS_FILE || f.rel === CREDENTIAL_FILE;
    violations.push(...checkColorLiterals(f.rel, f.parsed, isTokenFile));
    violations.push(...checkFocus(f.rel, f.parsed));
    violations.push(...checkRemote(f.rel, f.parsed));
    const animated = f.parsed.rules.some((r) => !isReduceMedia(r.media) && r.decls.some((d) => /^(?:transition|animation)(?:-|$)/.test(d.prop)));
    if (animated) {
      const covered = f.rel === CREDENTIAL_FILE ? hasReduceBlock(f.parsed) : hasReduceBlock(f.parsed) || sharedReduce;
      if (!covered) violations.push(`${f.rel}: transition/animation without a prefers-reduced-motion: reduce block`);
    }
  }

  if (credential && credential.parsed.statements.some((s) => s.name === 'import')) {
    violations.push(`${CREDENTIAL_FILE}: must not @import anything (spec 10.3 isolation)`);
  }
  if (credential) {
    for (const f of parsedFiles) {
      if (f !== credential && f.text === credential.text) violations.push(`${CREDENTIAL_FILE}: identical to ${f.rel} (the bundles would merge)`);
    }
  }

  // Every var(--x) must resolve in its own bundle (the credential page shares nothing).
  const bundles = [
    parsedFiles.filter((f) => f.rel !== CREDENTIAL_FILE),
    parsedFiles.filter((f) => f.rel === CREDENTIAL_FILE),
  ];
  for (const bundle of bundles) {
    const defined = new Set();
    for (const f of bundle) {
      for (const rule of f.parsed.rules) for (const d of rule.decls) if (d.prop.startsWith('--')) defined.add(d.prop);
    }
    for (const f of bundle) {
      for (const rule of f.parsed.rules) {
        for (const d of rule.decls) {
          for (const m of d.value.matchAll(/var\(\s*(--[\w-]+)\s*([,)])/g)) {
            if (m[2] === ')' && !defined.has(m[1])) violations.push(`${f.rel}: ${m[1]} is used but never defined`);
          }
        }
      }
    }
  }

  violations.push(...checkRowContract(parsedFiles.flatMap((f) => f.parsed.rules.map((rule) => ({ rel: f.rel, rule })))));
  violations.push(...checkRowRem(srcDir));
  violations.push(...checkStyleProps(srcDir));
  return violations;
}

function main(argv) {
  if (argv.length !== 1 || !existsSync(argv[0]) || !statSync(argv[0]).isDirectory()) {
    console.error('usage: node scripts/check-css.mjs <srcDir>');
    return 2;
  }
  const violations = checkAll(path.resolve(argv[0]));
  for (const v of violations) console.log(v);
  if (violations.length > 0) {
    console.log(`check-css: ${violations.length} violation(s)`);
    return 1;
  }
  console.log('check-css: ok');
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
