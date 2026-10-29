#!/usr/bin/env node
// i18n completeness check (M15 T2; PD-291..PD-298, PD-296).
// Encodes: (a) the closed code sets of Rust -- `ErrorCode::ALL` (crates/ipc/src/envelope.rs), the
// `CmdError` variants (crates/server/src/cmd.rs), the `e(StatusCode::..., "<code>", ...)` constants
// (crates/server/src/errors.rs), the `DecisionError` kinds, the `BatchFailure` codes (with every
// `InvalidReason`) and `BlockReason` (crates/core) -- equal the keys of `errors.{envelope,cmd,server,
// decision}` in app/ui/src/shared/i18n/{en,de}/errors.ts and of `approvals.{batch_failure,block_reason}`
// in {en,de}/approvals.ts, both ways; (b) a German string leaf equal to its English one needs an entry in
// `I18N_SAME_ALLOWLIST` (with a reason; an entry that no longer matches is stale and fails);
// (c) no empty string leaf; (d) the keys of `SHORT_KEYS` (buttons and other fixed-width texts) stay
// within 1.5x the English length + 4 in German. The two dictionaries also have exactly the same keys.
//
// The dictionary files are read as text by a small parser for the shape the dictionaries use
// (`export const name = { key: 'text', fn: (n) => ..., nested: { ... } } as const;`); function and
// array values are skipped, only plain string literals are compared.
//
// Usage: node ci/check-i18n.mjs
// Exit 0 = ok. Exit 1 = violations (one per line on stdout).
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const I18N_DIR = "app/ui/src/shared/i18n";

/** Dotted key paths (`<exported object>.<key>...`) whose German text equals the English one. */
export const I18N_SAME_ALLOWLIST = {
  "common.lang_de": "a language is named in its own language, in both dictionaries",
  "common.lang_en": "a language is named in its own language, in both dictionaries",
  "approvals.request.params_sha256": "the name of a field of the request, shown as it is on the wire",
  "approvals.request.cwd_basename": "the name of a field of the request, shown as it is on the wire",
  "audit.field.client_kind": "a column name that is the same word in German (the kind of MCP client)",
  "running.col_agent": "Agent is the German term for the AI program (CONTEXT.md)",
  "settings.col_alias": "Alias is the German word for the instance name",
  "settings.add_alias": "Alias is the German word for the instance name",
  "setup.col_alias": "Alias is the German word for the instance name",
  "settings.col_origin": "Origin is the term of the instance's confirmed origin (scheme, host, port), used as is in German texts",
  "setup.col_origin": "Origin is the term of the instance's confirmed origin (scheme, host, port), used as is in German texts",
  "settings.col_proxy": "Proxy is the German word",
  "settings.product.jira": "a product name",
  "settings.product.confluence": "a product name",
  "settings.limits": "Limits is the usual German IT word",
  "server.header.auditor": "Auditor is the German role name (CONTEXT.md)",
  "server.api_keys.name": "Name is the same German word",
  "server.api_keys.col_name": "Name is the same German word",
  "server.api_keys.never": "a dash, language-neutral",
  "server.connected_apps.never": "a dash, language-neutral",
  "server.credentials.col_url": "URL is the same in German",
  "server.credentials.col_token": "Token is the German word (glossary)",
  "server.connected_apps.col_app": "App is the German word",
};

/** Dotted key paths of fixed-width texts (buttons, tray tooltip parts); German <= 1.5 x English + 4. */
export const SHORT_KEYS = [
  // The decision bar and the batch and deny buttons (M15 T5, Review Focus 1).
  "approvals.detail.approve",
  "approvals.detail.release",
  "approvals.detail.release_outcome",
  "approvals.detail.release_status_only",
  "approvals.detail.deny",
  "approvals.deny.submit",
  "approvals.deny.cancel",
  "approvals.batch.confirm",
  "approvals.batch.cancel",
  "approvals.batch.deny_selected",
  "approvals.batch.deny_send",
  "approvals.edit.submit",
  "approvals.edit.reset",
  "approvals.queue.open",
  "approvals.recent.acknowledge",
  // The buttons of the other windows (M15 T6).
  "settings.confirm",
  "settings.retest",
  "settings.replace_token",
  "settings.add_token",
  "settings.apply",
  "settings.proxy_apply",
  "settings.removal_done",
  "settings.removal_undo",
  "audit.verify",
  "audit.apply",
  "audit.clear",
  "audit.list_more",
  "audit.ack_close",
  "running.kill",
  "onboarding.copy_button",
  "setup.continue",
  "setup.quit",
];

/** `CmdError` variants that are not UI error kinds: the decision errors have their own map (`errors.decision`). */
const CMD_NOT_UI = ["Decision"];
/** `BatchFailure` variants that stand for other codes: `Invalid(InvalidReason)` is the reasons themselves. */
const BATCH_FAILURE_NOT_CODE = ["Invalid"];

/** The code sets of `errors.ts` and of `approvals.ts` (root object, then section). */
const ERROR_SECTIONS = ["envelope", "cmd", "decision", "server"];
const APPROVAL_SECTIONS = ["batch_failure", "block_reason"];

// ---------- Rust sources ----------

const snake = (name) => name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();

export function parseEnvelopeCodes(src) {
  const start = src.indexOf("pub const ALL");
  if (start < 0) return [];
  const end = src.indexOf("];", start);
  return [...src.slice(start, end).matchAll(/ErrorCode::(\w+)/g)].map((m) => snake(m[1]));
}

/** The variant names of `pub enum <name> { ... }` (first level only), as snake_case, minus `exclude`. */
function enumVariants(raw, name, exclude = []) {
  const src = raw.replace(/^\s*\/\/.*$/gm, "");
  const start = src.search(new RegExp(`pub enum ${name}\\b`));
  if (start < 0) return [];
  const open = src.indexOf("{", start);
  const kinds = [];
  let depth = 0;
  let line = "";
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === "{") {
      if (depth === 1) collect(line);
      depth++;
      line = "";
    } else if (ch === "}") {
      depth--;
      if (depth === 0) break;
      line = "";
    } else if (ch === "\n" || (ch === "," && depth === 1)) {
      if (depth === 1) collect(line);
      line = "";
    } else {
      line += ch;
    }
  }
  function collect(text) {
    const m = /^\s*([A-Z]\w*)\s*(\(.*\))?\s*$/.exec(text);
    if (m && !exclude.includes(m[1])) kinds.push(snake(m[1]));
  }
  return kinds;
}

export const parseCmdKinds = (src) => enumVariants(src, "CmdError", CMD_NOT_UI);

/** `DecisionError` (crates/core/src/decision/mod.rs): its serializer writes the snake_case variant as `kind`. */
export const parseDecisionKinds = (src) => enumVariants(src, "DecisionError");

/** `BatchFailure` codes: its own variants plus every `InvalidReason` (serialized by `as_str`). */
export function parseBatchFailureCodes(decisionSrc, payloadsSrc) {
  return [
    ...enumVariants(decisionSrc, "BatchFailure", BATCH_FAILURE_NOT_CODE),
    ...enumVariants(payloadsSrc, "InvalidReason"),
  ];
}

/** `BlockReason` (crates/core/src/redact/mod.rs): serde `tag = "reason"`, snake_case. */
export const parseBlockReasons = (src) => enumVariants(src, "BlockReason");

export function parseServerCodes(src) {
  const code = src.split("#[cfg(test)]")[0];
  return [...code.matchAll(/\be\(\s*StatusCode::\w+,\s*"([^"]+)"/g)].map((m) => m[1]);
}

// ---------- TypeScript dictionary files ----------

const QUOTES = ["'", '"'];

function skipTrivia(s, i) {
  for (;;) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s.startsWith("//", i)) {
      while (i < s.length && s[i] !== "\n") i++;
    } else if (s.startsWith("/*", i)) {
      const end = s.indexOf("*/", i + 2);
      i = end < 0 ? s.length : end + 2;
    } else {
      return i;
    }
  }
}

const ESCAPES = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", 0: "\0" };

function readString(s, i) {
  const quote = s[i];
  let out = "";
  i++;
  while (i < s.length && s[i] !== quote) {
    if (s[i] === "\\") {
      const c = s[i + 1];
      if (c === "u" && /^[0-9a-fA-F]{4}$/.test(s.slice(i + 2, i + 6))) {
        out += String.fromCharCode(parseInt(s.slice(i + 2, i + 6), 16));
        i += 6;
        continue;
      }
      out += ESCAPES[c] ?? c;
      i += 2;
    } else {
      out += s[i++];
    }
  }
  return [out, i + 1];
}

/** Skips a template literal starting at the backtick; returns the index after it. */
function skipTemplate(s, i) {
  i++;
  while (i < s.length && s[i] !== "`") {
    if (s[i] === "\\") i += 2;
    else if (s[i] === "$" && s[i + 1] === "{") i = skipBalanced(s, i + 1);
    else i++;
  }
  return i + 1;
}

/** Skips from an opening bracket to just after its match, honouring strings and templates. */
function skipBalanced(s, i) {
  let depth = 0;
  while (i < s.length) {
    const ch = s[i];
    if (QUOTES.includes(ch)) i = readString(s, i)[1];
    else if (ch === "`") i = skipTemplate(s, i);
    else if (s.startsWith("//", i) || s.startsWith("/*", i)) i = skipTrivia(s, i);
    else {
      if ("([{".includes(ch)) depth++;
      else if (")]}".includes(ch)) {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
  }
  return i;
}

/** Skips an expression up to (not including) the `,` or closing bracket that ends it. */
function skipExpr(s, i) {
  while (i < s.length) {
    const ch = s[i];
    if (ch === "," || ch === "}" || ch === "]") return i;
    if (QUOTES.includes(ch)) i = readString(s, i)[1];
    else if (ch === "`") i = skipTemplate(s, i);
    else if ("([{".includes(ch)) i = skipBalanced(s, i);
    else if (s.startsWith("//", i) || s.startsWith("/*", i)) i = skipTrivia(s, i);
    else i++;
  }
  return i;
}

function parseValue(s, i) {
  i = skipTrivia(s, i);
  if (s[i] === "{") return parseObject(s, i);
  if (QUOTES.includes(s[i])) {
    const [str, end] = readString(s, i);
    const next = skipTrivia(s, end);
    if (next >= s.length || ",}]".includes(s[next])) return [str, next];
    return [null, skipExpr(s, end)];
  }
  return [null, skipExpr(s, i)];
}

function parseObject(s, i) {
  const out = {};
  i++;
  for (;;) {
    i = skipTrivia(s, i);
    if (i >= s.length) return [out, i];
    if (s[i] === "}") return [out, i + 1];
    if (s[i] === ",") {
      i++;
      continue;
    }
    if (s.startsWith("...", i)) {
      i = skipExpr(s, i);
      continue;
    }
    let key;
    if (QUOTES.includes(s[i])) [key, i] = readString(s, i);
    else {
      const m = /^[\w$]+/.exec(s.slice(i));
      if (m === null) return [out, s.length];
      key = m[0];
      i += key.length;
    }
    i = skipTrivia(s, i);
    if (s[i] === ":") {
      let value;
      [value, i] = parseValue(s, i + 1);
      out[key] = value;
    } else {
      out[key] = null; // shorthand property or method
      i = skipExpr(s, i);
    }
  }
}

/** The tree of `export const <name> ... = { ... }`: nested objects, string leaves, `null` for the rest. */
export function parseTsDict(src, name) {
  const re = new RegExp(`export const ${name}\\b[^=]*=\\s*`);
  const m = re.exec(src);
  if (m === null) return null;
  const i = skipTrivia(src, m.index + m[0].length);
  if (src[i] !== "{") return null;
  return parseObject(src, i)[0];
}

/** Every `export const <name>` of a file, as `{ name: tree }`. */
function parseAllRoots(src) {
  const roots = {};
  for (const m of src.matchAll(/export const (\w+)\b/g)) {
    const tree = parseTsDict(src, m[1]);
    if (tree !== null) roots[m[1]] = tree;
  }
  return roots;
}

// ---------- checks ----------

/** (a) The Rust code sets equal the keys of the dictionary sections in both languages. */
function checkSections(root, fileName, sections, rust, enSrc, deSrc) {
  const errors = [];
  for (const [file, src] of [
    [`en/${fileName}`, enSrc],
    [`de/${fileName}`, deSrc],
  ]) {
    const tree = parseTsDict(src, root);
    for (const section of sections.filter((s) => s in rust)) {
      const node = tree?.[section];
      if (node === null || node === undefined || typeof node !== "object") {
        errors.push(`${file}: section "${section}" is missing`);
        continue;
      }
      const have = new Set(Object.keys(node));
      const want = new Set(rust[section]);
      for (const code of want) if (!have.has(code)) errors.push(`${file}: ${section} code "${code}" has no text`);
      for (const code of have) if (!want.has(code)) errors.push(`${file}: ${section} key "${code}" is not in Rust`);
    }
  }
  return errors;
}

/** `errors.{envelope,cmd,decision,server}`: the error code sets of Rust. */
export const checkErrorCodes = (rust, enSrc, deSrc) =>
  checkSections("errors", "errors.ts", ERROR_SECTIONS, rust, enSrc, deSrc);

/** `approvals.{batch_failure,block_reason}`: the batch failure codes and block reasons of core. */
export const checkApprovalCodes = (rust, enSrc, deSrc) =>
  checkSections("approvals", "approvals.ts", APPROVAL_SECTIONS, rust, enSrc, deSrc);

function flatten(tree, prefix, out) {
  for (const [k, v] of Object.entries(tree)) {
    const path = prefix === "" ? k : `${prefix}.${k}`;
    if (v !== null && typeof v === "object") flatten(v, path, out);
    else out.set(path, v);
  }
  return out;
}

/** (b)-(d) and key parity of the German dictionary against the English one. */
export function checkLeaves(enRoots, deRoots, allowlist, shortKeys) {
  const errors = [];
  const en = new Map();
  const de = new Map();
  for (const [name, tree] of Object.entries(enRoots)) {
    flatten(tree, name, en);
    if (!(name in deRoots)) errors.push(`de: dictionary "${name}" is missing`);
  }
  for (const [name, tree] of Object.entries(deRoots)) if (name in enRoots) flatten(tree, name, de);
  for (const path of en.keys()) if (!de.has(path) && deRootOf(path, deRoots)) errors.push(`de: key ${path} is missing`);
  for (const path of de.keys()) if (!en.has(path)) errors.push(`de: key ${path} is not in en`);
  for (const [lang, map] of [
    ["en", en],
    ["de", de],
  ]) {
    for (const [path, v] of map) if (v === "") errors.push(`${lang} ${path}: empty text`);
  }
  for (const [path, e] of en) {
    const d = de.get(path);
    if (typeof e !== "string" || typeof d !== "string" || e === "" || d === "") continue;
    if (e === d && !(path in allowlist)) {
      errors.push(`${path}: German equals English "${e}" (translate it or add it to I18N_SAME_ALLOWLIST with a reason)`);
    }
  }
  for (const path of Object.keys(allowlist)) {
    const e = en.get(path);
    if (typeof e !== "string" || e !== de.get(path)) errors.push(`stale allowlist entry ${path}: the leaves differ or are gone`);
  }
  for (const path of shortKeys) {
    const e = en.get(path);
    const d = de.get(path);
    if (typeof e !== "string" || typeof d !== "string") {
      errors.push(`short key ${path} is not a string in both languages`);
    } else if (d.length > 1.5 * e.length + 4) {
      errors.push(`short key ${path}: German is ${d.length} characters, the limit is ${1.5 * e.length + 4} (English ${e.length})`);
    }
  }
  return errors;
}

const deRootOf = (path, deRoots) => path.split(".")[0] in deRoots;

// ---------- repository ----------

function readRoots(dir) {
  const roots = {};
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts")).sort()) {
    Object.assign(roots, parseAllRoots(readFileSync(join(dir, f), "utf8")));
  }
  return roots;
}

export function main(_argv = process.argv.slice(2), repo = REPO) {
  const read = (rel) => readFileSync(join(repo, rel), "utf8");
  const rust = {
    envelope: parseEnvelopeCodes(read("crates/ipc/src/envelope.rs")),
    cmd: parseCmdKinds(read("crates/server/src/cmd.rs")),
    server: parseServerCodes(read("crates/server/src/errors.rs")),
    decision: parseDecisionKinds(read("crates/core/src/decision/mod.rs")),
    batch_failure: parseBatchFailureCodes(read("crates/core/src/decision/mod.rs"), read("crates/core/src/payloads.rs")),
    block_reason: parseBlockReasons(read("crates/core/src/redact/mod.rs")),
  };
  const errors = [];
  for (const [section, codes] of Object.entries(rust)) {
    if (codes.length === 0) errors.push(`no ${section} codes found in the Rust sources (parser out of date?)`);
  }
  errors.push(...checkErrorCodes(rust, read(`${I18N_DIR}/en/errors.ts`), read(`${I18N_DIR}/de/errors.ts`)));
  errors.push(...checkApprovalCodes(rust, read(`${I18N_DIR}/en/approvals.ts`), read(`${I18N_DIR}/de/approvals.ts`)));
  errors.push(
    ...checkLeaves(readRoots(join(repo, I18N_DIR, "en")), readRoots(join(repo, I18N_DIR, "de")), I18N_SAME_ALLOWLIST, SHORT_KEYS),
  );
  for (const e of errors) console.log(e);
  if (errors.length === 0) console.log("check-i18n: ok");
  return errors.length === 0 ? 0 : 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
