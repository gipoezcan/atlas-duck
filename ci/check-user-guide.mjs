#!/usr/bin/env node
// User guide consistency check (M16 T3, PD-321, PD-327). Reads the sources `docs/user-guide`, the
// generated sets (`app/ui/public/help`, `app/ui/public-server/docs`: manifest.json and pages), the
// UI link map `docs/user-guide/ui-links.json`, the window labels of check-commands.mjs, the server
// page table of `crates/server/src/static_files.rs` and the Rust error code sets (parsers of
// check-i18n.mjs). The generator itself (`atlas-duck-docgen --check`) proves the committed output
// is current; this script proves what the generator cannot:
//
//   - both languages carry the same pages and the same heading anchors per set (PD-321),
//   - `error-reference` has one `err-<code>` section per code of the five error sets and no other
//     `err-` section (anchor = "err-" + code with "_" and "/" replaced by "-"),
//   - ui-links.json maps every desktop window label and every server page to an existing
//     `page#anchor` of the right set, and names nothing else,
//   - every internal link of the generated pages resolves,
//   - no `TODO` placeholder is left in a source (unless --allow-todo, used on the M16 branch only).
//
// Usage: node ci/check-user-guide.mjs [--allow-todo]
// Exit 0 = ok. Exit 1 = findings, one per line. No npm dependencies.

import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { LABELS } from "./check-commands.mjs";
import {
  parseBatchFailureCodes,
  parseCmdKinds,
  parseDecisionKinds,
  parseEnvelopeCodes,
  parseServerCodes,
} from "./check-i18n.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const LANGS = ["en", "de"];
const SETS = ["desktop", "server"];
const SET_DIRS = { desktop: "app/ui/public/help", server: "app/ui/public-server/docs" };

/** Labels without a "?" link of their own: the Help window itself. */
export const LABELS_WITHOUT_LINK = ["help"];
/** Server pages that need no entry in the page list of the map (still allowed in it). */
export const SERVER_PATHS_OPTIONAL = ["/oauth/consent"];
/** Desktop labels that need no entry (still allowed in the map). */
export const LABELS_OPTIONAL = ["credential"];

/** Which sets document each Rust error code set (the five sets of check-i18n's `errors`/`batch`). */
export const CODE_SETS = {
  envelope: SETS,
  decision: SETS,
  batch: SETS,
  cmd: ["server"],
  server: ["server"],
};

/** `error-reference` anchor of an error code. */
export const errAnchor = (code) => "err-" + code.replace(/[_/]/g, "-");

const diff = (a, b) => [...a].filter((x) => !b.has(x));

function manifestPages(manifest) {
  return new Map((manifest?.pages ?? []).map((p) => [p.id, p]));
}

/** PD-321: same pages, same anchors in both languages. */
function checkParity(inp, errors) {
  for (const set of SETS) {
    const en = manifestPages(inp.manifests[set].en);
    const de = manifestPages(inp.manifests[set].de);
    for (const id of en.keys()) if (!de.has(id)) errors.push(`${set}: page ${id} exists in en but not in de`);
    for (const id of de.keys()) if (!en.has(id)) errors.push(`${set}: page ${id} exists in de but not in en`);
    for (const [id, p] of en) {
      const q = de.get(id);
      if (!q) continue;
      const a = new Set(p.anchors);
      const b = new Set(q.anchors);
      const onlyEn = diff(a, b);
      const onlyDe = diff(b, a);
      if (onlyEn.length > 0 || onlyDe.length > 0) {
        errors.push(
          `${set}/${id}: anchors differ between en and de (only en: ${onlyEn.join(", ") || "-"}; only de: ${onlyDe.join(", ") || "-"})`,
        );
      }
    }
  }
}

/** One `err-` section per error code, per set the code is documented in. */
function checkErrorCodes(inp, errors) {
  const required = Object.fromEntries(SETS.map((s) => [s, new Set()]));
  for (const [name, sets] of Object.entries(CODE_SETS)) {
    for (const code of inp.codes[name] ?? []) for (const s of sets) required[s].add(errAnchor(code));
  }
  for (const set of SETS) {
    for (const lang of LANGS) {
      const page = manifestPages(inp.manifests[set][lang]).get("error-reference");
      if (!page) {
        errors.push(`${set}/${lang}: no error-reference page`);
        continue;
      }
      const have = new Set(page.anchors.filter((a) => a.startsWith("err-")));
      for (const a of diff(required[set], have)) errors.push(`${set}/${lang}: error code without an entry: ${a}`);
      for (const a of diff(have, required[set])) errors.push(`${set}/${lang}: entry without an error code: ${a}`);
    }
  }
}

/** PD-327: ui-links.json against the manifests, the window labels and the server pages. */
function checkUiLinks(inp, errors) {
  const wanted = {
    desktop: { keys: inp.labels, free: [...LABELS_WITHOUT_LINK, ...LABELS_OPTIONAL] },
    server: { keys: inp.serverPaths, free: SERVER_PATHS_OPTIONAL },
  };
  for (const set of SETS) {
    const map = inp.uiLinks[set] ?? {};
    const { keys, free } = wanted[set];
    for (const k of keys) {
      if (!free.includes(k) && !(k in map)) errors.push(`ui-links ${set}: ${k} has no help link`);
    }
    for (const [k, target] of Object.entries(map)) {
      if (!keys.includes(k)) errors.push(`ui-links ${set}: ${k} is not a ${set === "desktop" ? "window label" : "server page"}`);
      checkTarget(set, set, k, target, inp, errors);
    }
  }
  // M16 T7: the "?" links next to sections of the desktop windows, `<window label>/<section>`.
  for (const [k, target] of Object.entries(inp.uiLinks.desktop_sections ?? {})) {
    const [label, section, ...rest] = k.split("/");
    if (!label || !section || rest.length > 0 || !inp.labels.includes(label) || LABELS_WITHOUT_LINK.includes(label)) {
      errors.push(`ui-links desktop_sections: ${k} is not <window label>/<section>`);
    }
    checkTarget("desktop_sections", "desktop", k, target, inp, errors);
  }
}

/** One `page#anchor` target of ui-links.json: it must exist in every language of `set`. */
function checkTarget(name, set, k, target, inp, errors) {
  const m = /^([a-z0-9-]+)#([a-z0-9-]+)$/.exec(target);
  if (!m) {
    errors.push(`ui-links ${name}: ${k} -> ${target} is not page#anchor`);
    return;
  }
  for (const lang of LANGS) {
    const page = manifestPages(inp.manifests[set][lang]).get(m[1]);
    if (!page) errors.push(`ui-links ${name}: ${k} -> ${target}: no page ${m[1]} in the ${set} set (${lang})`);
    else if (!page.anchors.includes(m[2])) errors.push(`ui-links ${name}: ${k} -> ${target}: no anchor ${m[2]} (${lang})`);
  }
}
/** Resolves an href of a generated page to [lang, page id, anchor] or null when it is not internal. */
function resolveHref(set, lang, id, href) {
  if (/^https?:\/\//.test(href) || href.startsWith("assets/")) return "skip";
  const [path, anchor = null] = href.split("#");
  if (path === "") return [lang, id, anchor];
  if (set === "desktop") {
    const m = /^(?:\.\.\/(en|de)\/)?([a-z0-9-]+)\.html$/.exec(path);
    return m ? [m[1] ?? lang, m[2], anchor] : null;
  }
  const m = /^\/docs\/(en|de)\/(?:([a-z0-9-]+))?$/.exec(path);
  return m ? [m[1], m[2] ?? "index", anchor] : null;
}

function checkLinks(inp, errors) {
  for (const set of SETS) {
    for (const lang of LANGS) {
      for (const [id, html] of Object.entries(inp.html[set]?.[lang] ?? {})) {
        for (const m of html.matchAll(/\shref="([^"]*)"/g)) {
          const href = m[1].replaceAll("&amp;", "&");
          const r = resolveHref(set, lang, id, href);
          if (r === "skip") continue;
          const where = `${set}/${lang}/${id}: link ${href}`;
          if (!r) {
            errors.push(`${where} is not a guide link`);
            continue;
          }
          const [tl, tid, anchor] = r;
          const page = manifestPages(inp.manifests[set][tl]).get(tid);
          if (!page) errors.push(`${where} points at a missing page`);
          else if (anchor !== null && !page.anchors.includes(anchor)) errors.push(`${where} points at a missing anchor`);
        }
      }
    }
  }
}

function checkTodo(inp, errors, allowTodo) {
  if (allowTodo) return;
  for (const s of inp.sources) {
    s.text.split("\n").forEach((line, i) => {
      if (/^\s*TODO\b/.test(line)) errors.push(`${s.path}:${i + 1}: TODO placeholder`);
    });
  }
}

/** All findings for `inp` (see `loadInputs` for its shape). */
export function checkUserGuide(inp, { allowTodo = false } = {}) {
  const errors = [];
  checkParity(inp, errors);
  checkErrorCodes(inp, errors);
  checkUiLinks(inp, errors);
  checkLinks(inp, errors);
  checkTodo(inp, errors, allowTodo);
  return errors;
}

/** The `PAGES` paths of crates/server/src/static_files.rs. */
export function parseServerPages(src) {
  const start = src.indexOf("pub const PAGES");
  if (start < 0) return [];
  const end = src.indexOf("];", start);
  return [...src.slice(start, end).matchAll(/\(\s*"(\/[^"]*)"\s*,\s*"[^"]+\.html"\s*\)/g)].map((m) => m[1]);
}

export function loadInputs(repo = REPO) {
  const read = (rel) => readFileSync(join(repo, rel), "utf8").replace(/\r\n/g, "\n");
  const manifests = {};
  const html = {};
  for (const set of SETS) {
    manifests[set] = {};
    html[set] = {};
    for (const lang of LANGS) {
      const dir = join(SET_DIRS[set], lang);
      if (!existsSync(join(repo, dir, "manifest.json"))) {
        throw new Error(`${dir}/manifest.json is missing: run atlas-duck-docgen`);
      }
      const manifest = JSON.parse(read(`${dir}/manifest.json`));
      manifests[set][lang] = manifest;
      html[set][lang] = Object.fromEntries(manifest.pages.map((p) => [p.id, read(`${dir}/${p.file}`)]));
    }
  }
  const dec = read("crates/core/src/decision/mod.rs");
  const codes = {
    envelope: parseEnvelopeCodes(read("crates/ipc/src/envelope.rs")),
    decision: parseDecisionKinds(dec),
    batch: parseBatchFailureCodes(dec, read("crates/core/src/payloads.rs")),
    cmd: parseCmdKinds(read("crates/server/src/cmd.rs")),
    server: parseServerCodes(read("crates/server/src/errors.rs")),
  };
  const sources = [];
  for (const lang of LANGS) {
    const dir = `docs/user-guide/${lang}`;
    for (const f of readdirSync(join(repo, dir)).filter((n) => n.endsWith(".md")).sort()) {
      sources.push({ path: `${dir}/${f}`, text: read(`${dir}/${f}`) });
    }
  }
  return {
    manifests,
    html,
    uiLinks: JSON.parse(read("docs/user-guide/ui-links.json")),
    labels: LABELS,
    serverPaths: parseServerPages(read("crates/server/src/static_files.rs")),
    codes,
    sources,
  };
}

export function main(argv = process.argv.slice(2), repo = REPO) {
  const allowTodo = argv.includes("--allow-todo");
  let inp;
  try {
    inp = loadInputs(repo);
  } catch (e) {
    console.log(`check-user-guide: ${e.message}`);
    return 1;
  }
  const errors = [];
  for (const [name, list] of [
    ["window labels", inp.labels],
    ["server pages", inp.serverPaths],
    ...Object.entries(inp.codes).map(([n, l]) => [`${n} codes`, l]),
  ]) {
    if (list.length === 0) errors.push(`no ${name} found (parser out of date?)`);
  }
  errors.push(...checkUserGuide(inp, { allowTodo }));
  for (const e of errors) console.log(e);
  if (errors.length === 0) console.log(`check-user-guide: ok${allowTodo ? " (TODO placeholders allowed)" : ""}`);
  return errors.length === 0 ? 0 : 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
