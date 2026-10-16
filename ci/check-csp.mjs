#!/usr/bin/env node
// CSP check (§6.4, §10.3, §13 CI "CSP check", §15 V34; M6 T4).
// Encodes: for each platform's merged Tauri config (`tauri.conf.json` + `tauri.<platform>.conf.json`,
// JSON merge patch as Tauri applies it) the main-window CSP is exactly the §6.4 policy with the
// isolation-origin placeholder in `frame-src`, no `'unsafe-*'` source, no `devCsp`, no CSP opt-out,
// no asset protocol, `freezePrototype` on, the isolation pattern set and `useHttpsScheme` never
// true; the app patches the placeholder with this build's isolation origin before it builds
// (`csp::patch_context` in `run_gui`; Tauri 2.12.1 mints `isolation-<uuid>` per build, so no
// static origin can be right); the credential page(s) carry the §10.3 policy as the first `<head>`
// element, in the sources and, with `--dist`, in the built files. Both policies admit exactly one
// inline style besides 'self': the `<style>` Tauri's isolation.js injects into every page (its
// sha256 hash, lead ruling B1 of the M6 CI round 2; `csp::tests` pins it to Tauri's own constant).
//
// The main policy also admits the preview document's one inline `<style>` (`preview.css`, PD-92
// contingency, ruling C1) by its hash, which must equal the renderer's `PREVIEW_CSS_HASH`;
// `--write` puts the current hash into tauri.conf.json and crates/preview/src/sanitize.rs.
//
// Usage: node ci/check-csp.mjs [--write] [--dist app/ui/dist]
// Exit 0 = ok. Exit 1 = violations (one per line on stdout).
// No npm dependencies: node:fs, node:path, node:url, node:crypto only.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The `frame-src` source the policies carry for the isolation origin (§6.4 notation). */
export const ISOLATION_ORIGIN = "<isolation-origin>";

/** A CSP hash source for an inline element whose text is `text` (UTF-8, sha256, base64). */
export function cspHash(text) {
  return `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;
}

/**
 * The text of the `<style>` Tauri 2.12.1's isolation.js appends to every page
 * (`tauri::utils::pattern::isolation::IFRAME_STYLE`; `csp::tests` fails when Tauri changes it).
 */
export const ISOLATION_IFRAME_STYLE = "#__tauri_isolation__ { display: none !important }";

/** Its hash source, the one inline style both policies admit. */
export const ISOLATION_STYLE_HASH = cspHash(ISOLATION_IFRAME_STYLE);

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The preview document's stylesheet, as `crates/preview` embeds it (`include_str!`). */
export const PREVIEW_CSS_FILE = "app/ui/public/preview.css";
/** Where the renderer keeps its hash source (`PREVIEW_CSS_HASH`), written by `--write`. */
export const SANITIZE_RS = "crates/preview/src/sanitize.rs";
/** The renderer's embedding of `PREVIEW_CSS_FILE`, relative to `SANITIZE_RS`. */
export const PREVIEW_CSS_INCLUDE = 'include_str!("../../../app/ui/public/preview.css")';

/**
 * PD-92 contingency (ruling C1, M6 CI round 2): the sandboxed `srcdoc` preview document carries
 * `preview.css` as one inline `<style>`; the main policy, which that document inherits, admits it
 * by this hash (the document's own meta CSP names the same hash, `PREVIEW_CSS_HASH` in Rust).
 */
export const PREVIEW_CSS_HASH = cspHash(readFileSync(join(REPO, PREVIEW_CSS_FILE), "utf8"));

/** §6.4 main-window CSP with `previewHash` (verbatim otherwise, `<isolation-origin>` kept). */
export function mainPolicy(previewHash) {
  return (
    `default-src 'self'; script-src 'self'; style-src 'self' ${ISOLATION_STYLE_HASH} ${previewHash}; ` +
    "img-src 'self' data:; connect-src ipc: http://ipc.localhost; frame-src 'self' <isolation-origin>; " +
    "worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
}

/** §6.4 main-window CSP for this repository's `preview.css`. */
export const MAIN_POLICY = mainPolicy(PREVIEW_CSS_HASH);

/** §10.3 credential-entry window meta CSP (verbatim, `<isolation-origin>` kept). */
export const CREDENTIAL_POLICY =
  `default-src 'none'; script-src 'self'; style-src 'self' ${ISOLATION_STYLE_HASH}; connect-src ipc: http://ipc.localhost; ` +
  "frame-src <isolation-origin>; worker-src 'none'; form-action 'none'; base-uri 'none'";

export const PLATFORMS = ["windows", "macos", "linux"];

/** The credential entry page (PD-71; one page since T4: Rust serves it with the build's origin). */
export const CREDENTIAL_PAGES = ["credential.html"];

/** `run_gui` must call this before it builds the app. */
export const PATCH_CALL = "csp::patch_context(&mut context)";

// ---------- policies ----------

/** Directive name -> sources, in order; `null` when a directive repeats or a part is empty. */
export function parsePolicy(text) {
  const map = new Map();
  for (const part of String(text).split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (map.has(name)) return null;
    map.set(name, tokens.slice(1));
  }
  return map;
}

function normalize(text) {
  return String(text)
    .split(";")
    .map((p) => p.trim().split(/\s+/).filter(Boolean).join(" "))
    .filter(Boolean)
    .join("; ");
}

/** Violations of `text` against `expected` (both with the placeholder). */
export function checkPolicy(text, expected, where) {
  const errors = [];
  if (typeof text !== "string" || text.trim() === "") return [`${where}: no CSP`];
  for (const bad of ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'"]) {
    if (text.toLowerCase().includes(bad)) errors.push(`${where}: CSP contains ${bad}`);
  }
  const map = parsePolicy(text);
  if (!map) {
    errors.push(`${where}: CSP repeats a directive`);
    return errors;
  }
  const frame = map.get("frame-src");
  if (!frame || !frame.includes(ISOLATION_ORIGIN)) {
    errors.push(`${where}: frame-src does not name ${ISOLATION_ORIGIN} (every invoke would hang, §6.4)`);
  }
  if (text.split(ISOLATION_ORIGIN).length !== 2) {
    errors.push(`${where}: ${ISOLATION_ORIGIN} must appear exactly once, in frame-src`);
  }
  // The inline styles the policy admits: exactly the expected hash sources, nothing else.
  const style = (map.get("style-src") ?? []).join(" ");
  const expectedStyle = (parsePolicy(expected)?.get("style-src") ?? []).join(" ");
  if (style !== expectedStyle) {
    errors.push(`${where}: style-src must be exactly "${expectedStyle}", is "${style}"`);
  }
  if (normalize(text) !== normalize(expected)) {
    errors.push(`${where}: CSP differs from the spec text: ${normalize(text)} != ${normalize(expected)}`);
  }
  return errors;
}

// ---------- config ----------

/** RFC 7396 JSON merge patch (Tauri merges a platform config this way). */
export function mergePatch(target, patch) {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) return structuredClone(patch);
  const out = target !== null && typeof target === "object" && !Array.isArray(target) ? structuredClone(target) : {};
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete out[k];
    else out[k] = mergePatch(out[k], v);
  }
  return out;
}

function findKeys(value, names, path = "") {
  const hits = [];
  if (value === null || typeof value !== "object") return hits;
  for (const [k, v] of Object.entries(value)) {
    const p = path ? `${path}.${k}` : k;
    if (names.includes(k)) hits.push({ path: p, value: v });
    hits.push(...findKeys(v, names, p));
  }
  return hits;
}

/** Violations of one platform's merged config; `expected` is the main policy for the repository's
 *  own `preview.css` (`main` passes the one of the repository it checks). */
export function checkConfig(conf, platform, expected = MAIN_POLICY) {
  const where = `tauri config (${platform})`;
  const errors = [];
  const security = conf?.app?.security ?? {};
  errors.push(...checkPolicy(security.csp, expected, `${where} app.security.csp`));
  if (security.devCsp !== undefined) errors.push(`${where}: app.security.devCsp must not be set (dev builds use the same policy)`);
  if (security.dangerousDisableAssetCspModification !== undefined && security.dangerousDisableAssetCspModification !== false) {
    errors.push(`${where}: app.security.dangerousDisableAssetCspModification must not be set`);
  }
  if (security.assetProtocol?.enable) errors.push(`${where}: the asset protocol must stay disabled (§10.3)`);
  if (security.freezePrototype !== true) errors.push(`${where}: app.security.freezePrototype must be true`);
  if (security.pattern?.use !== "isolation") errors.push(`${where}: app.security.pattern must be the isolation pattern`);
  // T4 review M-4: both default off; neither may be turned on.
  if (conf?.app?.withGlobalTauri !== undefined && conf.app.withGlobalTauri !== false) {
    errors.push(`${where}: app.withGlobalTauri must stay unset (no window.__TAURI__ global)`);
  }
  if (security.headers !== undefined) errors.push(`${where}: app.security.headers must not be set (no custom response headers)`);
  for (const hit of findKeys(conf, ["useHttpsScheme", "use-https-scheme"])) {
    if (hit.value !== false) errors.push(`${where}: ${hit.path} must stay unset (the isolation origin assumes http/custom schemes)`);
  }
  return errors;
}

/** Platform overlays Tauri would merge, by platform: parsed JSON, or an Error. */
export function readOverlays(srcTauri) {
  const overlays = {};
  const errors = [];
  for (const name of readdirSync(srcTauri)) {
    const m = name.match(/^tauri\.(\w+)\.conf\.json$/i);
    if (m) {
      try {
        overlays[m[1].toLowerCase()] = JSON.parse(readFileSync(join(srcTauri, name), "utf8"));
      } catch (e) {
        errors.push(`${name}: not JSON (${e.message})`);
      }
    } else if (/^tauri\.\w+\.conf\.json5$/i.test(name) || /^tauri\.\w+\.toml$/i.test(name)) {
      errors.push(`${name}: platform overlays must be JSON so this check can read them`);
    }
  }
  return { overlays, errors };
}

/** Every platform's merged config checked against `expected` (see `checkConfig`). */
export function checkConfigs(base, overlays, expected = MAIN_POLICY) {
  const errors = [];
  for (const platform of PLATFORMS) {
    errors.push(...checkConfig(mergePatch(base, overlays[platform] ?? {}), platform, expected));
  }
  return errors;
}

// ---------- Rust ----------

/** The app patches the placeholder before building and never turns https schemes on. */
export function checkRust(files) {
  const errors = [];
  const lib = files["app/src-tauri/src/lib.rs"] ?? "";
  const csp = files["app/src-tauri/src/csp.rs"] ?? "";
  const gen = lib.indexOf("tauri::generate_context!()");
  const patch = lib.indexOf(PATCH_CALL);
  const build = lib.indexOf(".build(context)");
  if (patch < 0 || gen < 0 || patch < gen || (build >= 0 && patch > build)) {
    errors.push(`app/src-tauri/src/lib.rs: run_gui must call ${PATCH_CALL} between generate_context!() and .build(context)`);
  }
  if (!csp.includes(`pub const ISOLATION_ORIGIN_PLACEHOLDER: &str = "${ISOLATION_ORIGIN}";`)) {
    errors.push(`app/src-tauri/src/csp.rs: ISOLATION_ORIGIN_PLACEHOLDER must be "${ISOLATION_ORIGIN}"`);
  }
  for (const [file, text] of Object.entries(files)) {
    if (/use_https_scheme\s*\(\s*(?!false\s*\))/.test(text)) {
      errors.push(`${file}: use_https_scheme may only be called with false`);
    }
  }
  return errors;
}

// ---------- credential pages ----------

/** The first element of `<head>` and its CSP, or why there is none. */
export function headMetaCsp(html) {
  const head = String(html).match(/<head\b[^>]*>([\s\S]*?)<\/head>/i);
  if (!head) return { error: "no <head>" };
  const body = head[1].replace(/<!--[\s\S]*?-->/g, "").trimStart();
  const first = body.match(/^<([a-z]+)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/i);
  if (!first) return { error: "<head> has no element" };
  const attrs = {};
  for (const m of first[2].matchAll(/([a-z-]+)\s*=\s*("([^"]*)"|'([^']*)')/gi)) {
    attrs[m[1].toLowerCase()] = m[3] ?? m[4];
  }
  if (first[1].toLowerCase() !== "meta" || attrs["http-equiv"]?.toLowerCase() !== "content-security-policy") {
    return { error: "the first <head> element is not the CSP meta tag" };
  }
  return { csp: (attrs.content ?? "").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">") };
}

/** Violations of the credential pages in `pages` ({name: html}); `label` names the location. */
export function checkCredentialPages(pages, label) {
  const errors = [];
  for (const [name, html] of Object.entries(pages)) {
    const where = `${label}/${name}`;
    const { csp, error } = headMetaCsp(html);
    if (error) errors.push(`${where}: ${error} (§10.3)`);
    else errors.push(...checkPolicy(csp, CREDENTIAL_POLICY, where));
  }
  return errors;
}

function readPages(dir) {
  const pages = {};
  for (const name of CREDENTIAL_PAGES) {
    const p = join(dir, name);
    if (existsSync(p)) pages[name] = readFileSync(p, "utf8");
  }
  return pages;
}

// ---------- the preview stylesheet (PD-92 contingency, ruling C1) ----------

/** `css` can be one inline `<style>` with a stable hash: nothing ends it early, no CR (a browser
 *  normalizes line ends before hashing), not empty. */
export function checkPreviewCss(css) {
  const errors = [];
  if (css.trim() === "") errors.push(`${PREVIEW_CSS_FILE}: empty`);
  if (/<\/style/i.test(css)) errors.push(`${PREVIEW_CSS_FILE}: contains "</style", which would end the inline element`);
  if (css.includes("\r")) errors.push(`${PREVIEW_CSS_FILE}: contains a CR (the hash would not match the browser's)`);
  return errors;
}

const HASH_CONST = /pub const PREVIEW_CSS_HASH: &str = "([^"]*)";/g;

/** The renderer embeds `preview.css` from `PREVIEW_CSS_FILE` and names exactly `hash` once. */
export function checkPreviewRust(sanitize, hash) {
  const errors = [];
  if (!sanitize.includes(PREVIEW_CSS_INCLUDE)) {
    errors.push(`${SANITIZE_RS}: PREVIEW_CSS must be ${PREVIEW_CSS_INCLUDE}`);
  }
  const found = [...sanitize.matchAll(HASH_CONST)].map((m) => m[1]);
  if (found.length !== 1) {
    errors.push(`${SANITIZE_RS}: expected one PREVIEW_CSS_HASH constant, found ${found.length}`);
  } else if (found[0] !== hash) {
    errors.push(`${SANITIZE_RS}: PREVIEW_CSS_HASH is ${found[0]}, the hash of ${PREVIEW_CSS_FILE} is ${hash} (node ci/check-csp.mjs --write)`);
  }
  return errors;
}

const CONF_STYLE_SRC = /("csp":\s*"[^"]*?)style-src [^;"]*/;

/** What keeps `--write` from writing either file: a `css` that cannot be one inline `<style>`, a
 *  `conf` (tauri.conf.json text) that is no JSON or has no `style-src` in its `csp`, a `sanitize`
 *  (sanitize.rs text) without exactly one `PREVIEW_CSS_HASH` constant. */
export function previewWriteErrors(css, conf, sanitize) {
  const errors = checkPreviewCss(css);
  try {
    JSON.parse(conf);
  } catch (e) {
    errors.push(`tauri.conf.json: not JSON (${e.message})`);
  }
  if (!CONF_STYLE_SRC.test(conf)) errors.push("tauri.conf.json: no style-src in app.security.csp to write");
  const consts = [...sanitize.matchAll(HASH_CONST)].length;
  if (consts !== 1) errors.push(`${SANITIZE_RS}: expected one PREVIEW_CSS_HASH constant to write, found ${consts}`);
  return errors;
}

/** `--write`: `conf` (tauri.conf.json text) and `sanitize` (sanitize.rs text) with `hash` as the
 *  preview hash; the main policy's `style-src` is set to the expected one, nothing else changes. */
export function writePreviewHash(conf, sanitize, hash) {
  const style = parsePolicy(mainPolicy(hash)).get("style-src").join(" ");
  return {
    conf: conf.replace(CONF_STYLE_SRC, `$1style-src ${style}`),
    sanitize: sanitize.replace(HASH_CONST, `pub const PREVIEW_CSS_HASH: &str = "${hash}";`),
  };
}

// ---------- CLI ----------

function rustFiles(dir, repo) {
  const out = {};
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, name.name);
    if (name.isDirectory()) Object.assign(out, rustFiles(p, repo));
    else if (name.name.endsWith(".rs")) out[p.slice(repo.length + 1).replace(/\\/g, "/")] = readFileSync(p, "utf8");
  }
  return out;
}

export function main(argv = process.argv.slice(2), repo = REPO) {
  const errors = [];
  const notes = [];
  const srcTauri = join(repo, "app", "src-tauri");
  const css = readFileSync(join(repo, PREVIEW_CSS_FILE), "utf8");
  const previewHash = cspHash(css);
  if (argv.includes("--write")) {
    const confPath = join(srcTauri, "tauri.conf.json");
    const sanitizePath = join(repo, SANITIZE_RS);
    const conf = readFileSync(confPath, "utf8");
    const sanitize = readFileSync(sanitizePath, "utf8");
    // Everything is checked before either file is written: a refused input leaves both as they were.
    const refused = previewWriteErrors(css, conf, sanitize);
    if (refused.length > 0) {
      for (const e of refused) console.log(e);
      console.log("check-csp: --write wrote nothing");
      return 1;
    }
    const out = writePreviewHash(conf, sanitize, previewHash);
    writeFileSync(confPath, out.conf);
    writeFileSync(sanitizePath, out.sanitize);
    console.log(`check-csp: wrote the preview.css hash ${previewHash}`);
  }
  errors.push(...checkPreviewCss(css));
  errors.push(...checkPreviewRust(readFileSync(join(repo, SANITIZE_RS), "utf8"), previewHash));
  const base = JSON.parse(readFileSync(join(srcTauri, "tauri.conf.json"), "utf8"));
  const { overlays, errors: overlayErrors } = readOverlays(srcTauri);
  errors.push(...overlayErrors, ...checkConfigs(base, overlays, mainPolicy(previewHash)));
  errors.push(...checkRust(rustFiles(join(srcTauri, "src"), repo)));

  const uiDir = join(repo, "app", "ui");
  if (!existsSync(join(uiDir, "credential.html"))) {
    notes.push("check-csp: credential pages not present yet (app/ui/credential.html, Task 5)");
  } else {
    errors.push(...checkCredentialPages(readPages(uiDir), "app/ui"));
  }
  const distAt = argv.indexOf("--dist");
  if (distAt >= 0) {
    const dist = resolve(repo, argv[distAt + 1] ?? "app/ui/dist");
    if (!existsSync(dist)) errors.push(`--dist: ${dist} does not exist`);
    else if (existsSync(join(uiDir, "credential.html"))) {
      const built = readPages(dist);
      for (const name of Object.keys(readPages(uiDir))) {
        if (!(name in built)) errors.push(`dist/${name}: missing from the build`);
      }
      errors.push(...checkCredentialPages(built, "dist"));
    }
  }
  for (const n of notes) console.log(n);
  for (const e of errors) console.log(e);
  if (errors.length === 0) console.log("check-csp: ok");
  return errors.length === 0 ? 0 : 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
