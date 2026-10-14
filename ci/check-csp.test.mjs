// node --test ci/check-csp.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CREDENTIAL_POLICY,
  MAIN_POLICY,
  PLATFORMS,
  checkConfig,
  checkConfigs,
  checkCredentialPages,
  checkPolicy,
  checkRust,
  headMetaCsp,
  mergePatch,
  parsePolicy,
  readOverlays,
} from "./check-csp.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC_TAURI = join(REPO, "app", "src-tauri");

// ---------- fixtures ----------

function baseConf(security = {}) {
  return {
    productName: "Atlas Duck",
    app: {
      windows: [],
      security: {
        csp: MAIN_POLICY,
        freezePrototype: true,
        pattern: { use: "isolation", options: { dir: "../isolation" } },
        capabilities: ["approvals"],
        ...security,
      },
    },
  };
}

function assertFails(errors, pattern) {
  assert.ok(errors.length > 0, "expected a violation");
  assert.ok(
    errors.some((e) => pattern.test(e)),
    `no violation matches ${pattern}: ${JSON.stringify(errors)}`,
  );
}

const LIB_OK = `
pub fn run_gui() {
    let mut context = tauri::generate_context!();
    if csp::patch_context(&mut context).is_err() { std::process::exit(1); }
    let app = builder.build(context);
}
`;
const CSP_RS = `pub const ISOLATION_ORIGIN_PLACEHOLDER: &str = "<isolation-origin>";`;

function rustFiles(lib = LIB_OK, extra = {}) {
  return { "app/src-tauri/src/lib.rs": lib, "app/src-tauri/src/csp.rs": CSP_RS, ...extra };
}

function page(csp, before = "") {
  return `<!doctype html>\n<html lang="en">\n  <head>\n    ${before}<meta http-equiv="Content-Security-Policy" content="${csp}" />\n    <meta charset="utf-8" />\n    <script type="module" src="/src/credential/main.ts"></script>\n  </head>\n  <body></body>\n</html>\n`;
}

// ---------- the repository ----------

test("repository_config_passes_on_every_platform", () => {
  const base = JSON.parse(readFileSync(join(SRC_TAURI, "tauri.conf.json"), "utf8"));
  const { overlays, errors } = readOverlays(SRC_TAURI);
  assert.deepEqual(errors, []);
  assert.deepEqual(checkConfigs(base, overlays), []);
});

test("repository_rust_patches_the_isolation_origin", () => {
  const files = {};
  for (const name of ["lib.rs", "csp.rs"]) {
    files[`app/src-tauri/src/${name}`] = readFileSync(join(SRC_TAURI, "src", name), "utf8");
  }
  assert.deepEqual(checkRust(files), []);
});

test("spec_texts_parse", () => {
  const main = parsePolicy(MAIN_POLICY);
  assert.deepEqual(main.get("frame-src"), ["'self'", "<isolation-origin>"]);
  assert.deepEqual(main.get("frame-ancestors"), ["'none'"]);
  assert.deepEqual(main.get("connect-src"), ["ipc:", "http://ipc.localhost"]);
  const cred = parsePolicy(CREDENTIAL_POLICY);
  assert.deepEqual(cred.get("frame-src"), ["<isolation-origin>"]);
  assert.deepEqual(cred.get("default-src"), ["'none'"]);
  assert.equal(cred.has("frame-ancestors"), false, "a meta CSP cannot carry frame-ancestors");
});

// ---------- main policy (plan T4 step 1) ----------

test("windows_macos_linux_merged_values_pass", () => {
  assert.deepEqual(checkConfigs(baseConf(), {}), []);
  // An overlay that changes something else merges without touching the policy.
  const overlays = { linux: { productName: "atlas-duck" }, macos: { bundle: { active: true } } };
  assert.deepEqual(checkConfigs(baseConf(), overlays), []);
  for (const p of PLATFORMS) assert.deepEqual(checkConfig(mergePatch(baseConf(), overlays[p] ?? {}), p), []);
});

test("unsafe_inline_fixture_fails", () => {
  const csp = MAIN_POLICY.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'");
  assertFails(checkConfig(baseConf({ csp }), "linux"), /contains 'unsafe-inline'/);
  const eval_ = MAIN_POLICY.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'");
  assertFails(checkConfig(baseConf({ csp: eval_ }), "linux"), /contains 'unsafe-eval'/);
  const style = MAIN_POLICY.replace("style-src 'self'", "style-src 'self' 'UNSAFE-INLINE'");
  assertFails(checkConfig(baseConf({ csp: style }), "macos"), /unsafe-inline/);
});

test("missing_isolation_origin_in_frame_src_fails", () => {
  const csp = MAIN_POLICY.replace("frame-src 'self' <isolation-origin>", "frame-src 'self'");
  assertFails(checkConfig(baseConf({ csp }), "windows"), /frame-src does not name <isolation-origin>/);
  const noFrame = MAIN_POLICY.replace("frame-src 'self' <isolation-origin>; ", "");
  assertFails(checkConfig(baseConf({ csp: noFrame }), "windows"), /frame-src does not name/);
  // The spec's assumed static origins are not this build's (Tauri mints isolation-<uuid>).
  for (const origin of ["isolation://localhost", "http://isolation.localhost"]) {
    const fixed = MAIN_POLICY.replace("<isolation-origin>", origin);
    assertFails(checkConfig(baseConf({ csp: fixed }), "linux"), /frame-src does not name/);
  }
  const elsewhere = MAIN_POLICY.replace("default-src 'self'", "default-src 'self' <isolation-origin>");
  assertFails(checkConfig(baseConf({ csp: elsewhere }), "linux"), /exactly once/);
});

test("platform_overlay_is_merged_and_checked", () => {
  const weak = MAIN_POLICY.replace("object-src 'none'", "object-src 'none' 'unsafe-eval'");
  const errors = checkConfigs(baseConf(), { windows: { app: { security: { csp: weak } } } });
  assertFails(errors, /\(windows\) app\.security\.csp: CSP contains 'unsafe-eval'/);
  assert.ok(!errors.some((e) => /\((macos|linux)\)/.test(e)), JSON.stringify(errors));
  // A null in the overlay deletes the base policy (RFC 7396).
  assertFails(checkConfigs(baseConf(), { macos: { app: { security: { csp: null } } } }), /\(macos\) app\.security\.csp: no CSP/);
});

test("policy_differing_from_the_spec_text_fails", () => {
  for (const csp of [
    `${MAIN_POLICY}; connect-src https://evil.example`,
    MAIN_POLICY.replace("img-src 'self' data:", "img-src 'self' data: https:"),
    MAIN_POLICY.replace("; frame-ancestors 'none'", ""),
    MAIN_POLICY.replace("worker-src 'none'", "worker-src 'self'"),
    `${MAIN_POLICY}; script-src 'self'`,
  ]) {
    assert.ok(checkConfig(baseConf({ csp }), "linux").length > 0, csp);
  }
  // Whitespace is not a difference.
  assert.deepEqual(checkConfig(baseConf({ csp: MAIN_POLICY.replace(/; /g, " ;  ") }), "linux"), []);
});

test("use_https_scheme_true_fixture_fails", () => {
  const conf = baseConf();
  conf.app.windows = [{ label: "approvals", useHttpsScheme: true }];
  assertFails(checkConfig(conf, "windows"), /app\.windows\.0\.useHttpsScheme must stay unset/);
  assertFails(
    checkConfigs(baseConf(), { windows: { app: { windows: [{ "use-https-scheme": true }] } } }),
    /use-https-scheme must stay unset/,
  );
  assertFails(checkRust(rustFiles(LIB_OK, { "app/src-tauri/src/windows.rs": "b.use_https_scheme(true)" })), /use_https_scheme may only be called with false/);
  assertFails(checkRust(rustFiles(LIB_OK, { "app/src-tauri/src/windows.rs": "b.use_https_scheme(cfg!(windows))" })), /only be called with false/);
  assert.deepEqual(checkRust(rustFiles(LIB_OK, { "app/src-tauri/src/windows.rs": "b.use_https_scheme(false)" })), []);
});

test("other_security_settings_fail", () => {
  assertFails(checkConfig(baseConf({ devCsp: MAIN_POLICY }), "linux"), /devCsp must not be set/);
  assertFails(checkConfig(baseConf({ dangerousDisableAssetCspModification: true }), "linux"), /dangerousDisableAssetCspModification/);
  assertFails(checkConfig(baseConf({ dangerousDisableAssetCspModification: ["style-src"] }), "linux"), /dangerousDisableAssetCspModification/);
  assertFails(checkConfig(baseConf({ assetProtocol: { enable: true, scope: ["**"] } }), "linux"), /asset protocol/);
  assertFails(checkConfig(baseConf({ freezePrototype: false }), "linux"), /freezePrototype must be true/);
  assertFails(checkConfig(baseConf({ pattern: { use: "brownfield" } }), "linux"), /isolation pattern/);
});

test("the_app_must_patch_the_placeholder_before_building", () => {
  assert.deepEqual(checkRust(rustFiles()), []);
  assertFails(checkRust(rustFiles(LIB_OK.replace("csp::patch_context(&mut context)", "noop()"))), /must call csp::patch_context/);
  const late = `let mut context = tauri::generate_context!();\nlet app = builder.build(context);\ncsp::patch_context(&mut context);`;
  assertFails(checkRust(rustFiles(late)), /must call csp::patch_context/);
  assertFails(checkRust({ "app/src-tauri/src/lib.rs": LIB_OK, "app/src-tauri/src/csp.rs": 'pub const ISOLATION_ORIGIN_PLACEHOLDER: &str = "x";' }), /ISOLATION_ORIGIN_PLACEHOLDER/);
});

// ---------- credential pages ----------

test("credential_page_policy", () => {
  assert.deepEqual(checkCredentialPages({ "credential.html": page(CREDENTIAL_POLICY) }, "app/ui"), []);
  // An HTML comment before the meta tag is not an element.
  assert.deepEqual(checkCredentialPages({ "credential.html": page(CREDENTIAL_POLICY, "<!-- §10.3 -->\n    ") }, "app/ui"), []);
  assertFails(
    checkCredentialPages({ "credential.html": page(CREDENTIAL_POLICY, '<meta charset="utf-8" />\n    ') }, "app/ui"),
    /first <head> element is not the CSP meta tag/,
  );
  assertFails(
    checkCredentialPages({ "credential.html": page(CREDENTIAL_POLICY.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")) }, "dist"),
    /dist\/credential\.html: CSP contains 'unsafe-inline'/,
  );
  assertFails(
    checkCredentialPages({ "credential.html": page(CREDENTIAL_POLICY.replace("frame-src <isolation-origin>", "frame-src isolation://localhost")) }, "app/ui"),
    /frame-src does not name <isolation-origin>/,
  );
  assertFails(checkCredentialPages({ "credential.html": page(MAIN_POLICY) }, "app/ui"), /differs from the spec text/);
  assertFails(checkCredentialPages({ "credential.html": "<html><body></body></html>" }, "app/ui"), /no <head>/);
});

test("head_meta_csp_decodes_entities", () => {
  const html = page(CREDENTIAL_POLICY.replace(/'/g, "&#39;").replace("<isolation-origin>", "&lt;isolation-origin&gt;"));
  assert.equal(headMetaCsp(html).csp, CREDENTIAL_POLICY);
  assert.equal(checkPolicy(headMetaCsp(html).csp, CREDENTIAL_POLICY, "x").length, 0);
});

test("no_unreadable_overlay_formats_in_the_repository", () => {
  const names = readdirSync(SRC_TAURI).filter((n) => /^tauri\..+\.(json5|toml)$/i.test(n));
  assert.deepEqual(names, []);
});
