#!/usr/bin/env node
// Workspace drift check (plan addition; the spec does not ask for it).
// Encodes: the §2.2 dependency rule (workspace-internal edges, Tauri only in
// `app`), the §2.1 "no HTTP client, keychain or DB code linked" rule for the
// sandbox worker and the CLI, the §9.3 rquickjs pin/feature limits, the §7.7
// release `panic = "abort"` profile, the §7.7/§13 clippy lints on core and
// atlassian, and the §13 test-only features (no normal edge, no default and no
// member feature outside TEST_FEATURE_FORWARDERS turns one on).
//
// Usage: node ci/check-workspace.mjs
// Exit 0 = ok. Exit 1 = violations (one per line on stdout), or cargo failed.
// No npm dependencies: node:child_process, node:fs, node:path, node:url only.

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const APP_PACKAGE = "atlas-duck-app";
export const PKG = {
  registry: "atlas-duck-registry",
  core: "atlas-duck-core",
  atlassian: "atlas-duck-atlassian",
  convert: "atlas-duck-convert",
  preview: "atlas-duck-preview",
  audit: "atlas-duck-audit",
  ipc: "atlas-duck-ipc",
  sandboxHost: "atlas-duck-sandbox-host",
  sandboxWorker: "atlas-duck-sandbox-worker",
  cli: "atlas-duck-cli",
  mcpTools: "atlas-duck-mcp-tools",
  server: "atlas-duck-server",
};

// §2.2, read as workspace-internal normal/build edges (dev-dependencies ignored).
// `exact`: the set must match; `allowed`: the set must be a subset.
export const INTERNAL_RULES = [
  { pkg: PKG.registry, allowed: [] },
  {
    pkg: PKG.core,
    exact: [PKG.registry, PKG.atlassian, PKG.convert, PKG.preview, PKG.audit, PKG.ipc],
  },
  // M5 final review M-10: leaf crates (§2.2): no workspace dependency.
  { pkg: PKG.convert, allowed: [] },
  { pkg: PKG.preview, allowed: [] },
  { pkg: PKG.cli, allowed: [PKG.ipc, PKG.registry, PKG.mcpTools] },
  { pkg: PKG.sandboxWorker, allowed: [PKG.ipc] },
  // M12 PD-192/PD-193: the shared MCP tool layer and the server binary.
  { pkg: PKG.mcpTools, allowed: [PKG.ipc, PKG.registry] },
  { pkg: PKG.server, allowed: [PKG.core, PKG.audit, PKG.atlassian, PKG.ipc, PKG.registry, PKG.mcpTools] },
];

// M12 (plan "Global Constraints"): crates only the server links. Checked per desktop package with
// `cargo tree` (per-package feature resolution), which the unified `cargo metadata` resolve cannot
// show. rmcp's server-http deps (`sse-stream`, `http-body`) are harmless and not listed.
export const SERVER_ONLY_CRATES = ["axum", "axum-core", "ldap3", "lber", "atlas-duck-server"];
export const DESKTOP_PACKAGES = [APP_PACKAGE, PKG.cli, PKG.sandboxHost, PKG.sandboxWorker];

// §13 / §7.7: features that only the test builds may enable. A normal or build dependency
// edge between workspace packages must not turn one on, directly or through default features.
export const TEST_ONLY_FEATURES = [
  "atlas-duck-atlassian/testing",
  "atlas-duck-atlassian/insecure-test-http",
  "atlas-duck-core/testing",
  "atlas-duck-audit/testing",
  "atlas-duck-cli/test-env",
  "atlas-duck-ipc/test-paths",
  "atlas-duck-app/scripted-approver",
  // M12 T10: the server's in-memory store and test constructors.
  "atlas-duck-server/testing",
];

// The only member features that may forward a test-only feature from their own `[features]`
// table (M4 plan "Test-only features and their locks"; closes M3 final review M-10's gap). No
// member's `default` may reach any test-only feature, forwarders included.
export const TEST_FEATURE_FORWARDERS = [
  "atlas-duck-app/scripted-approver",
  "atlas-duck-core/testing",
  "atlas-duck-atlassian/testing",
  // M12 T23: the integration tests run user runtimes against plain-HTTP mocks (core's hooks).
  "atlas-duck-server/testing",
];

// The registry stays a plain data crate: its normal dependencies are these and nothing else.
export const REGISTRY_EXTERNAL_ALLOW = ["serde", "serde_json"];

// §2.2: convert is pure; its normal dependencies are the CommonMark parser, the
// storage-format XML reader and the HTML-to-Markdown converter (§7.6).
export const CONVERT_EXTERNAL_ALLOW = ["pulldown-cmark", "quick-xml", "htmd"];

export const TAURI_CRATES = ["tauri", "wry"];

// §10.3: the webview gets no shell, filesystem, network, opener, clipboard or updater plugin.
export const APP_BANNED_DEPS = [
  "tauri-plugin-shell",
  "tauri-plugin-fs",
  "tauri-plugin-http",
  "tauri-plugin-opener",
  "tauri-plugin-clipboard-manager",
  "tauri-plugin-updater",
];

// §2.5: devtools stay off in every build.
export const TAURI_BANNED_FEATURES = ["devtools"];

// §2.1: sandbox "No HTTP client, keychain, or DB code linked"; CLI "Never
// touches keychain or DB" (HTTP client ban for the CLI is a plan addition).
// Names match exactly, so the keyring-core store crates that `audit` links are
// listed next to the `keyring` umbrella.
export const BANNED_IN_CLI_AND_WORKER = [
  "reqwest",
  "hyper",
  "rusqlite",
  "libsqlite3-sys",
  "keyring",
  "keyring-core",
  "windows-native-keyring-store",
  "apple-native-keyring-store",
  "zbus-secret-service-keyring-store",
  "secret-service",
  "security-framework",
  "tauri",
  "wry",
];

// §9.3: rquickjs pinned exact; never loader, dyn-load or parallel.
export const RQUICKJS_REQ = "=0.14.0";
// `futures` is not a §9.3 ban: §9.3 left it to the M8 loop design, which decided it off.
export const RQUICKJS_BANNED_FEATURES = ["loader", "dyn-load", "parallel", "futures"];
export const RQUICKJS_BAN_REASONS = {
  futures: "decided off in M8 (PD-131, §9.3/§15 V15)",
};

const rquickjsBanMessage = (subject, f, what = "rquickjs feature") =>
  `${subject}: ${what} ${f} is ${RQUICKJS_BAN_REASONS[f] ?? "not allowed (§9.3)"}`;

// M8 T1: the sandbox worker links these external crates and nothing else (normal and build
// edges). It gains no dependency in M8: no tokio, no async runtime.
export const WORKER_EXTERNAL_ALLOW = [
  "rquickjs",
  "serde_json",
  "libc",
  "windows-sys",
  "landlock",
  "seccompiler",
  "syscalls",
];

// §2.2 "nothing that reaches the network or the keychain": the host may use tokio and
// async-trait, but links no HTTP client, keyring, SQLite or Tauri/wry.
export const BANNED_IN_SANDBOX_HOST = BANNED_IN_CLI_AND_WORKER;

// PD-134 (plan review B-2): `#[global_allocator]` lives only in the sandbox binary and in tests.
export const GLOBAL_ALLOCATOR_FILES = ["app/src-tauri/src/bin/atlas-duck-sandbox.rs"];

// A `tests/` directory directly under a crate root (an integration-test target, never part of the
// library). `src/tests/` modules compile into the crate and are not exempt.
const CRATE_TESTS_DIR = /^(?:crates\/[^/]+|app\/src-tauri)\/tests\//;

export const LINT_PACKAGES = [PKG.core, PKG.atlassian, PKG.convert, PKG.mcpTools, PKG.server];
export const REQUIRED_DENY_LINTS = ["unwrap_used", "expect_used"];

const isNormalOrBuild = (kind) => kind === null || kind === undefined || kind === "build";

function packagesById(metadata) {
  return new Map(metadata.packages.map((p) => [p.id, p]));
}

function workspaceMembers(metadata) {
  const byId = packagesById(metadata);
  return metadata.workspace_members.map((id) => byId.get(id)).filter(Boolean);
}

/** Normal-dependency closure (package names) of the package with the given id. */
export function normalClosure(metadata, rootId) {
  const byId = packagesById(metadata);
  const nodes = new Map((metadata.resolve?.nodes ?? []).map((n) => [n.id, n]));
  const seen = new Set();
  const stack = [rootId];
  while (stack.length > 0) {
    const id = stack.pop();
    const node = nodes.get(id);
    if (!node) continue;
    for (const dep of node.deps ?? []) {
      const normal = (dep.dep_kinds ?? []).some((k) => k.kind === null);
      if (!normal || seen.has(dep.pkg)) continue;
      seen.add(dep.pkg);
      stack.push(dep.pkg);
    }
  }
  return new Set([...seen].map((id) => byId.get(id)?.name).filter(Boolean));
}

/**
 * Dependency-graph checks on `cargo metadata --format-version 1` output. `trees` (optional):
 * package name -> names in its own `cargo tree` (see cargoTreeNames). The metadata resolve unifies
 * features across the whole workspace, dev-dependencies included, so since M12 the server's
 * dev-only rmcp HTTP client puts reqwest/hyper under rmcp for every package; for a package listed
 * in `trees` the banned-crate checks use its own tree instead of the unified closure.
 */
export function checkGraph(metadata, trees = {}) {
  const violations = [];
  const members = workspaceMembers(metadata);
  const memberNames = new Set(members.map((p) => p.name));
  const byName = new Map(members.map((p) => [p.name, p]));

  for (const rule of INTERNAL_RULES) {
    const pkg = byName.get(rule.pkg);
    if (!pkg) {
      violations.push(`${rule.pkg}: missing from the workspace`);
      continue;
    }
    const internal = [
      ...new Set(
        pkg.dependencies
          .filter((d) => isNormalOrBuild(d.kind) && memberNames.has(d.name))
          .map((d) => d.name),
      ),
    ].sort();
    if (rule.exact) {
      const want = [...rule.exact].sort();
      if (internal.join(",") !== want.join(",")) {
        violations.push(
          `${rule.pkg}: workspace dependencies must be exactly {${want.join(", ")}} (§2.2), found {${internal.join(", ")}}`,
        );
      }
    } else {
      for (const name of internal) {
        if (!rule.allowed.includes(name)) {
          violations.push(`${rule.pkg}: must not depend on ${name} (§2.2)`);
        }
      }
    }
  }

  for (const pkg of members) {
    for (const d of pkg.dependencies) {
      if (!isNormalOrBuild(d.kind) || !memberNames.has(d.name)) continue;
      const target = byName.get(d.name);
      const enabled = new Set(d.features ?? []);
      if (d.uses_default_features !== false) enabled.add("default");
      // Expand feature-to-feature edges inside the target package ("a = [\"b\"]"); `dep:` and
      // `pkg/feat` entries leave the package and are not followed.
      const stack = [...enabled];
      while (stack.length > 0) {
        const feature = stack.pop();
        for (const e of target?.features?.[feature] ?? []) {
          if (!e.includes("/") && !e.startsWith("dep:") && !enabled.has(e)) {
            enabled.add(e);
            stack.push(e);
          }
        }
      }
      for (const f of enabled) {
        if (TEST_ONLY_FEATURES.includes(`${d.name}/${f}`)) {
          violations.push(`${pkg.name}: normal dependency enables test-only feature ${d.name}/${f}`);
        }
      }
    }
  }

  for (const pkg of members) {
    violations.push(...checkFeatureForwarding(pkg));
  }

  // M12: nothing in the workspace depends on the server binary crate.
  for (const pkg of members) {
    if (pkg.name === PKG.server) continue;
    if (pkg.dependencies.some((d) => d.name === PKG.server && isNormalOrBuild(d.kind))) {
      violations.push(`${pkg.name}: must not depend on ${PKG.server} (M12 PD-192)`);
    }
  }

  const registry = byName.get(PKG.registry);
  for (const d of registry?.dependencies ?? []) {
    if (isNormalOrBuild(d.kind) && !memberNames.has(d.name) && !REGISTRY_EXTERNAL_ALLOW.includes(d.name)) {
      violations.push(`${PKG.registry}: external normal dependency ${d.name} is not allowed; only ${REGISTRY_EXTERNAL_ALLOW.join(", ")} (§2.2)`);
    }
  }

  const convert = byName.get(PKG.convert);
  for (const d of convert?.dependencies ?? []) {
    if (isNormalOrBuild(d.kind) && !memberNames.has(d.name) && !CONVERT_EXTERNAL_ALLOW.includes(d.name)) {
      violations.push(`${PKG.convert}: external dependency ${d.name} not allowed`);
    }
  }

  // The worker uses ipc types only: the tokio-based `async` feature stays off.
  const worker = byName.get(PKG.sandboxWorker);
  for (const d of worker?.dependencies ?? []) {
    if (d.name === PKG.ipc && isNormalOrBuild(d.kind) && d.uses_default_features !== false) {
      violations.push(`${PKG.sandboxWorker}: dependency on ${PKG.ipc} must set default-features = false`);
    }
    if (isNormalOrBuild(d.kind) && !memberNames.has(d.name)) {
      if (!WORKER_EXTERNAL_ALLOW.includes(d.name)) {
        violations.push(
          `${PKG.sandboxWorker}: external dependency ${d.name} is not allowed; only ${WORKER_EXTERNAL_ALLOW.join(", ")} (M8 T1)`,
        );
      } else if (!d.source?.startsWith("registry+")) {
        // A path or git dependency (source null / git+...) named like an allowed crate is not it.
        violations.push(
          `${PKG.sandboxWorker}: external dependency ${d.name} must come from a registry, found ${d.source ?? "a path"} (M8 T1)`,
        );
      }
    }
  }

  for (const pkg of members) {
    const unified = normalClosure(metadata, pkg.id);
    const closure = trees[pkg.name] ? new Set(trees[pkg.name].filter((n) => n !== pkg.name)) : unified;
    if (pkg.name !== APP_PACKAGE) {
      for (const t of TAURI_CRATES) {
        if (closure.has(t)) {
          violations.push(`${pkg.name}: ${t} in normal-dependency closure; nothing but app depends on Tauri (§2.2)`);
        }
      }
    }
    if (pkg.name === PKG.cli || pkg.name === PKG.sandboxWorker) {
      for (const b of BANNED_IN_CLI_AND_WORKER) {
        if (TAURI_CRATES.includes(b) && closure.has(b)) continue; // reported above
        if (closure.has(b)) {
          violations.push(`${pkg.name}: banned crate ${b} in normal-dependency closure (§2.1)`);
        }
      }
    }
    if (pkg.name === PKG.sandboxHost) {
      for (const b of BANNED_IN_SANDBOX_HOST) {
        if (TAURI_CRATES.includes(b) && closure.has(b)) continue; // reported above
        if (closure.has(b)) {
          violations.push(`${pkg.name}: banned crate ${b} in normal-dependency closure (§2.2)`);
        }
      }
    }
    for (const d of pkg.dependencies) {
      if (pkg.name === APP_PACKAGE && APP_BANNED_DEPS.includes(d.name)) {
        violations.push(`${APP_PACKAGE}: dependency ${d.name} is banned (§10.3)`);
      }
      if (d.name === "tauri") {
        for (const f of d.features ?? []) {
          if (TAURI_BANNED_FEATURES.includes(f)) {
            violations.push(`tauri feature ${f} must not be enabled (§2.5)`);
          }
        }
      }
      if (d.name !== "rquickjs") continue;
      if (d.req !== RQUICKJS_REQ) {
        violations.push(`${pkg.name}: rquickjs version req must be ${RQUICKJS_REQ} (§9.3), found ${d.req}`);
      }
      for (const f of d.features ?? []) {
        if (RQUICKJS_BANNED_FEATURES.includes(f)) violations.push(rquickjsBanMessage(pkg.name, f));
      }
    }
  }

  // Resolved features catch defaults and feature-to-feature activation.
  const byId = packagesById(metadata);
  for (const node of metadata.resolve?.nodes ?? []) {
    if (byId.get(node.id)?.name !== "rquickjs") continue;
    for (const f of node.features ?? []) {
      if (RQUICKJS_BANNED_FEATURES.includes(f)) {
        violations.push(rquickjsBanMessage("rquickjs", f, "resolved feature"));
      }
    }
  }

  return [...new Set(violations)];
}

/**
 * The `package/feature` a `[features]` entry of `pkg` turns on: `feat` -> `<pkg>/feat`,
 * `dep/feat` and `dep?/feat` -> `<package of dep>/feat` (a renamed dependency is resolved to its
 * package); `dep:x` turns on no feature (null).
 */
export function featureTarget(pkg, entry) {
  if (entry.startsWith("dep:")) return null;
  const slash = entry.indexOf("/");
  if (slash < 0) return `${pkg.name}/${entry}`;
  const dep = entry.slice(0, slash).replace(/\?$/, "");
  const feature = entry.slice(slash + 1);
  const d = (pkg.dependencies ?? []).find((x) => (x.rename ?? x.name) === dep);
  return `${d ? d.name : dep}/${feature}`;
}

/** Every `package/feature` that `feature` of `pkg` turns on, following its own features. */
export function featureReach(pkg, feature) {
  const reached = new Set();
  const seen = new Set([feature]);
  const stack = [feature];
  const own = `${pkg.name}/`;
  while (stack.length > 0) {
    for (const entry of pkg.features?.[stack.pop()] ?? []) {
      const target = featureTarget(pkg, entry);
      if (target === null) continue;
      reached.add(target);
      const local = target.startsWith(own) ? target.slice(own.length) : null;
      if (local !== null && !seen.has(local)) {
        seen.add(local);
        stack.push(local);
      }
    }
  }
  return reached;
}

/**
 * A member's own `[features]` table: only TEST_FEATURE_FORWARDERS may turn on a test-only
 * feature, and `default` may reach none.
 */
export function checkFeatureForwarding(pkg) {
  const violations = [];
  for (const feature of Object.keys(pkg.features ?? {})) {
    const testOnly = [...featureReach(pkg, feature)].filter((t) => TEST_ONLY_FEATURES.includes(t)).sort();
    if (feature === "default") {
      for (const t of testOnly) {
        violations.push(`${pkg.name}: default feature reaches test-only feature ${t} (§13)`);
      }
      continue;
    }
    if (TEST_FEATURE_FORWARDERS.includes(`${pkg.name}/${feature}`)) continue;
    for (const t of testOnly) {
      violations.push(
        `${pkg.name}: feature ${feature} forwards test-only feature ${t}; only ${TEST_FEATURE_FORWARDERS.join(", ")} may (§13)`,
      );
    }
  }
  return violations;
}

/**
 * Minimal TOML section scanner: maps "[section]" names to { key: rawValue }.
 * Handles `key = value` lines and `#` comments; arrays of tables and multi-line
 * values are skipped. Enough for the profile and lint tables checked below.
 */
export function scanToml(text) {
  const sections = new Map([["", new Map()]]);
  let current = sections.get("");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = stripComment(rawLine).trim();
    if (line === "") continue;
    const header = /^\[([^[\]]+)\]$/.exec(line);
    if (header) {
      const name = header[1].replace(/\s+/g, "");
      if (!sections.has(name)) sections.set(name, new Map());
      current = sections.get(name);
      continue;
    }
    if (line.startsWith("[[")) {
      current = new Map(); // array of tables: not inspected
      continue;
    }
    const kv = /^([A-Za-z0-9_.\-"']+)\s*=\s*(.+)$/.exec(line);
    if (kv) current.set(kv[1].replace(/["']/g, ""), kv[2].trim());
  }
  return sections;
}

function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

/** "deny" | 'deny' | { level = "deny", ... } -> "deny"; forbid counts as deny. */
export function lintLevel(raw) {
  if (raw === undefined) return undefined;
  const plain = /^["']([a-z]+)["']$/.exec(raw);
  const table = /level\s*=\s*["']([a-z]+)["']/.exec(raw);
  return (plain ?? table)?.[1];
}

const isDeny = (raw) => ["deny", "forbid"].includes(lintLevel(raw));

/**
 * Manifest checks.
 * @param {{ root: string, members: Record<string, string> }} manifests
 *   root = workspace Cargo.toml text; members = package name -> Cargo.toml text.
 */
export function checkManifests({ root, members }) {
  const violations = [];
  const rootToml = scanToml(root);
  const panic = rootToml.get("profile.release")?.get("panic");
  if (panic !== '"abort"' && panic !== "'abort'") {
    violations.push('workspace Cargo.toml: [profile.release] must set panic = "abort" (§7.7)');
  }
  // T21 review I-2: `debug-assertions` in a release profile would let the test-only features
  // (their `compile_error!` locks key on `not(debug_assertions)`) into a shipped build.
  // Every profile table counts, not just `release`: a custom profile that inherits release (and
  // is selected with `--profile`) ships the same binaries. Only dev and test stay open: the locks
  // exist because those are the debug-assertion profiles.
  for (const [section, keys] of rootToml) {
    const profile = /^profile\.("[^"]*"|'[^']*'|[^.]+)/.exec(section)?.[1]?.replace(/["']/g, "");
    if (profile === undefined || profile === "dev" || profile === "test") continue;
    for (const [key, value] of keys) {
      if (key.split(".").pop() === "debug-assertions" && value !== "false") {
        violations.push(
          `workspace Cargo.toml: [${section}] must not set debug-assertions (T21 I-2: it defeats the release locks of the test-only features)`,
        );
      }
    }
  }
  for (const name of LINT_PACKAGES) {
    const text = members[name];
    if (text === undefined) {
      violations.push(`${name}: manifest not found`);
      continue;
    }
    const toml = scanToml(text);
    const inherits = toml.get("lints")?.get("workspace") === "true";
    const clippy = inherits ? rootToml.get("workspace.lints.clippy") : toml.get("lints.clippy");
    for (const lint of REQUIRED_DENY_LINTS) {
      if (!isDeny(clippy?.get(lint))) {
        violations.push(`${name}: [lints.clippy] must set ${lint} = "deny" (§7.7, §13)`);
      }
    }
  }
  return violations;
}

/**
 * `#[global_allocator]` source scan (PD-134). `files`: [{ path, text }] with repo-relative paths.
 * Allowed only in GLOBAL_ALLOCATOR_FILES and in files under a crate's own `tests/` directory
 * (`crates/<name>/tests/`, `app/src-tauri/tests/`).
 */
export function checkGlobalAllocators(files) {
  const violations = [];
  for (const { path, text } of files) {
    const p = path.replace(/\\/g, "/");
    if (GLOBAL_ALLOCATOR_FILES.includes(p) || CRATE_TESTS_DIR.test(p)) continue;
    // Any attribute that names `global_allocator`: plain, path-qualified, or inside `cfg_attr(...)`.
    if (/#\s*!?\s*\[[^\]]*\bglobal_allocator\b/.test(blankCommentsAndStrings(text))) {
      violations.push(
        `${p}: #[global_allocator] is allowed only in ${GLOBAL_ALLOCATOR_FILES.join(", ")} and under tests/ (PD-134)`,
      );
    }
  }
  return violations;
}

/**
 * Rust source with comments (line, nested block) and string/char literal contents blanked, so a
 * commented-out or quoted `#[global_allocator]` does not count and `"//"` or `"/*"` in a string
 * does not start a comment. Newlines are kept. Raw strings (`r#"..."#`) are handled.
 */
export function blankCommentsAndStrings(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  const blank = (s) => s.replace(/[^\n]/g, " ");
  while (i < n) {
    const rest = text.slice(i, i + 2);
    if (rest === "//") {
      const end = text.indexOf("\n", i);
      const stop = end < 0 ? n : end;
      out += blank(text.slice(i, stop));
      i = stop;
    } else if (rest === "/*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (text.startsWith("/*", j)) (depth++, (j += 2));
        else if (text.startsWith("*/", j)) (depth--, (j += 2));
        else j++;
      }
      out += blank(text.slice(i, j));
      i = j;
    } else {
      const raw = /^b?r(#*)"/.exec(text.slice(i, i + 20));
      if (raw && !/[A-Za-z0-9_]/.test(text[i - 1] ?? "")) {
        const close = `"${raw[1]}`;
        const end = text.indexOf(close, i + raw[0].length);
        const stop = end < 0 ? n : end + close.length;
        out += blank(text.slice(i, stop));
        i = stop;
      } else if (text[i] === '"') {
        let j = i + 1;
        while (j < n && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
        out += blank(text.slice(i, j + 1));
        i = j + 1;
      } else {
        // A char literal ('x', '\n', '"') is blanked; a lifetime ('a) is left alone.
        const ch = /^'(?:\\[^']+|[^\\'])'/.exec(text.slice(i, i + 12));
        if (ch) {
          out += blank(ch[0]);
          i += ch[0].length;
        } else {
          out += text[i];
          i++;
        }
      }
    }
  }
  return out;
}

// Never scanned: build output and dependency trees. Matched against repo-relative paths from the
// repo root, so a crate directory that happens to be named `target` or `dist` is still scanned.
const SCAN_SKIP_PATHS = new Set(["target", "node_modules", ".git", "app/ui/dist", "app/ui/node_modules"]);

/** Every `.rs` file under `root` (repo-relative paths), skipping build and dependency dirs. */
export function collectRustFiles(root, rel = "") {
  const out = [];
  for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
    const path = rel === "" ? e.name : `${rel}/${e.name}`;
    if (e.isDirectory()) {
      if (!SCAN_SKIP_PATHS.has(path)) out.push(...collectRustFiles(root, path));
    } else if (e.name.endsWith(".rs")) {
      out.push({ path, text: readFileSync(join(root, path), "utf8") });
    }
  }
  return out;
}

/**
 * Server-only crates in the desktop packages' own trees (M12). `trees`: package name -> the
 * package names `cargo tree -p <pkg> -e normal,build --prefix none -f "{p}"` printed for it.
 */
export function checkDesktopTrees(trees) {
  const violations = [];
  for (const [pkg, names] of Object.entries(trees)) {
    for (const name of SERVER_ONLY_CRATES) {
      if (names.includes(name)) violations.push(`${pkg}: links server-only crate ${name}`);
    }
  }
  return violations;
}

/** Package names in one package's normal+build tree over every target (per-package features). */
export function cargoTreeNames(manifestPath, pkg) {
  const res = spawnSync(
    "cargo",
    [
      "tree", "-p", pkg, "-e", "normal,build", "--target", "all", "--prefix", "none",
      "-f", "{p}", "--locked", "--manifest-path", manifestPath,
    ],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`cargo tree -p ${pkg} failed (exit ${res.status}): ${res.stderr.trim()}`);
  }
  // "{p}" prints "name vX.Y.Z (path)" plus " (*)" for repeats; the name is the first word.
  return [...new Set(res.stdout.split(/\r?\n/).map((l) => l.trim().split(" ")[0]).filter(Boolean))];
}

export function cargoMetadata(manifestPath) {
  const res = spawnSync(
    "cargo",
    ["metadata", "--format-version", "1", "--locked", "--manifest-path", manifestPath],
    { encoding: "utf8", maxBuffer: 512 * 1024 * 1024 },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`cargo metadata failed (exit ${res.status}): ${res.stderr.trim()}`);
  }
  return JSON.parse(res.stdout);
}

export function main() {
  const rootManifest = join(dirname(fileURLToPath(import.meta.url)), "..", "Cargo.toml");
  let metadata;
  try {
    metadata = cargoMetadata(rootManifest);
  } catch (err) {
    console.log(`check-workspace: ${err.message}`);
    return 1;
  }
  const members = {};
  for (const pkg of workspaceMembers(metadata)) {
    members[pkg.name] = readFileSync(pkg.manifest_path, "utf8");
  }
  const trees = {};
  try {
    for (const pkg of DESKTOP_PACKAGES) trees[pkg] = cargoTreeNames(rootManifest, pkg);
  } catch (err) {
    console.log(`check-workspace: ${err.message}`);
    return 1;
  }
  const violations = [
    ...checkDesktopTrees(trees),
    ...checkGraph(metadata, trees),
    ...checkManifests({ root: readFileSync(join(metadata.workspace_root, "Cargo.toml"), "utf8"), members }),
    ...checkGlobalAllocators(collectRustFiles(metadata.workspace_root)),
  ];
  for (const v of violations) console.log(v);
  if (violations.length > 0) return 1;
  console.error(`check-workspace: ok (${Object.keys(members).length} workspace members)`);
  return 0;
}

function isMain() {
  if (!process.argv[1]) return false;
  const self = realpathSync(fileURLToPath(import.meta.url));
  const invoked = realpathSync(process.argv[1]);
  return process.platform === "win32" ? self.toLowerCase() === invoked.toLowerCase() : self === invoked;
}

if (isMain()) {
  process.exitCode = main();
}
