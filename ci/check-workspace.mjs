#!/usr/bin/env node
// Workspace drift check (plan addition; the spec does not ask for it).
// Encodes: the §2.2 dependency rule (workspace-internal edges, Tauri only in
// `app`), the §2.1 "no HTTP client, keychain or DB code linked" rule for the
// sandbox worker and the CLI, the §9.3 rquickjs pin/feature limits, the §7.7
// release `panic = "abort"` profile and the §7.7/§13 clippy lints on core and
// atlassian.
//
// Usage: node ci/check-workspace.mjs
// Exit 0 = ok. Exit 1 = violations (one per line on stdout), or cargo failed.
// No npm dependencies: node:child_process, node:fs, node:path, node:url only.

import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
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
};

// §2.2, read as workspace-internal normal/build edges (dev-dependencies ignored).
// `exact`: the set must match; `allowed`: the set must be a subset.
export const INTERNAL_RULES = [
  { pkg: PKG.registry, allowed: [] },
  {
    pkg: PKG.core,
    exact: [PKG.registry, PKG.atlassian, PKG.convert, PKG.preview, PKG.audit, PKG.ipc],
  },
  { pkg: PKG.cli, allowed: [PKG.ipc, PKG.registry] },
  { pkg: PKG.sandboxWorker, allowed: [PKG.ipc] },
];

export const TAURI_CRATES = ["tauri", "wry"];

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
export const RQUICKJS_BANNED_FEATURES = ["loader", "dyn-load", "parallel"];
// Not a §9.3 ban: §9.3 leaves `futures` to the implementation plan together
// with the M8 loop design (§15, M8). M1 keeps it off (Task 14). M8 lifts this
// rule by emptying the list.
export const RQUICKJS_M1_BANNED_FEATURES = ["futures"];
export const RQUICKJS_M1_BAN_REASON = "not allowed in M1: M8 decides (§9.3/§15)";

export const LINT_PACKAGES = [PKG.core, PKG.atlassian];
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

/** Dependency-graph checks on `cargo metadata --format-version 1` output. */
export function checkGraph(metadata) {
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

  // The worker uses ipc types only: the tokio-based `async` feature stays off.
  const worker = byName.get(PKG.sandboxWorker);
  for (const d of worker?.dependencies ?? []) {
    if (d.name === PKG.ipc && isNormalOrBuild(d.kind) && d.uses_default_features !== false) {
      violations.push(`${PKG.sandboxWorker}: dependency on ${PKG.ipc} must set default-features = false`);
    }
  }

  for (const pkg of members) {
    const closure = normalClosure(metadata, pkg.id);
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
    for (const d of pkg.dependencies) {
      if (d.name !== "rquickjs") continue;
      if (d.req !== RQUICKJS_REQ) {
        violations.push(`${pkg.name}: rquickjs version req must be ${RQUICKJS_REQ} (§9.3), found ${d.req}`);
      }
      for (const f of d.features ?? []) {
        if (RQUICKJS_BANNED_FEATURES.includes(f)) {
          violations.push(`${pkg.name}: rquickjs feature ${f} is not allowed (§9.3)`);
        } else if (RQUICKJS_M1_BANNED_FEATURES.includes(f)) {
          violations.push(`${pkg.name}: rquickjs feature ${f} is ${RQUICKJS_M1_BAN_REASON}`);
        }
      }
    }
  }

  // Resolved features catch defaults and feature-to-feature activation.
  const byId = packagesById(metadata);
  for (const node of metadata.resolve?.nodes ?? []) {
    if (byId.get(node.id)?.name !== "rquickjs") continue;
    for (const f of node.features ?? []) {
      if (RQUICKJS_BANNED_FEATURES.includes(f)) {
        violations.push(`rquickjs: resolved feature ${f} is not allowed (§9.3)`);
      } else if (RQUICKJS_M1_BANNED_FEATURES.includes(f)) {
        violations.push(`rquickjs: resolved feature ${f} is ${RQUICKJS_M1_BAN_REASON}`);
      }
    }
  }

  return [...new Set(violations)];
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
  const violations = [
    ...checkGraph(metadata),
    ...checkManifests({ root: readFileSync(join(metadata.workspace_root, "Cargo.toml"), "utf8"), members }),
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
