// node --test ci/check-workspace.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkGraph, checkManifests, lintLevel, scanToml } from "./check-workspace.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------- fixture metadata (shape of `cargo metadata --format-version 1`) ----------

const MEMBERS = [
  "atlas-duck-registry",
  "atlas-duck-core",
  "atlas-duck-atlassian",
  "atlas-duck-convert",
  "atlas-duck-preview",
  "atlas-duck-audit",
  "atlas-duck-ipc",
  "atlas-duck-sandbox-host",
  "atlas-duck-sandbox-worker",
  "atlas-duck-cli",
];

const memberId = (name) => `path+file:///ws/crates/${name}#${name}@0.1.0`;
const extId = (name, version = "1.0.0") =>
  `registry+https://github.com/rust-lang/crates.io-index#${name}@${version}`;

/** The M1 workspace graph after Task 1. */
function baseEdges() {
  return {
    "atlas-duck-registry": [],
    "atlas-duck-core": [
      "atlas-duck-registry",
      "atlas-duck-atlassian",
      "atlas-duck-convert",
      "atlas-duck-preview",
      "atlas-duck-audit",
      "atlas-duck-ipc",
    ],
    "atlas-duck-atlassian": [],
    "atlas-duck-convert": [],
    "atlas-duck-preview": [],
    "atlas-duck-audit": ["atlas-duck-ipc"],
    "atlas-duck-ipc": [],
    "atlas-duck-sandbox-host": ["atlas-duck-ipc"],
    "atlas-duck-sandbox-worker": [{ name: "atlas-duck-ipc", uses_default_features: false }],
    "atlas-duck-cli": ["atlas-duck-ipc", "atlas-duck-registry"],
  };
}

/**
 * edges: package name -> list of deps; a dep is a name or
 *   { name, kind?, req?, features?, uses_default_features? }.
 * Names not in MEMBERS (and not "atlas-duck-app") become crates.io packages.
 * resolvedFeatures: package name -> resolved feature list.
 */
function makeMetadata(edges, { extraMembers = [], resolvedFeatures = {} } = {}) {
  const members = [...MEMBERS, ...extraMembers];
  const isMember = (n) => members.includes(n);
  const idOf = (n) => (isMember(n) ? memberId(n) : extId(n));
  const names = new Set(Object.keys(edges));
  for (const deps of Object.values(edges)) for (const d of deps) names.add(typeof d === "string" ? d : d.name);
  const norm = (d) => ({
    kind: null,
    req: "*",
    features: [],
    uses_default_features: true,
    ...(typeof d === "string" ? { name: d } : d),
  });
  const packages = [...names].map((name) => ({
    name,
    id: idOf(name),
    manifest_path: `/ws/crates/${name}/Cargo.toml`,
    dependencies: (edges[name] ?? []).map((d) => {
      const n = norm(d);
      return {
        name: n.name,
        source: isMember(n.name) ? null : "registry+https://github.com/rust-lang/crates.io-index",
        req: n.req,
        kind: n.kind,
        rename: null,
        optional: false,
        uses_default_features: n.uses_default_features,
        features: n.features,
        target: null,
        registry: null,
      };
    }),
  }));
  const nodes = [...names].map((name) => ({
    id: idOf(name),
    dependencies: (edges[name] ?? []).map((d) => idOf(norm(d).name)),
    deps: (edges[name] ?? []).map((d) => {
      const n = norm(d);
      return { name: n.name.replace(/-/g, "_"), pkg: idOf(n.name), dep_kinds: [{ kind: n.kind, target: null }] };
    }),
    features: resolvedFeatures[name] ?? [],
  }));
  return {
    packages,
    workspace_members: members.map(memberId),
    resolve: { nodes, root: null },
    workspace_root: "/ws",
    version: 1,
  };
}

const graph = (edges, opts) => checkGraph(makeMetadata(edges, opts));

// ---------- fixture manifests ----------

const ROOT_OK = `[workspace]
resolver = "3"
members = [
    "crates/core", # comment
]

[workspace.package]
version = "0.1.0"

[profile.release]
panic = "abort"
`;
const LINTS_OK = `[package]
name = "x"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
`;
const manifests = (over = {}) => ({
  root: ROOT_OK,
  members: { "atlas-duck-core": LINTS_OK, "atlas-duck-atlassian": LINTS_OK },
  ...over,
});

// ---------- graph rules ----------

test("the M1 graph has no violations", () => {
  assert.deepEqual(graph(baseEdges()), []);
});

test("registry with any workspace dependency is a violation", () => {
  const e = baseEdges();
  e["atlas-duck-registry"] = ["atlas-duck-ipc"];
  assert.deepEqual(graph(e), ["atlas-duck-registry: must not depend on atlas-duck-ipc (§2.2)"]);
});

test("a build-dependency counts as a workspace edge; a dev-dependency does not", () => {
  const e = baseEdges();
  e["atlas-duck-registry"] = [{ name: "atlas-duck-ipc", kind: "build" }];
  assert.equal(graph(e).length, 1);
  e["atlas-duck-registry"] = [{ name: "atlas-duck-ipc", kind: "dev" }];
  assert.deepEqual(graph(e), []);
});

test("cli depending on core is a violation", () => {
  const e = baseEdges();
  e["atlas-duck-cli"].push("atlas-duck-core");
  assert.ok(graph(e).includes("atlas-duck-cli: must not depend on atlas-duck-core (§2.2)"));
});

test("sandbox-worker depending on registry is a violation", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"].push("atlas-duck-registry");
  assert.deepEqual(graph(e), ["atlas-duck-sandbox-worker: must not depend on atlas-duck-registry (§2.2)"]);
});

test("sandbox-worker must use ipc with default-features = false", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"] = ["atlas-duck-ipc"];
  assert.deepEqual(graph(e), [
    "atlas-duck-sandbox-worker: dependency on atlas-duck-ipc must set default-features = false",
  ]);
});

test("core workspace deps must be exactly the six §2.2 crates", () => {
  const missing = baseEdges();
  missing["atlas-duck-core"] = missing["atlas-duck-core"].filter((n) => n !== "atlas-duck-preview");
  const extra = baseEdges();
  extra["atlas-duck-core"].push("atlas-duck-sandbox-host");
  for (const e of [missing, extra]) {
    const v = graph(e);
    assert.equal(v.length, 1);
    assert.match(v[0], /^atlas-duck-core: workspace dependencies must be exactly \{/);
  }
});

for (const crate of ["tauri", "wry"]) {
  test(`a non-app package with ${crate} in its normal closure is a violation`, () => {
    const e = baseEdges();
    e["atlas-duck-audit"].push("some-gui-helper");
    e["some-gui-helper"] = [crate];
    const v = graph(e);
    assert.ok(v.includes(`atlas-duck-audit: ${crate} in normal-dependency closure; nothing but app depends on Tauri (§2.2)`));
    // core reaches it through audit, so core is reported too.
    assert.ok(v.some((l) => l.startsWith(`atlas-duck-core: ${crate} in normal-dependency closure`)));
  });
}

test("tauri reached only through a dev-dependency is not a violation", () => {
  const e = baseEdges();
  e["atlas-duck-audit"].push({ name: "tauri", kind: "dev" });
  assert.deepEqual(graph(e), []);
});

test("atlas-duck-app may depend on tauri", () => {
  const e = baseEdges();
  e["atlas-duck-app"] = ["tauri", "atlas-duck-cli", "atlas-duck-sandbox-worker", "atlas-duck-ipc"];
  e["tauri"] = ["wry"];
  assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), []);
});

const BANNED = [
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
];
for (const pkg of ["atlas-duck-cli", "atlas-duck-sandbox-worker"]) {
  for (const banned of BANNED) {
    test(`${pkg} with ${banned} in its closure (transitively) is a violation`, () => {
      const e = baseEdges();
      e[pkg].push("some-wrapper");
      e["some-wrapper"] = [banned];
      assert.deepEqual(graph(e), [`${pkg}: banned crate ${banned} in normal-dependency closure (§2.1)`]);
    });
  }
  for (const crate of ["tauri", "wry"]) {
    test(`${pkg} with ${crate} in its closure is a violation`, () => {
      const e = baseEdges();
      e[pkg].push(crate);
      assert.deepEqual(graph(e), [
        `${pkg}: ${crate} in normal-dependency closure; nothing but app depends on Tauri (§2.2)`,
      ]);
    });
  }
}

test("banned crates are allowed outside cli and sandbox-worker", () => {
  const e = baseEdges();
  e["atlas-duck-audit"].push("rusqlite");
  e["atlas-duck-atlassian"].push("reqwest");
  e["atlas-duck-audit"].push("keyring-core", "windows-native-keyring-store", "apple-native-keyring-store", "zbus-secret-service-keyring-store");
  assert.deepEqual(graph(e), []);
});

test("serde_jcs is allowed in the closure of cli and sandbox-worker", () => {
  const e = baseEdges();
  e["atlas-duck-ipc"].push("serde_jcs");
  e["serde_jcs"] = ["ryu-js"];
  assert.deepEqual(graph(e), []);
});

test("rquickjs pinned to =0.14.0 with allowed features is fine", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["macro"], uses_default_features: false });
  assert.deepEqual(graph(e, { resolvedFeatures: { rquickjs: ["macro"] } }), []);
});

test("rquickjs with a version req other than =0.14.0 is a violation", () => {
  for (const req of ["^0.14.0", "=0.13.0", "*"]) {
    const e = baseEdges();
    e["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req, features: ["macro"] });
    assert.deepEqual(graph(e), [
      `atlas-duck-sandbox-worker: rquickjs version req must be =0.14.0 (§9.3), found ${req}`,
    ]);
  }
});

for (const feature of ["loader", "dyn-load", "parallel"]) {
  test(`rquickjs feature ${feature} (declared or resolved) is a violation`, () => {
    const declared = baseEdges();
    declared["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["macro", feature] });
    assert.ok(graph(declared).includes(`atlas-duck-sandbox-worker: rquickjs feature ${feature} is not allowed (§9.3)`));

    const resolved = baseEdges();
    resolved["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["full"] });
    assert.ok(
      graph(resolved, { resolvedFeatures: { rquickjs: ["full", feature] } }).includes(
        `rquickjs: resolved feature ${feature} is not allowed (§9.3)`,
      ),
    );
  });
}

// `futures` is not a §9.3 ban: §9.3 leaves it to the plan with the M8 loop
// design. It is an M1-only rule, with its own message and no bare "(§9.3)".
test("rquickjs feature futures (declared or resolved) is an M1-only violation, not a §9.3 ban", () => {
  const declared = baseEdges();
  declared["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["macro", "futures"] });
  assert.deepEqual(graph(declared), [
    "atlas-duck-sandbox-worker: rquickjs feature futures is not allowed in M1: M8 decides (§9.3/§15)",
  ]);

  const resolved = baseEdges();
  resolved["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["full"] });
  assert.ok(
    graph(resolved, { resolvedFeatures: { rquickjs: ["full", "futures"] } }).includes(
      "rquickjs: resolved feature futures is not allowed in M1: M8 decides (§9.3/§15)",
    ),
  );
});

// ---------- manifest rules ----------

test("the M1 manifests have no violations", () => {
  assert.deepEqual(checkManifests(manifests()), []);
});

test('missing panic = "abort" in [profile.release] is a violation', () => {
  const want = ['workspace Cargo.toml: [profile.release] must set panic = "abort" (§7.7)'];
  for (const root of [
    ROOT_OK.replace('panic = "abort"', 'panic = "unwind"'),
    ROOT_OK.replace('panic = "abort"', '# panic = "abort"'),
    ROOT_OK.replace("[profile.release]", "[profile.dev]"),
  ]) {
    assert.deepEqual(checkManifests(manifests({ root })), want);
  }
});

for (const pkg of ["atlas-duck-core", "atlas-duck-atlassian"]) {
  for (const lint of ["unwrap_used", "expect_used"]) {
    test(`${pkg} without ${lint} = "deny" is a violation`, () => {
      const want = [`${pkg}: [lints.clippy] must set ${lint} = "deny" (§7.7, §13)`];
      for (const text of [
        LINTS_OK.replace(`${lint} = "deny"`, `${lint} = "warn"`),
        LINTS_OK.replace(`${lint} = "deny"\n`, ""),
      ]) {
        const m = manifests();
        m.members[pkg] = text;
        assert.deepEqual(checkManifests(m), want);
      }
    });
  }
  test(`${pkg} with the lints under the wrong table reports both lints`, () => {
    const m = manifests();
    m.members[pkg] = LINTS_OK.replace("[lints.clippy]", "[lints.rust]");
    assert.deepEqual(checkManifests(m), [
      `${pkg}: [lints.clippy] must set unwrap_used = "deny" (§7.7, §13)`,
      `${pkg}: [lints.clippy] must set expect_used = "deny" (§7.7, §13)`,
    ]);
  });
}

test("lint level accepts the table form and forbid; [lints] workspace = true reads workspace.lints", () => {
  assert.equal(lintLevel('{ level = "deny", priority = 1 }'), "deny");
  const m = manifests();
  m.members["atlas-duck-core"] = '[package]\nname = "x"\n\n[lints.clippy]\nunwrap_used = "forbid"\nexpect_used = { level = "deny" }\n';
  m.members["atlas-duck-atlassian"] = '[package]\nname = "y"\n\n[lints]\nworkspace = true\n';
  m.root = `${ROOT_OK}\n[workspace.lints.clippy]\nunwrap_used = "deny"\nexpect_used = "deny"\n`;
  assert.deepEqual(checkManifests(m), []);
});

test("scanToml ignores # inside strings and keeps sections apart", () => {
  const s = scanToml('[a]\nk = "x # y" # c\n[b.c]\nk = 1\n');
  assert.equal(s.get("a").get("k"), '"x # y"');
  assert.equal(s.get("b.c").get("k"), "1");
});

// ---------- the real workspace ----------

test("the real workspace passes: node ci/check-workspace.mjs exits 0", () => {
  const res = spawnSync(process.execPath, [join(REPO, "ci", "check-workspace.mjs")], { encoding: "utf8" });
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /^check-workspace: ok \(\d+ workspace members\)/);
  assert.equal(res.status, 0);
});
