// node --test ci/check-workspace.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BANNED_IN_SANDBOX_HOST,
  GLOBAL_ALLOCATOR_FILES,
  LINT_PACKAGES,
  SERVER_ONLY_CRATES,
  TEST_FEATURE_FORWARDERS,
  TEST_ONLY_FEATURES,
  WORKER_EXTERNAL_ALLOW,
  checkDesktopTrees,
  checkGlobalAllocators,
  checkGraph,
  checkManifests,
  collectRustFiles,
  lintLevel,
  scanToml,
} from "./check-workspace.mjs";

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
  "atlas-duck-mcp-tools",
  "atlas-duck-server",
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
    "atlas-duck-cli": ["atlas-duck-ipc", "atlas-duck-registry", "atlas-duck-mcp-tools"],
    "atlas-duck-mcp-tools": [{ name: "atlas-duck-ipc", uses_default_features: false }, "atlas-duck-registry"],
    "atlas-duck-server": [
      "atlas-duck-core",
      "atlas-duck-audit",
      "atlas-duck-atlassian",
      "atlas-duck-ipc",
      "atlas-duck-registry",
      "atlas-duck-mcp-tools",
    ],
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
        source:
          n.source !== undefined
            ? n.source
            : isMember(n.name)
              ? null
              : "registry+https://github.com/rust-lang/crates.io-index",
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
  members: {
    "atlas-duck-core": LINTS_OK,
    "atlas-duck-atlassian": LINTS_OK,
    "atlas-duck-convert": LINTS_OK,
    "atlas-duck-mcp-tools": LINTS_OK,
    "atlas-duck-server": LINTS_OK,
  },
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

test("app banned plugin dependency is rejected", () => {
  for (const banned of [
    "tauri-plugin-shell",
    "tauri-plugin-fs",
    "tauri-plugin-http",
    "tauri-plugin-opener",
    "tauri-plugin-clipboard-manager",
    "tauri-plugin-updater",
  ]) {
    const e = baseEdges();
    e["atlas-duck-app"] = ["tauri", banned];
    assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), [
      `atlas-duck-app: dependency ${banned} is banned (§10.3)`,
    ]);
  }
  // The notification plugin is the one allowed plugin besides dialog, single-instance, autostart.
  const e = baseEdges();
  e["atlas-duck-app"] = ["tauri", "tauri-plugin-notification"];
  assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), []);
});

test("tauri devtools feature is rejected", () => {
  const e = baseEdges();
  e["atlas-duck-app"] = [{ name: "tauri", features: ["tray-icon", "isolation", "devtools"] }];
  assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), [
    "tauri feature devtools must not be enabled (§2.5)",
  ]);
  e["atlas-duck-app"] = [{ name: "tauri", features: ["tray-icon", "isolation"] }];
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
      // The worker's direct external edges are allow-listed (M8 T1), so the wrapper is an allowed name.
      const wrapper = pkg === "atlas-duck-sandbox-worker" ? "serde_json" : "some-wrapper";
      e[pkg].push(wrapper);
      e[wrapper] = [banned];
      assert.deepEqual(graph(e), [`${pkg}: banned crate ${banned} in normal-dependency closure (§2.1)`]);
    });
  }
  for (const crate of ["tauri", "wry"]) {
    test(`${pkg} with ${crate} in its closure is a violation`, () => {
      const e = baseEdges();
      if (pkg === "atlas-duck-sandbox-worker") {
        e[pkg].push("serde_json");
        e["serde_json"] = [crate];
      } else {
        e[pkg].push(crate);
      }
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

// `futures` is not a §9.3 ban: §9.3 left it to the M8 loop design, which decided it off. It has
// its own reason and no bare "(§9.3)".
test("rquickjs futures is banned with the M8 reason", () => {
  const declared = baseEdges();
  declared["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["macro", "futures"] });
  assert.deepEqual(graph(declared), [
    "atlas-duck-sandbox-worker: rquickjs feature futures is decided off in M8 (PD-131, §9.3/§15 V15)",
  ]);

  const resolved = baseEdges();
  resolved["atlas-duck-sandbox-worker"].push({ name: "rquickjs", req: "=0.14.0", features: ["full"] });
  assert.ok(
    graph(resolved, { resolvedFeatures: { rquickjs: ["full", "futures"] } }).includes(
      "rquickjs: resolved feature futures is decided off in M8 (PD-131, §9.3/§15 V15)",
    ),
  );
});

// ---------- M8 Task 1: worker allow-list, host ban list, global allocator scan ----------

test("sandbox-worker may link exactly the allowed external crates", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"].push(
    { name: "rquickjs", req: "=0.14.0", features: ["macro"], uses_default_features: false },
    "serde_json",
    "libc",
    "windows-sys",
    "landlock",
    "seccompiler",
    "syscalls",
    { name: "proptest", kind: "dev" },
  );
  assert.deepEqual(graph(e), []);
});

test("sandbox-worker gains no dependency (fixture adds tokio -> violation)", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"].push("tokio");
  assert.deepEqual(graph(e), [
    `atlas-duck-sandbox-worker: external dependency tokio is not allowed; only ${WORKER_EXTERNAL_ALLOW.join(", ")} (M8 T1)`,
  ]);
});

test("sandbox-worker with a build-dependency on tokio is a violation too", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-worker"].push({ name: "tokio", kind: "build" });
  assert.deepEqual(graph(e), [
    `atlas-duck-sandbox-worker: external dependency tokio is not allowed; only ${WORKER_EXTERNAL_ALLOW.join(", ")} (M8 T1)`,
  ]);
});

test("an allowed worker crate name from a path or git source is a violation", () => {
  for (const [source, found] of [
    [null, "a path"],
    ["git+https://example.com/serde_json?rev=abc#abc", "git+https://example.com/serde_json?rev=abc#abc"],
  ]) {
    const e = baseEdges();
    e["atlas-duck-sandbox-worker"].push({ name: "serde_json", source });
    assert.deepEqual(graph(e), [
      `atlas-duck-sandbox-worker: external dependency serde_json must come from a registry, found ${found} (M8 T1)`,
    ]);
  }
});

test("sandbox-host may use tokio and async-trait", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-host"].push("tokio", "async-trait", "serde", "serde_json", "libc", "windows-sys");
  assert.deepEqual(graph(e), []);
});

for (const banned of [...BANNED_IN_SANDBOX_HOST.filter((b) => !["tauri", "wry"].includes(b))]) {
  test(`sandbox-host may not link ${banned} (fixture adds it through a wrapper -> violation)`, () => {
    const e = baseEdges();
    e["atlas-duck-sandbox-host"].push("some-wrapper");
    e["some-wrapper"] = [banned];
    assert.deepEqual(graph(e), [`atlas-duck-sandbox-host: banned crate ${banned} in normal-dependency closure (§2.2)`]);
  });
}

test("sandbox-host may not link an HTTP client (fixture adds reqwest -> violation)", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-host"].push("reqwest");
  assert.deepEqual(graph(e), ["atlas-duck-sandbox-host: banned crate reqwest in normal-dependency closure (§2.2)"]);
});

test("sandbox-host with tauri in its closure is reported once, by the Tauri rule", () => {
  const e = baseEdges();
  e["atlas-duck-sandbox-host"].push("tauri");
  assert.deepEqual(graph(e), [
    "atlas-duck-sandbox-host: tauri in normal-dependency closure; nothing but app depends on Tauri (§2.2)",
  ]);
});

const ALLOC = "#[global_allocator]\nstatic A: Counting = Counting;\n";
const ALLOC_MSG = (p) =>
  `${p}: #[global_allocator] is allowed only in ${GLOBAL_ALLOCATOR_FILES.join(", ")} and under tests/ (PD-134)`;
const alloc = (path, text) => checkGlobalAllocators([{ path, text }]);

test("global_allocator outside the worker bin and tests is a violation", () => {
  assert.deepEqual(
    checkGlobalAllocators([
      { path: "crates/sandbox-worker/src/lib.rs", text: ALLOC },
      { path: "crates\\core\\src\\lib.rs", text: `fn x() {}\n    ${ALLOC}` },
    ]),
    [ALLOC_MSG("crates/sandbox-worker/src/lib.rs"), ALLOC_MSG("crates/core/src/lib.rs")],
  );
});

test("global_allocator is allowed in the sandbox bin and under a crate's tests/; comments and strings do not count", () => {
  assert.deepEqual(
    checkGlobalAllocators([
      ...GLOBAL_ALLOCATOR_FILES.map((path) => ({ path, text: ALLOC })),
      { path: "crates/core/tests/budget.rs", text: ALLOC },
      { path: "crates/sandbox-worker/tests/confined_scripts.rs", text: ALLOC },
      { path: "crates/core/tests/common/mod.rs", text: ALLOC },
      { path: "app/src-tauri/tests/app_alloc.rs", text: ALLOC },
      { path: "crates/sandbox-worker/src/lib.rs", text: "// #[global_allocator] lives in the bin\n" },
      { path: "crates/a/src/b.rs", text: "/*\n#[global_allocator]\n*/\nfn f() {}\n" },
      { path: "crates/a/src/c.rs", text: "/* outer /* nested */ #[global_allocator] */\n" },
      { path: "crates/a/src/d.rs", text: 'const S: &str = "#[global_allocator]";\n' },
      { path: "crates/a/src/e.rs", text: 'const S: &str = r#"\n#[global_allocator]\n"#;\n' },
    ]),
    [],
  );
});

test("a tests directory that is not directly under a crate root is not exempt", () => {
  for (const path of [
    "crates/sandbox-worker/src/tests/x.rs",
    "crates/sandbox-worker/src/tests.rs/x.rs",
    "app/src-tauri/src/tests/x.rs",
    "crates/core/benches/tests/x.rs",
    "tests/x.rs",
    "other/tests/x.rs",
  ]) {
    assert.deepEqual(alloc(path, ALLOC), [ALLOC_MSG(path)], path);
  }
});

test("global_allocator bypasses: a slash before the attribute, cfg_attr, path-qualified", () => {
  for (const text of [
    `/* c */ ${ALLOC}`,
    `let u = a / b; ${ALLOC}`,
    "// c\n#[cfg_attr(not(test), global_allocator)]\nstatic A: Counting = Counting;\n",
    "#[core::prelude::v1::global_allocator]\nstatic A: Counting = Counting;\n",
    "#[ global_allocator ]\nstatic A: Counting = Counting;\n",
    '"//"; #[global_allocator] static A: Counting = Counting;\n',
    "fn f() {} // x\n/* y */ #[global_allocator] static A: Counting = Counting;\n",
    "fn f<'a>(x: &'a str) {}\n#[global_allocator] static A: Counting = Counting;\n",
    "const C: char = '\"';\n#[global_allocator] static A: Counting = Counting;\n",
  ]) {
    assert.deepEqual(alloc("crates/a/src/lib.rs", text), [ALLOC_MSG("crates/a/src/lib.rs")], text);
  }
});

test("collectRustFiles skips target/node_modules/.git at the root and app/ui/dist, not same-named crate dirs", () => {
  const root = mkdtempSync(join(REPO, "ci", ".scan-fixture-"));
  try {
    for (const p of [
      "target/a.rs",
      "node_modules/a.rs",
      ".git/a.rs",
      "app/ui/dist/a.rs",
      "app/ui/node_modules/a.rs",
      "crates/dist/src/a.rs",
      "crates/target/src/a.rs",
      "crates/x/target/a.rs",
      "crates/x/src/lib.rs",
    ]) {
      mkdirSync(dirname(join(root, p)), { recursive: true });
      writeFileSync(join(root, p), "");
    }
    assert.deepEqual(
      collectRustFiles(root)
        .map((f) => f.path)
        .sort(),
      ["crates/dist/src/a.rs", "crates/target/src/a.rs", "crates/x/src/lib.rs", "crates/x/target/a.rs"],
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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

test("debug-assertions in [profile.release] or a release package override is a violation", () => {
  const bad = (section) =>
    `workspace Cargo.toml: [${section}] must not set debug-assertions (T21 I-2: it defeats the release locks of the test-only features)`;
  const cases = [
    [ROOT_OK.replace('panic = "abort"', 'panic = "abort"\ndebug-assertions = true'), ["profile.release"]],
    [`${ROOT_OK}
[profile.release.package.atlas-duck-ipc]
debug-assertions = true
`, ["profile.release.package.atlas-duck-ipc"]],
    [`${ROOT_OK}
[profile.release.package."*"]
debug-assertions = true
`, ['profile.release.package."*"']],
    [`${ROOT_OK}
[profile.release.build-override]
debug-assertions = true
`, ["profile.release.build-override"]],
    [ROOT_OK.replace('panic = "abort"', 'panic = "abort"\npackage.x.debug-assertions = true'), ["profile.release"]],
    [`${ROOT_OK}
[profile.shipping]
inherits = "release"
debug-assertions = true
`, ["profile.shipping"]],
    [`${ROOT_OK}
[profile.shipping.package.atlas-duck-ipc]
debug-assertions = true
`, ["profile.shipping.package.atlas-duck-ipc"]],
    [`${ROOT_OK}
[profile.bench]
debug-assertions = true
`, ["profile.bench"]],
  ];
  for (const [root, sections] of cases) {
    assert.deepEqual(checkManifests(manifests({ root })), sections.map(bad));
  }
  // false is fine, and so is debug-assertions in the dev profile.
  for (const root of [
    ROOT_OK.replace('panic = "abort"', 'panic = "abort"\ndebug-assertions = false'),
    `${ROOT_OK}
[profile.dev]
debug-assertions = true
`,
  ]) {
    assert.deepEqual(checkManifests(manifests({ root })), []);
  }
});

for (const pkg of ["atlas-duck-core", "atlas-duck-atlassian", "atlas-duck-convert"]) {
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
  m.members["atlas-duck-convert"] = '[package]\nname = "z"\n\n[lints]\nworkspace = true\n';
  m.root = `${ROOT_OK}\n[workspace.lints.clippy]\nunwrap_used = "deny"\nexpect_used = "deny"\n`;
  assert.deepEqual(checkManifests(m), []);
});

test("scanToml ignores # inside strings and keeps sections apart", () => {
  const s = scanToml('[a]\nk = "x # y" # c\n[b.c]\nk = 1\n');
  assert.equal(s.get("a").get("k"), '"x # y"');
  assert.equal(s.get("b.c").get("k"), "1");
});

// ---------- test-only features and the registry allow-list (Task 30) ----------

test("a normal dependency enabling a test-only feature is a violation", () => {
  for (const [from, to] of [
    ["atlas-duck-core", "atlas-duck-atlassian"],
    ["atlas-duck-cli", "atlas-duck-core"],
    ["atlas-duck-cli", "atlas-duck-audit"],
  ]) {
    const e = baseEdges();
    e[from] = e[from].filter((d) => d !== to);
    e[from].push({ name: to, features: ["testing"] });
    assert.deepEqual(graph(e).filter((v) => v.includes("test-only")), [
      `${from}: normal dependency enables test-only feature ${to}/testing`,
    ]);
  }
  const e = baseEdges();
  e["atlas-duck-core"] = [
    ...e["atlas-duck-core"].filter((d) => d !== "atlas-duck-atlassian"),
    { name: "atlas-duck-atlassian", features: ["insecure-test-http"], kind: "build" },
  ];
  assert.equal(graph(e).filter((v) => v.includes("test-only")).length, 1);
});

test("a dev-dependency may enable test-only features; so may optional external deps", () => {
  const e = baseEdges();
  e["atlas-duck-core"] = [
    ...e["atlas-duck-core"],
    { name: "atlas-duck-atlassian", kind: "dev", features: ["testing"] },
    { name: "atlas-duck-audit", kind: "dev", features: ["testing"] },
    { name: "proptest" },
    { name: "tempfile" },
  ];
  assert.deepEqual(graph(e), []);
});

test("a default feature that reaches a test-only feature is a violation", () => {
  const m = makeMetadata(baseEdges());
  const atlassian = m.packages.find((p) => p.name === "atlas-duck-atlassian");
  atlassian.features = { default: ["wire"], wire: ["testing"], testing: ["insecure-test-http"], "insecure-test-http": [] };
  const core = m.packages.find((p) => p.name === "atlas-duck-core");
  const dep = core.dependencies.find((d) => d.name === "atlas-duck-atlassian");
  // Only core's edge is under test (the M12 server depends on atlassian too).
  const server = m.packages.find((p) => p.name === "atlas-duck-server");
  server.dependencies.find((d) => d.name === "atlas-duck-atlassian").uses_default_features = false;
  const edgeViolations = () => checkGraph(m).filter((v) => v.includes("normal dependency"));
  assert.deepEqual(edgeViolations().sort(), [
    "atlas-duck-core: normal dependency enables test-only feature atlas-duck-atlassian/insecure-test-http",
    "atlas-duck-core: normal dependency enables test-only feature atlas-duck-atlassian/testing",
  ]);
  dep.uses_default_features = false;
  assert.deepEqual(edgeViolations(), []);
  // T21: the package's own table is wrong whoever depends on it: `wire` is no forwarder, and
  // `default` reaches test-only features.
  assert.deepEqual(checkGraph(m).sort(), [
    "atlas-duck-atlassian: default feature reaches test-only feature atlas-duck-atlassian/insecure-test-http (§13)",
    "atlas-duck-atlassian: default feature reaches test-only feature atlas-duck-atlassian/testing (§13)",
    `atlas-duck-atlassian: feature wire forwards test-only feature atlas-duck-atlassian/insecure-test-http; only ${TEST_FEATURE_FORWARDERS.join(", ")} may (§13)`,
    `atlas-duck-atlassian: feature wire forwards test-only feature atlas-duck-atlassian/testing; only ${TEST_FEATURE_FORWARDERS.join(", ")} may (§13)`,
  ]);
});

// ---------- test-only feature forwarders (M4 Task 21) ----------

const FORWARD_MSG = (pkg, feature, target) =>
  `${pkg}: feature ${feature} forwards test-only feature ${target}; only ${TEST_FEATURE_FORWARDERS.join(", ")} may (§13)`;

/** The real M4 feature tables (atlas-duck-app as an extra member with its dependencies). */
function forwarderMetadata() {
  const e = baseEdges();
  e["atlas-duck-app"] = ["atlas-duck-core", "atlas-duck-ipc", "atlas-duck-cli", "atlas-duck-audit"];
  const m = makeMetadata(e, { extraMembers: ["atlas-duck-app"] });
  const pkg = (name) => m.packages.find((p) => p.name === name);
  pkg("atlas-duck-app").features = {
    "scripted-approver": ["atlas-duck-ipc/test-paths", "atlas-duck-cli/test-env", "atlas-duck-core/testing"],
  };
  pkg("atlas-duck-core").features = {
    testing: ["atlas-duck-atlassian/testing", "atlas-duck-audit/testing", "dep:tempfile", "dep:proptest"],
    tempfile: ["dep:tempfile"],
    proptest: ["dep:proptest"],
  };
  pkg("atlas-duck-atlassian").features = {
    "insecure-test-http": [],
    testing: ["insecure-test-http", "dep:wiremock", "tokio/net"],
  };
  pkg("atlas-duck-audit").features = { testing: [] };
  pkg("atlas-duck-ipc").features = {
    default: ["async"],
    async: ["dep:tokio", "dep:sha2"],
    "test-paths": [],
  };
  pkg("atlas-duck-cli").features = { "test-env": [] };
  pkg("atlas-duck-sandbox-host").features = {};
  return { m, pkg };
}

test("the forwarder list and the M4 test-only features", () => {
  for (const f of ["atlas-duck-ipc/test-paths", "atlas-duck-cli/test-env", "atlas-duck-app/scripted-approver"]) {
    assert.ok(TEST_ONLY_FEATURES.includes(f), f);
  }
  assert.deepEqual(TEST_FEATURE_FORWARDERS, [
    "atlas-duck-app/scripted-approver",
    "atlas-duck-core/testing",
    "atlas-duck-atlassian/testing",
  ]);
});

test("the real forwarders (app/scripted-approver, core/testing, atlassian/testing) pass", () => {
  const { m } = forwarderMetadata();
  assert.deepEqual(checkGraph(m), []);
});

test("a feature outside the forwarder list that forwards a test-only feature is a violation", () => {
  for (const [name, features, want] of [
    ["atlas-duck-sandbox-host", { probe: ["atlas-duck-ipc/test-paths"] }, ["probe", "atlas-duck-ipc/test-paths"]],
    // A test-only feature that is not a forwarder may not forward another one.
    ["atlas-duck-audit", { testing: ["atlas-duck-ipc/test-paths"] }, ["testing", "atlas-duck-ipc/test-paths"]],
    ["atlas-duck-app", { "other-tests": ["atlas-duck-cli/test-env"] }, ["other-tests", "atlas-duck-cli/test-env"]],
    // The weak form counts.
    ["atlas-duck-app", { weak: ["atlas-duck-core?/testing"] }, ["weak", "atlas-duck-core/testing"]],
    // Forwarding a forwarder counts.
    ["atlas-duck-app", { e2e: ["scripted-approver"], "scripted-approver": [] }, ["e2e", "atlas-duck-app/scripted-approver"]],
  ]) {
    const { m, pkg } = forwarderMetadata();
    Object.assign(pkg(name).features, features);
    assert.deepEqual(checkGraph(m), [FORWARD_MSG(name, ...want)], `${name} ${JSON.stringify(features)}`);
  }
});

test("forwarding through the package's own features is followed", () => {
  const { m, pkg } = forwarderMetadata();
  Object.assign(pkg("atlas-duck-sandbox-host").features, { a: ["b"], b: ["c"], c: ["atlas-duck-cli/test-env"] });
  assert.deepEqual(checkGraph(m).sort(), [
    FORWARD_MSG("atlas-duck-sandbox-host", "a", "atlas-duck-cli/test-env"),
    FORWARD_MSG("atlas-duck-sandbox-host", "b", "atlas-duck-cli/test-env"),
    FORWARD_MSG("atlas-duck-sandbox-host", "c", "atlas-duck-cli/test-env"),
  ]);
});

test("a renamed dependency is resolved to its package", () => {
  const { m, pkg } = forwarderMetadata();
  const host = pkg("atlas-duck-sandbox-host");
  host.dependencies.find((d) => d.name === "atlas-duck-ipc").rename = "ipc";
  host.features = { paths: ["ipc/test-paths"] };
  assert.deepEqual(checkGraph(m), [FORWARD_MSG("atlas-duck-sandbox-host", "paths", "atlas-duck-ipc/test-paths")]);
});

test("no default feature may reach a test-only feature, forwarders included", () => {
  for (const [name, features, want] of [
    ["atlas-duck-cli", { default: ["test-env"] }, ["atlas-duck-cli/test-env"]],
    ["atlas-duck-ipc", { default: ["async", "test-paths"] }, ["atlas-duck-ipc/test-paths"]],
    [
      "atlas-duck-app",
      { default: ["scripted-approver"] },
      [
        "atlas-duck-app/scripted-approver",
        "atlas-duck-cli/test-env",
        "atlas-duck-core/testing",
        "atlas-duck-ipc/test-paths",
      ],
    ],
    ["atlas-duck-core", { default: ["testing"] }, ["atlas-duck-atlassian/testing", "atlas-duck-audit/testing", "atlas-duck-core/testing"]],
  ]) {
    const { m, pkg } = forwarderMetadata();
    Object.assign(pkg(name).features, features);
    // (A dependent using default features is reported as well, by the edge rule.)
    assert.deepEqual(
      checkGraph(m)
        .filter((v) => v.includes("default feature reaches"))
        .sort(),
      want.map((t) => `${name}: default feature reaches test-only feature ${t} (§13)`).sort(),
      `${name} ${JSON.stringify(features)}`,
    );
  }
  // Through an intermediate feature: both the intermediate and default are reported.
  const { m, pkg } = forwarderMetadata();
  Object.assign(pkg("atlas-duck-app").features, { default: ["gui"], gui: ["scripted-approver"] });
  const got = checkGraph(m);
  assert.ok(got.includes("atlas-duck-app: default feature reaches test-only feature atlas-duck-app/scripted-approver (§13)"), got.join("\n"));
  assert.ok(got.includes(FORWARD_MSG("atlas-duck-app", "gui", "atlas-duck-app/scripted-approver")), got.join("\n"));
});

test("a normal dependency enabling test-paths or test-env is a violation", () => {
  for (const [from, to, feature] of [
    ["atlas-duck-sandbox-host", "atlas-duck-ipc", "test-paths"],
    ["atlas-duck-cli", "atlas-duck-ipc", "test-paths"],
  ]) {
    const e = baseEdges();
    e[from] = e[from].filter((d) => d !== to);
    e[from].push({ name: to, features: [feature] });
    assert.deepEqual(graph(e), [`${from}: normal dependency enables test-only feature ${to}/${feature}`]);
  }
  const e = baseEdges();
  e["atlas-duck-app"] = [{ name: "atlas-duck-cli", features: ["test-env"] }];
  assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), [
    "atlas-duck-app: normal dependency enables test-only feature atlas-duck-cli/test-env",
  ]);
  // A dev-dependency may (the app's own test targets).
  e["atlas-duck-app"] = [{ name: "atlas-duck-cli", features: ["test-env"], kind: "dev" }];
  assert.deepEqual(graph(e, { extraMembers: ["atlas-duck-app"] }), []);
});

test("registry normal dependencies are limited to serde and serde_json", () => {
  const e = baseEdges();
  e["atlas-duck-registry"] = ["serde", "serde_json", { name: "jsonschema", kind: "dev" }];
  assert.deepEqual(graph(e), []);
  e["atlas-duck-registry"].push("regex");
  assert.deepEqual(graph(e), [
    "atlas-duck-registry: external normal dependency regex is not allowed; only serde, serde_json (§2.2)",
  ]);
});

test("convert external dependency outside allowlist is rejected", () => {
  const e = baseEdges();
  e["atlas-duck-convert"] = ["pulldown-cmark", { name: "proptest", kind: "dev" }];
  assert.deepEqual(graph(e), []);
  e["atlas-duck-convert"].push("reqwest");
  assert.deepEqual(graph(e), ["atlas-duck-convert: external dependency reqwest not allowed"]);
});

test("convert may depend on quick-xml and htmd", () => {
  const e = baseEdges();
  e["atlas-duck-convert"] = ["pulldown-cmark", "quick-xml", "htmd", { name: "proptest", kind: "dev" }];
  assert.deepEqual(graph(e), []);
});

test("convert and preview depend on no workspace crate", () => {
  for (const leaf of ["atlas-duck-convert", "atlas-duck-preview"]) {
    const e = baseEdges();
    assert.deepEqual(graph(e), []);
    // A dev-dependency is ignored.
    e[leaf] = [{ name: "atlas-duck-core", kind: "dev" }];
    assert.deepEqual(graph(e), []);
    e[leaf] = ["atlas-duck-core"];
    assert.deepEqual(graph(e), [`${leaf}: must not depend on atlas-duck-core (§2.2)`]);
  }
});

// ---------- M12 server crates ----------

test("desktop trees without server-only crates pass", () => {
  const trees = {
    "atlas-duck-app": ["atlas-duck-app", "tauri", "hyper", "rmcp"],
    "atlas-duck-cli": ["atlas-duck-cli", "rmcp", "atlas-duck-mcp-tools"],
  };
  assert.deepEqual(checkDesktopTrees(trees), []);
});

test("axum under atlas-duck-app is reported", () => {
  const trees = { "atlas-duck-app": ["atlas-duck-app", "axum", "tauri"] };
  assert.deepEqual(checkDesktopTrees(trees), ["atlas-duck-app: links server-only crate axum"]);
});

test("every server-only crate is reported for a desktop package", () => {
  assert.deepEqual(
    checkDesktopTrees({ "atlas-duck-cli": [...SERVER_ONLY_CRATES] }),
    SERVER_ONLY_CRATES.map((c) => `atlas-duck-cli: links server-only crate ${c}`),
  );
});

test("no workspace member may depend on atlas-duck-server", () => {
  const e = baseEdges();
  assert.deepEqual(graph(e), []);
  e["atlas-duck-cli"] = [...e["atlas-duck-cli"], { name: "atlas-duck-server", kind: "dev" }];
  assert.deepEqual(graph(e), []);
  e["atlas-duck-cli"] = [...baseEdges()["atlas-duck-cli"], "atlas-duck-server"];
  assert.ok(graph(e).includes("atlas-duck-cli: must not depend on atlas-duck-server (M12 PD-192)"));
});

test("mcp-tools and server stay inside their allowed workspace edges", () => {
  const e = baseEdges();
  e["atlas-duck-mcp-tools"] = [...e["atlas-duck-mcp-tools"], "atlas-duck-core"];
  assert.deepEqual(graph(e), ["atlas-duck-mcp-tools: must not depend on atlas-duck-core (§2.2)"]);
  const s = baseEdges();
  s["atlas-duck-server"] = [...s["atlas-duck-server"], "atlas-duck-sandbox-host"];
  assert.deepEqual(graph(s), ["atlas-duck-server: must not depend on atlas-duck-sandbox-host (§2.2)"]);
});

test("a per-package tree overrides the unified closure for the banned-crate checks", () => {
  const e = baseEdges();
  e["atlas-duck-cli"] = [...e["atlas-duck-cli"], "rmcp"];
  e.rmcp = ["hyper"]; // unified: the server's dev-only rmcp client features
  assert.deepEqual(graph(e), ["atlas-duck-cli: banned crate hyper in normal-dependency closure (§2.1)"]);
  const md = makeMetadata(e);
  assert.deepEqual(checkGraph(md, { "atlas-duck-cli": ["atlas-duck-cli", "rmcp"] }), []);
  assert.deepEqual(checkGraph(md, { "atlas-duck-cli": ["atlas-duck-cli", "rmcp", "hyper"] }), [
    "atlas-duck-cli: banned crate hyper in normal-dependency closure (§2.1)",
  ]);
});

test("server and mcp-tools are lint packages", () => {
  assert.ok(LINT_PACKAGES.includes("atlas-duck-server"));
  assert.ok(LINT_PACKAGES.includes("atlas-duck-mcp-tools"));
});

// ---------- the real workspace ----------

test("the real workspace passes: node ci/check-workspace.mjs exits 0", () => {
  const res = spawnSync(process.execPath, [join(REPO, "ci", "check-workspace.mjs")], { encoding: "utf8" });
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /^check-workspace: ok \(\d+ workspace members\)/);
  assert.equal(res.status, 0);
});
