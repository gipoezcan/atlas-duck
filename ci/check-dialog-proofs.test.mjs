// node --test ci/check-dialog-proofs.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { GUARDED_CALLS, PROOF_HELPERS, collectFiles, isExempt, scanDialogProofs } from "./check-dialog-proofs.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVE = "app/src-tauri/src/serve.rs";
const OTHER = "app/src-tauri/src/commands/other.rs";

const DIALOG_FN = [
  "async fn archive(confirmer: Arc<dyn NativeConfirmer>, text: String) {",
  "    if confirmer.confirm(&text) != Confirm::Ok {",
  "        return;",
  "    }",
  "    let c = confirmed_by(&text);",
  "}",
].join("\n");

const HELPER = [
  "fn confirmed_by(text: &str) -> Confirmed {",
  "    Confirmed {",
  "        dialog_text_sha256: digest(text),",
  "    }",
  "}",
].join("\n");

test("flags_confirmed_outside_allowlist", () => {
  const src = ["fn sneaky() -> Confirmed {", "    Confirmed { dialog_text_sha256: [0; 32] }", "}"].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src }]), [
    `${OTHER}:2: Confirmed built outside a dialog function and the proof-helper allowlist`,
  ]);
});

test("flags_rust_chosen_path_without_dialog_in_fn", () => {
  const src = [
    "fn export(store: &Store, p: PathBuf) {",
    "    store.backup(RustChosenPath::from_native_dialog(p));",
    "}",
  ].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src }]), [
    `${OTHER}:2: RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog`,
  ]);
  // A confirm dialog is not a folder dialog.
  const confirmOnly = DIALOG_FN.replace("confirmed_by(&text)", "RustChosenPath::from_native_dialog(p)");
  assert.equal(scanDialogProofs([{ path: OTHER, src: confirmOnly }]).length, 1);
});

test("flags_helper_with_a_non_dialog_caller", () => {
  const caller = ["fn quiet_apply(text: &str) {", "    let c = confirmed_by(text);", "}"].join("\n");
  const found = scanDialogProofs([
    { path: SERVE, src: `${HELPER}\n${DIALOG_FN}` },
    { path: OTHER, src: caller },
  ]);
  assert.deepEqual(found, [
    `${OTHER}:2: proof helper confirmed_by called from fn quiet_apply, which is not a dialog function or a listed helper`,
  ]);
});

test("M10 T13: a helper called through its module path is a call; another module's fn of that name is not", () => {
  const caller = [
    "fn quiet_restore(text: &str) {",
    "    let c = crate::serve::confirmed_by(text);",
    "    let d = serve::confirmed_by(text);",
    "    let e = redact::confirmed_by(text);",
    "}",
  ].join("\n");
  const found = scanDialogProofs([
    { path: SERVE, src: `${HELPER}\n${DIALOG_FN}` },
    { path: OTHER, src: caller },
  ]);
  assert.deepEqual(found, [
    `${OTHER}:2: proof helper confirmed_by called from fn quiet_restore, which is not a dialog function or a listed helper`,
    `${OTHER}:3: proof helper confirmed_by called from fn quiet_restore, which is not a dialog function or a listed helper`,
  ]);
  // On a dialog function's Ok path the module path is accepted.
  const ok = DIALOG_FN.replace("confirmed_by(&text)", "crate::serve::confirmed_by(&text)");
  assert.deepEqual(scanDialogProofs([{ path: SERVE, src: HELPER }, { path: OTHER, src: ok }]), []);
});

test("accepts_listed_helper_called_from_dialog_fn", () => {
  assert.deepEqual(scanDialogProofs([{ path: SERVE, src: `${HELPER}\n${DIALOG_FN}` }]), []);
  // A path dialog function may build the chosen path.
  const pick = [
    "fn pick(app: &App, store: &Store) {",
    "    let Some(p) = app.dialog().file().blocking_pick_folder() else { return };",
    "    store.backup(RustChosenPath::from_native_dialog(p));",
    "}",
  ].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: pick }]), []);
  // Another listed helper may call a helper; an unrelated type's method of the same name is not a call.
  const chain = [
    "fn confirmed_twice(text: &str) -> Confirmed { confirmed_by(text) }",
    "fn other(pem: Vec<u8>) { let _ = PinnedCa::confirmed_by(pem); let _ = x.confirmed_by(); }",
  ].join("\n");
  const helpers = [...PROOF_HELPERS, { file: SERVE, name: "confirmed_twice" }];
  assert.deepEqual(scanDialogProofs([{ path: SERVE, src: `${HELPER}\n${chain}` }], helpers), []);
});

test("a caller that propagates confirm with ? is a dialog function; one without .confirm( is not", () => {
  const helpers = [{ file: SERVE, name: "apply" }];
  const helper = "fn apply(t: Option<&str>) -> Confirmed { Confirmed { dialog_text_sha256: [0; 32] } }";
  const ok = "fn add(&self) { self.confirm(&text)?; self.apply(Some(&text)); }";
  const bad = "fn add(&self) { self.apply(Some(&text)); }";
  assert.deepEqual(scanDialogProofs([{ path: SERVE, src: `${helper}\n${ok}` }], helpers), []);
  assert.equal(scanDialogProofs([{ path: SERVE, src: `${helper}\n${bad}` }], helpers).length, 1);
  // noneOk: a call without text mints nothing.
  const none = "fn set(&self) { self.apply(Change { a: 1 }, None)?; }";
  assert.deepEqual(scanDialogProofs([{ path: SERVE, src: `${helper}\n${none}` }], [{ ...helpers[0], noneOk: true }]), []);
});

test("exempt paths, cfg(test) items, struct items and comments are not sites", () => {
  const lit = "fn t() -> Confirmed { Confirmed { dialog_text_sha256: [0; 32] } }";
  for (const path of [
    "crates/audit/src/testing.rs",
    "crates/core/src/testing/harness.rs",
    "crates/audit/tests/prune.rs",
    "app/src-tauri/tests/commands_acl.rs",
    "app/src-tauri/tests/cli_flows/main.rs",
  ]) {
    assert.ok(isExempt(path), path);
    assert.deepEqual(scanDialogProofs([{ path, src: lit }]), []);
  }
  const src = [
    "pub struct Confirmed {",
    "    pub dialog_text_sha256: [u8; 32],",
    "}",
    "impl Confirmed {}",
    '// Confirmed { not code } and RustChosenPath::from_native_dialog(p) in a comment',
    "#[cfg(test)]",
    "mod tests {",
    "    fn c() -> Confirmed { Confirmed { dialog_text_sha256: [0; 32] } }",
    "}",
  ].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: "crates/audit/src/types.rs", src }]), []);
});

const LITERAL = "Confirmed { dialog_text_sha256: [0; 32] }";
const SITE = `${OTHER}:`;
const OUTSIDE = "Confirmed built outside a dialog function and the proof-helper allowlist";
const NO_PATH_DIALOG = "RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog";
const lines = (...l) => l.join("\n");

test("I-1: Confirmed built on the Cancel arm, after ignoring the answer or before the dialog is flagged", () => {
  const cancelArm = lines(
    "fn pick(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
    '    match c.confirm("t") {',
    "        Confirm::Ok => None,",
    `        Confirm::Cancel => { let k = ${LITERAL}; Some(k) }`,
    "    }",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: cancelArm }]), [`${SITE}4: ${OUTSIDE}`]);
  const ignored = lines(
    "fn f(c: &dyn NativeConfirmer) -> Confirmed {",
    '    let _r = c.confirm("t");',
    "    let _o = Confirm::Ok;",
    `    ${LITERAL}`,
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: ignored }]), [`${SITE}4: ${OUTSIDE}`]);
  const before = lines(
    "fn f(c: &dyn NativeConfirmer) -> Confirmed {",
    `    let k = ${LITERAL};`,
    '    if c.confirm("t") != Confirm::Ok { panic!() }',
    "    k",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: before }]), [`${SITE}2: ${OUTSIDE}`]);
  // The realistic accident: the Ok branch only logs, the proof is built whatever the answer was.
  const accident = lines(
    "fn f(c: &dyn NativeConfirmer, store: &Store) {",
    '    if c.confirm("t") == Confirm::Ok { log(); }',
    `    store.apply(Some(${LITERAL}));`,
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: accident }]), [`${SITE}3: ${OUTSIDE}`]);
  // Built inside the block of a `!= Ok` test, which is the cancel path.
  const inNe = lines(
    "fn f(c: &dyn NativeConfirmer) -> Confirmed {",
    '    if c.confirm("t") != Confirm::Ok {',
    `        return ${LITERAL};`,
    "    }",
    `    ${LITERAL}`,
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: inNe }]), [`${SITE}3: ${OUTSIDE}`]);
});

test("I-1: Confirmed built on the Ok path is accepted in each of its shapes", () => {
  const shapes = [
    // brace arm, expression arm, `==` block, `!=` early return, `?`, `if let`
    lines(
      "fn f(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
      '    match c.confirm("t") {',
      `        Confirm::Ok => { Some(${LITERAL}) }`,
      "        Confirm::Cancel => None,",
      "    }",
      "}",
    ),
    lines(
      "fn f(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
      '    match c.confirm("t") {',
      `        Confirm::Ok => Some(${LITERAL}),`,
      "        _ => None,",
      "    }",
      "}",
    ),
    lines(
      "fn f(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
      '    if c.confirm("t") == Confirm::Ok {',
      `        return Some(${LITERAL});`,
      "    }",
      "    None",
      "}",
    ),
    lines(
      "fn f(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
      '    if c.confirm("t") != Confirm::Ok { return None; }',
      `    Some(${LITERAL})`,
      "}",
    ),
    lines("fn f(&self) -> Result<Confirmed, E> {", '    self.confirm("t")?;', `    Ok(${LITERAL})`, "}"),
    lines(
      "fn f(c: &dyn NativeConfirmer) -> Option<Confirmed> {",
      '    if let Confirm::Ok = c.confirm("t") {',
      `        return Some(${LITERAL});`,
      "    }",
      "    None",
      "}",
    ),
  ];
  for (const src of shapes) assert.deepEqual(scanDialogProofs([{ path: OTHER, src }]), [], src);
});

test("I-1: from_native_dialog takes the picked result: a literal path, a path before the dialog or on the cancel path is flagged", () => {
  const literal = lines(
    "fn pick(app: &App, store: &Store) {",
    "    let Some(p) = app.dialog().file().blocking_pick_folder() else { return };",
    '    store.backup(RustChosenPath::from_native_dialog(PathBuf::from("/etc")));',
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: literal }]), [`${SITE}3: ${NO_PATH_DIALOG}`]);
  const ignored = lines(
    "fn pick(app: &App, store: &Store, other: PathBuf) {",
    "    let _ = app.dialog().file().blocking_pick_folder();",
    "    store.backup(RustChosenPath::from_native_dialog(other));",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: ignored }]), [`${SITE}3: ${NO_PATH_DIALOG}`]);
  const before = lines(
    "fn pick(app: &App, store: &Store, other: PathBuf) {",
    "    let r = RustChosenPath::from_native_dialog(other);",
    "    let _ = app.dialog().file().blocking_pick_folder();",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: before }]), [`${SITE}2: ${NO_PATH_DIALOG}`]);
  const cancelArm = lines(
    "fn pick(app: &App, store: &Store, d: PathBuf) {",
    "    match app.dialog().file().blocking_pick_folder() {",
    "        Some(p) => store.backup(RustChosenPath::from_native_dialog(p)),",
    "        None => store.backup(RustChosenPath::from_native_dialog(d)),",
    "    }",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: cancelArm }]), [`${SITE}4: ${NO_PATH_DIALOG}`]);
  // The picked value, derived and passed on, is what the check wants.
  const derived = lines(
    "fn pick(app: &App, store: &Store) -> Result<bool, E> {",
    "    let Some(chosen) = app.dialog().file().set_title(T).blocking_pick_folder() else { return Ok(false) };",
    "    let path = chosen.into_path().map_err(|_| E::Internal)?;",
    "    store.backup(RustChosenPath::from_native_dialog(path))?;",
    "    Ok(true)",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: derived }]), []);
});

test("I-2: only #[cfg(test)] modules, crate-root tests/ dirs and the testing paths are exempt", () => {
  const lit = `fn t() -> Confirmed { ${LITERAL} }`;
  for (const path of ["crates/ipc/src/tests/x.rs", "crates/ipc/src/tests.rs", "app/src-tauri/src/commands/tests/y.rs"]) {
    assert.ok(!isExempt(path), path);
    assert.equal(scanDialogProofs([{ path, src: lit }]).length, 1, path);
  }
  // A file that the parent declares `#[cfg(test)] mod x;` is test code.
  const parent = { path: "crates/ipc/src/lib.rs", src: "#[cfg(test)]\nmod tests;\nmod live;\n" };
  assert.deepEqual(scanDialogProofs([parent, { path: "crates/ipc/src/tests/x.rs", src: lit }]), []);
  assert.deepEqual(scanDialogProofs([parent, { path: "crates/ipc/src/tests.rs", src: lit }]), []);
  assert.equal(scanDialogProofs([parent, { path: "crates/ipc/src/live.rs", src: lit }]).length, 1);
  const nested = { path: "crates/ipc/src/a/mod.rs", src: "#[cfg(test)]\npub(crate) mod tests;\n" };
  assert.deepEqual(scanDialogProofs([nested, { path: "crates/ipc/src/a/tests.rs", src: lit }]), []);
  // The real scan visits the crate-root tests/ dirs, so the exemption is exercised on real paths.
  const visited = collectFiles(REPO).map((f) => f.path);
  for (const dir of ["crates/audit/tests/", "app/src-tauri/tests/"]) {
    const some = visited.filter((p) => p.startsWith(dir));
    assert.ok(some.length > 0, dir);
    assert.ok(some.every(isExempt), dir);
  }
});

test("M-1: an aliased import or alias of Confirmed or RustChosenPath, and Self literals in impl Confirmed", () => {
  const alias = lines("use atlas_duck_audit::types::Confirmed as C;", `fn f() -> C { C { dialog_text_sha256: [0; 32] } }`);
  const found = scanDialogProofs([{ path: OTHER, src: alias }]);
  assert.equal(found.length, 1);
  assert.match(found[0], /^app\/src-tauri\/src\/commands\/other\.rs:1: .*Confirmed.*under another name/);
  assert.equal(scanDialogProofs([{ path: OTHER, src: "use a::{RustChosenPath as R, X};" }]).length, 1);
  assert.equal(scanDialogProofs([{ path: OTHER, src: "type C = Confirmed;" }]).length, 1);
  const selfLit = lines(
    "impl Confirmed {",
    "    fn f() -> Self { Self { dialog_text_sha256: [0; 32] } }",
    "}",
  );
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: selfLit }]), [`${SITE}2: ${OUTSIDE}`]);
  const traitImpl = lines("impl From<X> for Confirmed {", "    fn from(_: X) -> Self { Self { dialog_text_sha256: [0; 32] } }", "}");
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: traitImpl }]), [`${SITE}2: ${OUTSIDE}`]);
  // `Self {` in an unrelated impl is not a Confirmed.
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: "impl Other { fn f() -> Self { Self { a: 1 } } }" }]), []);
});

test("M-2: Self::apply and Self::confirmed callers are callers of the helper", () => {
  const helper = "fn apply(t: Option<&str>) -> Confirmed { Confirmed { dialog_text_sha256: [0; 32] } }";
  for (const name of ["apply", "confirmed"]) {
    const h = helper.replace("apply", name);
    const rogue = `fn rogue(&self) { Self::${name}(self, Some("x")); }`;
    const found = scanDialogProofs([{ path: SERVE, src: `${h}\n${rogue}` }], [{ file: SERVE, name }]);
    assert.equal(found.length, 1, name);
    assert.match(found[0], new RegExp(`proof helper ${name} called from fn rogue`));
    const ok = `fn add(&self) { self.confirm(&t)?; Self::${name}(self, Some("x")); }`;
    assert.deepEqual(scanDialogProofs([{ path: SERVE, src: `${h}\n${ok}` }], [{ file: SERVE, name }]), []);
  }
});

test("M-3: impl<T> Confirmed {} is not a literal", () => {
  for (const head of ["impl<T> Confirmed {", "impl<T: Clone + Into<X>> Confirmed {", "impl<'a> Trait<'a> for Confirmed {"]) {
    assert.deepEqual(scanDialogProofs([{ path: OTHER, src: `${head}\n    fn f(&self) {}\n}` }]), [], head);
  }
});

// T12 review (rule 5): `Store::acknowledge_incident` takes no `Confirmed`; its callers must run it
// on a native confirmation's Ok path.
const ACK = "app/src-tauri/src/commands/audit.rs";

test("rule 5: a guarded call outside a dialog function's Ok path is flagged", () => {
  assert.deepEqual(GUARDED_CALLS.map((g) => g.name), ["acknowledge_incident"]);
  const quiet = ["fn ack(store: &Store, seq: u64) {", "    let _ = store.acknowledge_incident(seq, \"u\", \"\");", "}"].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: ACK, src: quiet }]), [
    `${ACK}:2: guarded call acknowledge_incident from fn ack, which does not run it on a native confirmation's Ok path`,
  ]);
  // Before the dialog, on its Cancel path, as a path call or a function value, outside any fn.
  const shapes = [
    [
      "fn early(c: &dyn NativeConfirmer, store: &Store) {",
      "    let _ = store.acknowledge_incident(1, \"u\", \"\");",
      "    if c.confirm(\"t\") != Confirm::Ok { return; }",
      "}",
    ],
    [
      "fn cancel_arm(c: &dyn NativeConfirmer, store: &Store) {",
      "    match c.confirm(\"t\") {",
      "        Confirm::Cancel => { let _ = store.acknowledge_incident(1, \"u\", \"\"); }",
      "        Confirm::Ok => {}",
      "    }",
      "}",
    ],
    ["fn path_call(store: &Store) {", "    let _ = Store::acknowledge_incident(store, 1, \"u\", \"\");", "}"],
    ["fn value(store: &Store) {", "    let f = Store::acknowledge_incident;", "}"],
    ["static F: fn(&Store, u64, &str, &str) = Store::acknowledge_incident;"],
  ];
  for (const lines of shapes) {
    const found = scanDialogProofs([{ path: OTHER, src: lines.join("\n") }]);
    assert.equal(found.length, 1, `${lines.join("\n")}\n${found.join("\n")}`);
    assert.match(found[0], /guarded call acknowledge_incident from /);
  }
});

test("rule 5: a guarded call on the Ok path, its definition and other names of it are accepted", () => {
  const dialog = [
    "fn acknowledge_dto(store: &Store, c: &dyn NativeConfirmer, seq: u64) {",
    "    if c.confirm(&text(seq)) != Confirm::Ok {",
    "        return;",
    "    }",
    "    let _ = store.acknowledge_incident(seq, \"u\", \"\");",
    "}",
    "fn propagated(store: &Store, c: &Confirmer) -> Result<(), E> {",
    "    c.confirm(\"t\")?;",
    "    store.acknowledge_incident(1, \"u\", \"\").map(|_| ())",
    "}",
  ].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: ACK, src: dialog }]), []);
  const others = [
    "pub fn acknowledge_incident(&self, verify_seq: u64, os_user: &str, note: &str) {}",
    "pub async fn acknowledge_incident_cmd() {}",
    "fn handlers() { let _ = commands::audit::acknowledge_incident; }",
    "// store.acknowledge_incident(1, \"u\", \"\") in a comment",
    "#[cfg(test)]",
    "mod tests { fn t(store: &Store) { let _ = store.acknowledge_incident(1, \"u\", \"\"); } }",
  ].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: OTHER, src: others }]), []);
  // The crate-root tests/ directories are exempt.
  const quiet = ["fn t(store: &Store) {", "    let _ = store.acknowledge_incident(1, \"u\", \"\");", "}"].join("\n");
  assert.deepEqual(scanDialogProofs([{ path: "crates/audit/tests/verify.rs", src: quiet }]), []);
  // An empty guarded list accepts the quiet caller (the list is what the rule checks).
  assert.deepEqual(scanDialogProofs([{ path: ACK, src: quiet }], PROOF_HELPERS, []), []);
});

// M-4: the allowlist and the dialog proof are load-bearing on the real files. A slice of the real
// tree (the three files that hold a listed helper, and rule 5's guarded method and its caller) is
// copied into a scratch directory (the env var, else `target/`, never the system temp dir) and
// mutated; the CLI must then fail.
const SLICE = [
  SERVE,
  "crates/core/src/instances/admin.rs",
  "crates/core/src/settings/mod.rs",
  "crates/audit/src/store.rs",
  ACK,
  // M10 T13: the restore's two native confirmations and its source dialog.
  "app/src-tauri/src/restore_flow.rs",
  // M10 T14: the recovery tier's confirmations and the anchor directory's folder dialog.
  "app/src-tauri/src/recovery_tier.rs",
  "app/src-tauri/src/commands/settings.rs",
];
const RESTORE = "app/src-tauri/src/restore_flow.rs";
const RECOVERY = "app/src-tauri/src/recovery_tier.rs";
const SETTINGS_COMMANDS = "app/src-tauri/src/commands/settings.rs";

function withSliceCopy(mutate, run) {
  const base = process.env.CHECK_DIALOG_PROOFS_SCRATCH ?? join(REPO, "target", "check-dialog-proofs-scratch");
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, "slice-"));
  try {
    for (const rel of SLICE) {
      const to = join(root, ...rel.split("/"));
      mkdirSync(dirname(to), { recursive: true });
      let text = readFileSync(join(REPO, ...rel.split("/")), "utf8");
      text = mutate(rel, text);
      writeFileSync(to, text);
    }
    return run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const cli = (root) =>
  spawnSync(process.execPath, [join(REPO, "ci", "check-dialog-proofs.mjs"), root], { encoding: "utf8" });

function replaceOnce(text, from, to) {
  assert.ok(text.includes(from), `mutation target missing: ${from}`);
  return text.replace(from, to);
}

test("M-4: the unmodified slice of the real tree passes", () => {
  const r = withSliceCopy((_, t) => t, cli);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
});

test("M-4: dropping a helper from the allowlist (renaming it) fails the check", () => {
  const r = withSliceCopy((rel, t) => (rel === SERVE ? t.replace(/\bconfirmed_by\b/g, "confirmed_by_renamed") : t), cli);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /serve\.rs:\d+: Confirmed built outside a dialog function/);
  assert.match(r.stdout, /listed proof helper confirmed_by not found/);
});

test("M-4: a rogue caller of a real helper fails the check", () => {
  const rogue = (rel, t) =>
    rel === "crates/core/src/settings/mod.rs" ? `${t}\nfn rogue_caller(text: &str) { let _ = confirmed(text); }\n` : t;
  const r = withSliceCopy(rogue, cli);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /settings\/mod\.rs:\d+: proof helper confirmed called from fn rogue_caller/);
});

test("M-4: removing the answer test before a real helper call fails the check", () => {
  const r = withSliceCopy((rel, t) => (rel === SERVE ? replaceOnce(t, "answer != Confirm::Ok", "false") : t), cli);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /serve\.rs:\d+: proof helper confirmed_by called from fn /);
});

test("M10 T13: the restore's confirmations and source dialog are load-bearing on the real file", () => {
  for (const [from, to, flagged] of [
    // The "Restore backup" answer (PD-168, L54) ignored.
    ["confirmer.confirm(RESTORE_CONFIRM_TEXT) != Confirm::Ok", "false", /restore_flow\.rs:\d+: proof helper confirmed_by called from fn ask_restore/],
    // The rollback answer (§8.11 step 4) ignored.
    ["confirmer.confirm(&text) != Confirm::Ok", "false", /restore_flow\.rs:\d+: proof helper confirmed_by called from fn ask_rollback/],
    // A source path that no dialog returned.
    [
      "RustChosenPath::from_native_dialog(source)",
      'RustChosenPath::from_native_dialog(PathBuf::from("/tmp/backup"))',
      /restore_flow\.rs:\d+: RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog/,
    ],
  ]) {
    const r = withSliceCopy((rel, t) => (rel === RESTORE ? replaceOnce(t, from, to) : t), cli);
    assert.equal(r.status, 1, from);
    assert.match(r.stdout, flagged);
  }
});

test("M10 T14: the recovery tier's confirmations and the anchor folder dialog are load-bearing on the real files", () => {
  for (const [file, from, to, flagged] of [
    // The anchor-directory confirmation after the folder dialog (PD-166, L54; T14 review I-1:
    // the one that names the folder chosen, and the proof the store records) ignored.
    [RECOVERY, "if confirmer.confirm(&set_text) != Confirm::Ok {", "if false {", /recovery_tier\.rs:\d+: proof helper confirmed_by called from fn set_anchor_dir/],
    // "Remove anchor directory", "Re-anchor" and the first "Forget old install" dialog ignored.
    [RECOVERY, "if confirmer.confirm(&remove_text) != Confirm::Ok {", "if false {", /recovery_tier\.rs:\d+: proof helper confirmed_by called from fn remove_anchor_dir/],
    [RECOVERY, "if confirmer.confirm(&re_text) != Confirm::Ok {", "if false {", /recovery_tier\.rs:\d+: proof helper confirmed_by called from fn re_anchor/],
    [RECOVERY, "if confirmer.confirm(&first_text) != Confirm::Ok {", "if false {", /recovery_tier\.rs:\d+: proof helper confirmed_by called from fn forget/],
    // The second "Forget old install" dialog (the archived log's keys, PD-170) ignored.
    [RECOVERY, "if confirmer.confirm(&text) == Confirm::Ok {", "if true {", /recovery_tier\.rs:\d+: proof helper confirmed_by called from fn ask_keys/],
    // An anchor directory that no folder dialog returned.
    [
      SETTINGS_COMMANDS,
      "RustChosenPath::from_native_dialog(folder)",
      'RustChosenPath::from_native_dialog(std::path::PathBuf::from("/tmp/anchors"))',
      /settings\.rs:\d+: RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog/,
    ],
  ]) {
    const r = withSliceCopy((rel, t) => (rel === file ? replaceOnce(t, from, to) : t), cli);
    assert.equal(r.status, 1, from);
    assert.match(r.stdout, flagged);
  }
});

// T14 review I-1: the anchor-directory proof is of the text that names the folder chosen, so the
// confirmation comes after Rust's folder dialog, and set_anchor_dir asks no other confirmation
// (a prompt before the pick could not name the folder). The checker sees a proof on an Ok path,
// not the order: this pins it on the real file.
test("M10 T14: set_anchor_dir asks its one confirmation after the folder dialog", () => {
  const src = readFileSync(join(REPO, ...RECOVERY.split("/")), "utf8");
  const start = src.indexOf("pub fn set_anchor_dir(");
  assert.ok(start >= 0, "set_anchor_dir not found");
  const end = src.indexOf("\n}\n", start);
  const body = src.slice(start, end);
  const pick = body.indexOf("pick()");
  const asks = [...body.matchAll(/confirmer\.confirm\(/g)].map((m) => m.index);
  assert.ok(pick >= 0, "no folder dialog in set_anchor_dir");
  assert.equal(asks.length, 1, "set_anchor_dir asks exactly one confirmation");
  assert.ok(pick < asks[0], "the confirmation comes before the folder dialog");
});

test("rule 5: removing the acknowledgement's dialog test in the real caller fails the check", () => {
  const r = withSliceCopy(
    (rel, t) =>
      rel === ACK
        ? replaceOnce(t, "confirmer.confirm(&acknowledge_text(verify_seq, &result, &detected_at)) != Confirm::Ok", "false")
        : t,
    cli,
  );
  assert.equal(r.status, 1);
  assert.match(r.stdout, /commands\/audit\.rs:\d+: guarded call acknowledge_incident from fn acknowledge_dto/);
});

test("rule 5: renaming the guarded store method fails the check (stale GUARDED_CALLS)", () => {
  const r = withSliceCopy(
    (rel, t) => (rel === "crates/audit/src/store.rs" ? replaceOnce(t, "pub fn acknowledge_incident(", "pub fn ack_incident(") : t),
    cli,
  );
  assert.equal(r.status, 1);
  assert.match(r.stdout, /guarded call acknowledge_incident not found \(update GUARDED_CALLS\)/);
});

test("accepts_current_tree", () => {
  const r = spawnSync(process.execPath, [join(REPO, "ci", "check-dialog-proofs.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  assert.equal(r.stdout, "");
});
