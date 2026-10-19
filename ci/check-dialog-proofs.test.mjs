// node --test ci/check-dialog-proofs.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROOF_HELPERS, isExempt, scanDialogProofs } from "./check-dialog-proofs.mjs";

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

test("accepts_current_tree", () => {
  const r = spawnSync(process.execPath, [join(REPO, "ci", "check-dialog-proofs.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  assert.equal(r.stdout, "");
});
