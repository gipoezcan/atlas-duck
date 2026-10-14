// node --test ci/check-commands.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ARG_EXEMPTIONS,
  BEGIN_MARKER,
  DROPPED_CMD,
  END_MARKER,
  EVENT_PERMISSIONS,
  LABELS,
  LISTENING_WINDOWS,
  WINDOW_COMMANDS,
  allowPermission,
  checkArgStructs,
  checkSurface,
  parseAllowedBlock,
  parseCommandList,
  parseHandlerLists,
  readRepo,
  renderAllowedBlock,
} from "./check-commands.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------- fixtures ----------

/** Capability files granting `commands` exactly per the Δ1 table. */
function capsFor(commands) {
  const caps = {};
  for (const label of LABELS) {
    const permissions = commands.filter((c) => WINDOW_COMMANDS[label].includes(c)).map(allowPermission);
    if (LISTENING_WINDOWS.includes(label)) permissions.push(...Object.keys(EVENT_PERMISSIONS));
    caps[label] = { identifier: label, description: "x", windows: [label], permissions };
  }
  return caps;
}

const COMMANDS = ["app_status", "quit", "running_list", "verify_now"];
const ALLOWED = [...COMMANDS, "plugin:event|listen", "plugin:event|unlisten"];

function surface(overrides = {}) {
  return {
    commands: COMMANDS,
    handlerLists: [[...COMMANDS]],
    caps: capsFor(COMMANDS),
    securityCapabilities: [...LABELS],
    allowed: [...ALLOWED],
    ...overrides,
  };
}

function errorsOf(input) {
  return checkSurface(input).errors;
}

function assertFails(errors, pattern) {
  assert.ok(errors.length > 0, "expected a violation");
  assert.ok(
    errors.some((e) => pattern.test(e)),
    `no violation matches ${pattern}: ${JSON.stringify(errors)}`,
  );
}

const ARGS_OK = `
use serde::Deserialize;
#[tauri::command]
pub async fn app_status<R: Runtime>(app: AppHandle<R>, args: Args<AppStatusArgs>) -> Result<(), CommandError> { Ok(()) }

/// \`app_status {}\`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppStatusArgs {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideArgs {
    pub request_id: RequestId,
    pub reason: Option<Reason>,
    pub ops: Vec<RedactionOpDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RedactionOpDto {
    Drop { pointer: String },
    Mask { pointer: String },
}

pub struct Args<T>(pub T);
impl<'de, R: Runtime, T: DeserializeOwned> CommandArg<'de, R> for Args<T> {}

pub struct RequestId(String);
impl<'de> Deserialize<'de> for RequestId {}

#[cfg(test)]
mod tests {
    #[derive(Debug, Deserialize)]
    struct Probe { path: std::path::PathBuf }
}
`;

function argErrors(src) {
  return checkArgStructs({ "app/src-tauri/src/commands/dto.rs": src });
}

// ---------- the repository ----------

test("repository_passes", () => {
  const r = readRepo(REPO);
  const html = readFileSync(r.isolationPath, "utf8");
  const errors = [
    ...checkSurface({
      commands: parseCommandList(r.namesRs),
      handlerLists: parseHandlerLists(r.modRs),
      caps: r.caps,
      securityCapabilities: r.securityCapabilities,
      allowed: parseAllowedBlock(html),
    }).errors,
    ...checkArgStructs(r.files),
  ];
  assert.deepEqual(errors, []);
});

test("arg_exemption_list_stays_empty", () => {
  assert.deepEqual(ARG_EXEMPTIONS, []);
});

test("delta1_table_covers_seven_windows_and_listeners_are_labels", () => {
  assert.deepEqual(Object.keys(WINDOW_COMMANDS).sort(), [...LABELS].sort());
  for (const l of LISTENING_WINDOWS) assert.ok(LABELS.includes(l), l);
  // Decision commands only in approvals, secret commands only in credential (§10.3).
  for (const c of ["decide", "decide_batch", "deny_batch", "deny_session", "preview_fetch"]) {
    assert.deepEqual(LABELS.filter((l) => WINDOW_COMMANDS[l].includes(c)), ["approvals"], c);
  }
  assert.deepEqual(LABELS.filter((l) => WINDOW_COMMANDS[l].includes("submit_secret")), ["credential"]);
  assert.ok(!Object.values(WINDOW_COMMANDS).flat().includes(DROPPED_CMD));
});

test("fixture_passes", () => {
  assert.deepEqual(errorsOf(surface()), []);
  assert.deepEqual(argErrors(ARGS_OK), []);
});

// ---------- negative cases (plan T4 step 1) ----------

test("command_missing_from_a_capability_fails", () => {
  const caps = capsFor(COMMANDS);
  caps.settings.permissions = caps.settings.permissions.filter((p) => p !== "allow-app-status");
  assertFails(errorsOf(surface({ caps })), /app_status is missing from capabilities\/settings\.json/);
});

test("command_in_no_capability_fails", () => {
  const caps = capsFor(COMMANDS);
  for (const label of LABELS) caps[label].permissions = caps[label].permissions.filter((p) => p !== "allow-verify-now");
  assertFails(errorsOf(surface({ caps })), /verify_now is missing from capabilities\/audit\.json/);
});

test("extra_command_outside_its_delta1_row_fails", () => {
  const caps = capsFor(COMMANDS);
  caps.audit.permissions.push("allow-app-status");
  assertFails(errorsOf(surface({ caps })), /app_status is granted to audit, outside its Δ1 windows/);
  const caps2 = capsFor(COMMANDS);
  caps2.settings.permissions.push("allow-quit");
  assertFails(errorsOf(surface({ caps: caps2 })), /quit is granted to settings/);
});

test("command_not_in_the_delta1_table_fails", () => {
  const commands = [...COMMANDS, "zz_new_command"].sort();
  const input = surface({ commands, handlerLists: [[...commands]], allowed: [...commands, "plugin:event|listen", "plugin:event|unlisten"] });
  assertFails(errorsOf(input), /zz_new_command is in no window of the Δ1 table/);
});

test("non_app_permissions_fail", () => {
  for (const perm of [
    "core:default",
    "core:app:default",
    "core:window:allow-create",
    "dialog:default",
    "dialog:allow-open",
    "notification:default",
    "autostart:allow-enable",
    "single-instance:default",
    "deny-app-status",
    "allow-no-such-command",
  ]) {
    const caps = capsFor(COMMANDS);
    caps.approvals.permissions.push(perm);
    assertFails(errorsOf(surface({ caps })), new RegExp(`permission ${perm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} is not`));
  }
  const caps = capsFor(COMMANDS);
  caps.approvals.permissions.push({ identifier: "allow-app-status", allow: [{ path: "*" }] });
  assertFails(errorsOf(surface({ caps })), /must be a plain identifier/);
});

test("event_permissions_only_for_listening_windows", () => {
  const caps = capsFor(COMMANDS);
  caps.audit.permissions.push("core:event:allow-listen");
  assertFails(errorsOf(surface({ caps })), /audit\.json: this window listens to no event/);
  const caps2 = capsFor(COMMANDS);
  caps2.approvals.permissions = caps2.approvals.permissions.filter((p) => p !== "core:event:allow-unlisten");
  assertFails(errorsOf(surface({ caps: caps2 })), /approvals\.json: a listening window needs exactly/);
});

test("capability_shape_is_strict", () => {
  const cases = [
    [(c) => (c.approvals.windows = ["approvals", "settings"]), /approvals\.json: windows must be exactly/],
    [(c) => (c.approvals.windows = ["*"]), /approvals\.json: windows must be exactly/],
    [(c) => (c.approvals.identifier = "main"), /approvals\.json: identifier must be approvals/],
    [(c) => (c.approvals.webviews = ["approvals"]), /key webviews is not allowed/],
    [(c) => (c.approvals.remote = { urls: ["https://*"] }), /key remote is not allowed/],
    [(c) => (c.approvals.local = false), /key local is not allowed/],
    [(c) => (c.approvals.platforms = ["windows"]), /key platforms is not allowed/],
    [(c) => (c.extra = { identifier: "extra", windows: ["extra"], permissions: [] }), /extra\.json is not a window label/],
    [(c) => delete c.setup, /setup\.json is missing/],
    [(c) => (c.audit = new SyntaxError("bad")), /audit\.json: not a JSON object/],
  ];
  for (const [mutate, pattern] of cases) {
    const caps = capsFor(COMMANDS);
    mutate(caps);
    assertFails(errorsOf(surface({ caps })), pattern);
  }
});

test("security_capabilities_must_list_the_seven", () => {
  for (const list of [[], undefined, LABELS.slice(1), [...LABELS, "extra"], [...LABELS.slice(1), "approvals", "approvals"]]) {
    assertFails(errorsOf(surface({ securityCapabilities: list })), /app\.security\.capabilities must be exactly/);
  }
});

test("handler_list_must_equal_commands", () => {
  assertFails(errorsOf(surface({ handlerLists: [COMMANDS.slice(1)] })), /generate_handler! lacks command app_status/);
  assertFails(errorsOf(surface({ handlerLists: [[...COMMANDS, "secret_cmd"]] })), /registers secret_cmd/);
  assertFails(errorsOf(surface({ handlerLists: [] })), /exactly one generate_handler!/);
  assertFails(errorsOf(surface({ handlerLists: [COMMANDS, COMMANDS] })), /exactly one generate_handler!/);
});

test("command_list_rules", () => {
  assertFails(errorsOf(surface({ commands: ["quit", "app_status"] })), /not sorted/);
  assertFails(errorsOf(surface({ commands: ["app_status", "app_status"] })), /duplicates/);
  assertFails(errorsOf(surface({ commands: [DROPPED_CMD] })), /reserved for the isolation hook/);
  assertFails(errorsOf(surface({ commands: null })), /COMMANDS not found/);
});

test("isolation_block_out_of_date_fails", () => {
  assertFails(errorsOf(surface({ allowed: COMMANDS })), /ALLOWED block is out of date/);
  assertFails(errorsOf(surface({ allowed: [...ALLOWED, "decide"] })), /ALLOWED block is out of date/);
  assertFails(errorsOf(surface({ allowed: [...ALLOWED, DROPPED_CMD] })), /must not list/);
  assertFails(errorsOf(surface({ allowed: null })), /ALLOWED block not found/);
  // A capability without the event permissions changes the expected block too.
  const caps = capsFor(COMMANDS);
  for (const l of LISTENING_WINDOWS) caps[l].permissions = caps[l].permissions.filter((p) => !p.startsWith("core:event"));
  assert.deepEqual(checkSurface(surface({ caps })).expectedAllowed, COMMANDS);
});

test("render_allowed_block_round_trips", () => {
  const html = `<script>\n    // keep\n    ${BEGIN_MARKER}\n    var ALLOWED = [\n      "old",\n    ];\n    ${END_MARKER}\n    var x = 1;\n</script>\n`;
  const next = renderAllowedBlock(html, ALLOWED);
  assert.deepEqual(parseAllowedBlock(next), ALLOWED);
  assert.ok(next.includes(`    ${END_MARKER}\n    var x = 1;`));
  assert.ok(next.includes(`      "plugin:event|listen",\n`));
  assert.equal(renderAllowedBlock(next, ALLOWED), next, "idempotent");
  assert.throws(() => renderAllowedBlock("<script></script>", ALLOWED));
  assert.throws(() => renderAllowedBlock(`${html}${html}`, ALLOWED));
});

test("parsers_read_names_and_handler_lists", () => {
  const names = `// c\n#[rustfmt::skip]\npub const COMMANDS: &[&str] = &[\n    "app_status",\n    // "commented_out",\n    "quit",\n];\n`;
  assert.deepEqual(parseCommandList(names), ["app_status", "quit"]);
  const modRs = `builder.invoke_handler(tauri::generate_handler![app_status, window::quit, // x\n settings::settings_get,])`;
  assert.deepEqual(parseHandlerLists(modRs), [["app_status", "quit", "settings_get"]]);
});

test("arg_struct_without_deny_unknown_fields_fails", () => {
  const src = ARGS_OK.replace("#[serde(deny_unknown_fields)]\npub struct AppStatusArgs", "pub struct AppStatusArgs");
  assertFails(argErrors(src), /argument struct AppStatusArgs lacks #\[serde\(deny_unknown_fields\)\]/);
  // A nested DTO without it fails too, and so does an `Args<T>` type not named `…Args`.
  const nested = ARGS_OK.replace("#[serde(deny_unknown_fields, rename_all", "#[serde(rename_all");
  assertFails(argErrors(nested), /RedactionOpDto has struct variants but no #\[serde\(deny_unknown_fields\)\]/);
  const named = `${ARGS_OK}\npub async fn f(args: Args<Decision>) {}\n#[derive(Deserialize)]\npub struct Decision { pub id: RequestId }\n`;
  assertFails(argErrors(named), /argument struct Decision lacks/);
  const qualified = `${ARGS_OK}\npub async fn f(args: Args<dto::Decision>) {}\n#[derive(Deserialize)]\npub struct Decision { pub id: RequestId }\n`;
  assertFails(argErrors(qualified), /argument struct Decision lacks/);
  const missing = `${ARGS_OK}\npub async fn f(args: Args<Elsewhere>) {}\n`;
  assertFails(argErrors(missing), /Elsewhere is not defined/);
  const noDerive = `${ARGS_OK}\n#[serde(deny_unknown_fields)]\npub struct BareArgs { pub id: RequestId }\n`;
  assertFails(argErrors(noDerive), /BareArgs must derive Deserialize/);
});

test("pathbuf_and_byte_fields_fail", () => {
  const field = (decl) =>
    argErrors(`${ARGS_OK}\n#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct InstanceAddArgs {\n    pub alias: String,\n    ${decl},\n}\n`);
  assertFails(field("pub dir: std::path::PathBuf"), /InstanceAddArgs has a field of a forbidden type \(\\bPathBuf\\b\)/);
  assertFails(field("pub dir: PathBuf"), /forbidden type/);
  assertFails(field("pub dir: Box<Path>"), /forbidden type/);
  assertFails(field("pub dir: OsString"), /forbidden type/);
  assertFails(field("pub ca: Vec<u8>"), /forbidden type/);
  assertFails(field("pub ca: Vec< u8 >"), /forbidden type/);
  assertFails(field("pub ca: [u8; 32]"), /forbidden type/);
  assertFails(field("pub ca_pem: String"), /InstanceAddArgs\.ca_pem: no field named like a path, PEM or certificate/);
  assertFails(field("pub client_cert: String"), /client_cert/);
  assertFails(field("pub data_path: String"), /data_path/);
  assertFails(field("pub filePath: String"), /filePath/);
  // In a nested DTO and in a hand-written `Deserialize` newtype as well.
  const nested = argErrors(`${ARGS_OK}\n#[derive(Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct Inner { pub target: PathBuf }\n`);
  assertFails(nested, /Inner has a field of a forbidden type/);
  const newtype = argErrors(`${ARGS_OK}\npub struct CaFile(std::path::PathBuf);\nimpl<'de> Deserialize<'de> for CaFile {}\n`);
  assertFails(newtype, /CaFile has a field of a forbidden type/);
  // `use_custom_ca: bool` is how instance_add asks for a certificate (Rust opens the dialog).
  assert.deepEqual(field("pub use_custom_ca: bool"), []);
});

test("test_modules_are_not_arguments", () => {
  assert.deepEqual(argErrors(ARGS_OK), []);
  // Without the cfg(test) marker the same struct is checked.
  assertFails(argErrors(ARGS_OK.replace("#[cfg(test)]", "")), /Probe/);
});
