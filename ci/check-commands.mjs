#!/usr/bin/env node
// Command surface check (M6 T4; §2.4, §10.3, C.10 + Δ1, PD-66, PD-87).
// Encodes: the command list `commands::COMMANDS` (names.rs), the one `generate_handler!` list
// (`commands::register`), the union of the capability files' app permissions and the isolation
// hook's generated `ALLOWED` block name the same commands; every command is granted in exactly the
// windows of the Δ1 table below; only the listening windows get the two event permissions and no
// window gets any other permission (no `core:default`, no plugin permission); every
// `#[tauri::command]` lives under `app/src-tauri/src/commands/**` and takes exactly one `Args<…>`
// besides injected parameters; every argument struct there denies unknown fields and carries no
// path, byte or certificate field (grep-level).
//
// Usage: node ci/check-commands.mjs [--write]
//   --write regenerates the `ALLOWED` block of app/isolation/index.html, then checks.
// Exit 0 = ok. Exit 1 = violations (one per line on stdout).
// No npm dependencies: node:fs, node:path, node:url only.

import { readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

/** The seven window labels (C.10 + Δ1, PD-72); one capability file each. */
export const LABELS = [
  "approvals",
  "settings",
  "audit",
  "running_scripts",
  "onboarding",
  "credential",
  "setup",
];

// C.10 + Δ1 (master plan, M6 plan "Contract deltas"): the windows each command may exist in.
// A command in `COMMANDS` must be granted in exactly these windows; a name listed here but not
// yet in `COMMANDS` is a later task's.
export const WINDOW_COMMANDS = {
  approvals: [
    "queue_list",
    "queue_get",
    "preview_fetch",
    "raw_page",
    "decide",
    "decide_batch",
    "deny_batch",
    "deny_session",
    "redaction_preview",
    "recent_list",
    "acknowledge_attention",
    "open_window",
    "quit",
    "app_status",
  ],
  settings: [
    "settings_get",
    "settings_apply",
    "instance_add",
    "instance_change_url",
    "instance_confirm_config",
    "instance_accept_url_change",
    "instance_set_proxy",
    "credential_window_open",
    "retest_token",
    "prune_backlog_now",
    "cli_install",
    "cli_uninstall",
    // M6 T28 (PD-88): the "Prepare for removal" step machine's five commands.
    "removal_state",
    "removal_backup",
    "removal_begin",
    "removal_mark",
    "removal_finish",
    "app_status",
    // M10 T13 (Δ-M10-3, PD-168): "Back up now" (the Audit window's trigger) and "Restore backup…".
    "backup_trigger",
    "restore_begin",
    "restore_cancel",
    // M10 T14 (Δ-M10-3, PD-166, PD-169, PD-170): the recovery passphrase change (its secret enters
    // the credential window), the anchor directory, re-anchor and "Forget old install".
    "recovery_passphrase_change",
    "anchor_dir_set",
    "anchor_dir_remove",
    "re_anchor",
    "orphan_installs",
    "forget_install",
  ],
  // M6: `verify_now` (P8); M10 T12 (Δ-M10-3, L201): the queries, the payload view, the incident
  // acknowledgement and the export/backup triggers (`backup_trigger` also in settings, T13).
  audit: [
    "verify_now",
    "audit_query",
    "audit_payload",
    "audit_trail",
    "audit_status",
    "acknowledge_incident",
    "export_trigger",
    "export_cancel",
    "backup_trigger",
  ],
  running_scripts: ["running_list", "running_kill"],
  onboarding: ["onboarding_text"],
  credential: [
    "submit_secret",
    "credential_context",
    "save_recovery_note",
    "archive_and_start_fresh",
    "retry_keychain",
    // M6 T25 (T21 review I-4): the page's own Close / Cancel; credential only, like the OS close.
    "close_credential",
    "quit",
    // M10 T13 (Δ-M10-3, L201, PD-168): "Restore a backup instead" in the `keychain_lost` state.
    "restore_from_backup",
  ],
  setup: [
    "wizard_state",
    "wizard_use_default_dir",
    "wizard_choose_dir",
    "wizard_begin",
    "wizard_skip_instances",
    "wizard_finish",
    "instance_add",
    "instance_change_url",
    "instance_confirm_config",
    "instance_accept_url_change",
    "cli_install",
    "onboarding_text",
    "quit",
  ],
};

/**
 * The windows that listen to events (C.10 + Δ1 events): they, and only they, get both. The Audit
 * window since M10 T12 (Δ-M10-3: `audit_job` progress, `audit_changed`).
 */
export const LISTENING_WINDOWS = ["approvals", "settings", "audit", "running_scripts", "credential", "setup"];

/** The only non-app permissions a capability file may hold, and the IPC command each grants. */
export const EVENT_PERMISSIONS = {
  "core:event:allow-listen": "plugin:event|listen",
  "core:event:allow-unlisten": "plugin:event|unlisten",
};

/** The isolation hook's replacement name for a dropped message; never a command. */
export const DROPPED_CMD = "__atlas_duck_isolation_dropped__";

/**
 * Argument structs exempt from the field rules, as `"<file>:<struct>"`. Must stay empty (§10.3:
 * no command accepts a path, certificate bytes or a `PathBuf`-bearing type).
 */
export const ARG_EXEMPTIONS = [];

// Core types that carry a `PathBuf` count as one (T4 review M-3; grep cannot see inside them):
// `SessionKey.peer_origin_exe` (PD-86), `KeyOrigin::Exe`, `InstanceConfig.ca_bundle`.
const FORBIDDEN_TYPES = [
  /\bPathBuf\b/,
  /\bPath\b/,
  /\bOsString\b/,
  /\bOsStr\b/,
  /\bVec\s*<\s*u8\s*>/,
  /\[\s*u8\s*;/,
  /\bSessionKey\b/,
  /\bKeyOrigin\b/,
  /\bInstanceConfig\b/,
];
// path, PEM and certificate anywhere in a name; file, folder, directory, bytes and blob as a whole
// snake_case word ("profile" and "redirect" stay allowed).
const FORBIDDEN_FIELD_NAME = /path|pem|cert|(^|_)(file|dir|directory|folder|bytes|blob)s?(_|$)/i;

export const BEGIN_MARKER = "// BEGIN GENERATED (node ci/check-commands.mjs --write)";
export const END_MARKER = "// END GENERATED";

// ---------- parsing ----------

/** Rust source without comments (string contents kept; good enough for these files). */
export function stripComments(src) {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
    } else if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
    } else if (c === "/" && n === "*") {
      let depth = 1;
      i += 2;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") (depth += 1), (i += 2);
        else if (src[i] === "*" && src[i + 1] === "/") (depth -= 1), (i += 2);
        else i += 1;
      }
      out += " ";
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Index just past the brace block opening at `open` (`src[open] === "{"`). */
function closeBrace(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    if (src[i] === "{") depth += 1;
    else if (src[i] === "}") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return src.length;
}

/** Removes `#[cfg(test)] mod x { … }` blocks (test-only structs are not arguments). */
export function stripTestModules(src) {
  const re = /#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{/g;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(src)) !== null) {
    const open = m.index + m[0].length - 1;
    const end = closeBrace(src, open);
    out += src.slice(last, m.index);
    last = end;
    re.lastIndex = end;
  }
  return out + src.slice(last);
}

/** `COMMANDS` from names.rs. */
export function parseCommandList(namesRs) {
  const m = stripComments(namesRs).match(/COMMANDS\s*:\s*&\[\s*&str\s*\]\s*=\s*&\[([\s\S]*?)\];/);
  if (!m) return null;
  return [...m[1].matchAll(/"([^"]*)"/g)].map((x) => x[1]);
}

/** The function names of every `generate_handler![…]` in `src` (last path segment). */
export function parseHandlerLists(modRs) {
  const src = stripComments(modRs);
  return [...src.matchAll(/generate_handler!\s*\[([\s\S]*?)\]/g)].map((m) =>
    m[1]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => s.split("::").pop()),
  );
}

/** The quoted entries between the isolation markers, or null. */
export function parseAllowedBlock(html) {
  const begin = html.indexOf(BEGIN_MARKER);
  const end = html.indexOf(END_MARKER);
  if (begin < 0 || end < begin) return null;
  return [...html.slice(begin, end).matchAll(/"([^"]*)"/g)].map((m) => m[1]);
}

/** The isolation html with its `ALLOWED` block rewritten to `entries`. */
export function renderAllowedBlock(html, entries) {
  const begin = html.indexOf(BEGIN_MARKER);
  const end = html.indexOf(END_MARKER);
  if (begin < 0 || end < begin || html.indexOf(BEGIN_MARKER, begin + 1) >= 0) {
    throw new Error("isolation html: expected exactly one generated block");
  }
  const lineStart = html.lastIndexOf("\n", begin) + 1;
  const indent = html.slice(lineStart, begin);
  const block = [
    BEGIN_MARKER,
    `${indent}var ALLOWED = [`,
    ...entries.map((e) => `${indent}  ${JSON.stringify(e)},`),
    `${indent}];`,
    `${indent}`,
  ].join("\n");
  return html.slice(0, begin) + block + html.slice(end);
}

/** The app-manifest permission id of a command (tauri-build writes `_` as `-`). */
export function allowPermission(command) {
  return `allow-${command.replace(/_/g, "-")}`;
}

// ---------- checks ----------

/**
 * Cross-checks the command list, the handler list, the capability files and the isolation block.
 * `caps`: { [fileStem]: parsed JSON | Error }. `securityCapabilities`: tauri.conf.json's
 * `app.security.capabilities`. Returns the expected `ALLOWED` entries and the violations.
 */
export function checkSurface({ commands, handlerLists, caps, securityCapabilities, allowed }) {
  const errors = [];
  if (!commands) {
    errors.push("names.rs: COMMANDS not found");
    return { errors, expectedAllowed: [] };
  }
  const commandSet = new Set(commands);
  if (commandSet.size !== commands.length) errors.push("names.rs: COMMANDS has duplicates");
  if ([...commands].sort().join() !== commands.join()) errors.push("names.rs: COMMANDS is not sorted");
  for (const c of commands) {
    if (!/^[a-z][a-z0-9_]*$/.test(c)) errors.push(`names.rs: command name ${JSON.stringify(c)} is not snake_case`);
  }
  if (commandSet.has(DROPPED_CMD)) errors.push(`names.rs: ${DROPPED_CMD} is reserved for the isolation hook`);

  // generate_handler! == COMMANDS
  if (handlerLists.length !== 1) {
    errors.push(`commands/mod.rs: expected exactly one generate_handler! list, found ${handlerLists.length}`);
  } else {
    const handlers = new Set(handlerLists[0]);
    for (const c of commands) if (!handlers.has(c)) errors.push(`generate_handler! lacks command ${c}`);
    for (const h of handlers) if (!commandSet.has(h)) errors.push(`generate_handler! registers ${h}, which COMMANDS does not list`);
  }

  // tauri.conf.json lists the seven capabilities explicitly (an empty list means "every file").
  const listed = Array.isArray(securityCapabilities) ? securityCapabilities : null;
  if (!listed || [...listed].sort().join() !== [...LABELS].sort().join() || listed.length !== LABELS.length) {
    errors.push(`tauri.conf.json: app.security.capabilities must be exactly ${JSON.stringify(LABELS)}`);
  }

  // capability files
  const stems = Object.keys(caps).sort();
  for (const label of LABELS) if (!stems.includes(label)) errors.push(`capabilities/${label}.json is missing`);
  for (const stem of stems) if (!LABELS.includes(stem)) errors.push(`capabilities/${stem}.json is not a window label`);

  const grantedIn = new Map(); // command -> Set(label)
  const eventCommands = new Set();
  for (const label of LABELS) {
    const cap = caps[label];
    if (cap === undefined) continue;
    const where = `capabilities/${label}.json`;
    if (cap instanceof Error || typeof cap !== "object" || cap === null || Array.isArray(cap)) {
      errors.push(`${where}: not a JSON object`);
      continue;
    }
    for (const key of Object.keys(cap)) {
      if (!["identifier", "description", "windows", "permissions"].includes(key)) {
        errors.push(`${where}: key ${key} is not allowed (no webviews, remote, local or platforms)`);
      }
    }
    if (cap.identifier !== label) errors.push(`${where}: identifier must be ${label}`);
    if (!Array.isArray(cap.windows) || cap.windows.length !== 1 || cap.windows[0] !== label) {
      errors.push(`${where}: windows must be exactly ["${label}"]`);
    }
    const perms = Array.isArray(cap.permissions) ? cap.permissions : null;
    if (!perms) {
      errors.push(`${where}: permissions must be an array`);
      continue;
    }
    if (new Set(perms.map(String)).size !== perms.length) errors.push(`${where}: duplicate permission`);
    const events = [];
    for (const p of perms) {
      if (typeof p !== "string") {
        errors.push(`${where}: permission ${JSON.stringify(p)} must be a plain identifier (no scopes)`);
        continue;
      }
      if (Object.hasOwn(EVENT_PERMISSIONS, p)) {
        events.push(p);
        eventCommands.add(EVENT_PERMISSIONS[p]);
        continue;
      }
      const command = commands.find((c) => allowPermission(c) === p);
      if (!command) {
        errors.push(`${where}: permission ${p} is not an allow-<command> of COMMANDS or an event permission`);
        continue;
      }
      if (!grantedIn.has(command)) grantedIn.set(command, new Set());
      grantedIn.get(command).add(label);
    }
    const listens = LISTENING_WINDOWS.includes(label);
    const wanted = listens ? Object.keys(EVENT_PERMISSIONS) : [];
    if (events.sort().join() !== [...wanted].sort().join()) {
      errors.push(
        listens
          ? `${where}: a listening window needs exactly ${Object.keys(EVENT_PERMISSIONS).join(" and ")}`
          : `${where}: this window listens to no event; no event permission`,
      );
    }
  }

  // every command in exactly its Δ1 windows
  for (const c of commands) {
    const want = LABELS.filter((l) => WINDOW_COMMANDS[l].includes(c));
    const have = LABELS.filter((l) => grantedIn.get(c)?.has(l));
    if (want.length === 0) {
      errors.push(`command ${c} is in no window of the Δ1 table (ci/check-commands.mjs WINDOW_COMMANDS)`);
      continue;
    }
    for (const l of want) if (!have.includes(l)) errors.push(`command ${c} is missing from capabilities/${l}.json`);
    for (const l of have) if (!want.includes(l)) errors.push(`command ${c} is granted to ${l}, outside its Δ1 windows (${want.join(", ")})`);
  }

  // isolation ALLOWED == COMMANDS + the granted event commands
  const expectedAllowed = [...commands, ...[...eventCommands].sort()];
  if (!allowed) {
    errors.push("app/isolation/index.html: generated ALLOWED block not found");
  } else if (allowed.join("\n") !== expectedAllowed.join("\n")) {
    errors.push("app/isolation/index.html: ALLOWED block is out of date (run node ci/check-commands.mjs --write)");
  }
  if (allowed?.includes(DROPPED_CMD)) errors.push(`app/isolation/index.html: ALLOWED must not list ${DROPPED_CMD}`);
  return { errors, expectedAllowed };
}

/** Items (struct/enum) with their attributes, name, kind and body, from comment-free source. */
export function parseItems(src) {
  const items = [];
  const re = /((?:#\[[^\]]*(?:\[[^\]]*\][^\]]*)*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)(?:\s*<[^>{(;]*>)?/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    let i = re.lastIndex;
    while (i < src.length && /\s/.test(src[i])) i += 1;
    let body = "";
    let shape = "unit";
    if (src[i] === "{") {
      const end = closeBrace(src, i);
      body = src.slice(i + 1, end - 1);
      shape = "braced";
      re.lastIndex = end;
    } else if (src[i] === "(") {
      const end = src.indexOf(";", i);
      body = src.slice(i + 1, end < 0 ? src.length : end);
      shape = "tuple";
      re.lastIndex = end < 0 ? src.length : end;
    } else if (/^where\b/.test(src.slice(i))) {
      const open = src.indexOf("{", i);
      const end = closeBrace(src, open);
      body = src.slice(open + 1, end - 1);
      shape = "braced";
      re.lastIndex = end;
    }
    items.push({ attrs: m[1], kind: m[2], name: m[3], body, shape });
  }
  return items;
}

/** The field declarations `name: Type` of a braced body (enum variants' fields included). */
function fields(body) {
  return [...body.matchAll(/(?:^|[{,(\s])(?:pub(?:\([^)]*\))?\s+)?(r#)?([A-Za-z_]\w*)\s*:\s*([^,{}]+(?:<[^>]*>)?)/g)].map(
    (m) => ({ name: m[2], type: m[3].trim() }),
  );
}

/**
 * The argument-struct rules over `files` ({path: source}). An argument struct is any type named
 * in `Args<…>` or any struct whose name ends in `Args`; it must be a struct deriving `Deserialize`
 * with `#[serde(deny_unknown_fields)]`. Every type in these files that derives or implements
 * `Deserialize` (argument structs and the DTOs they nest) has no `PathBuf`/`Path`/`OsString`/byte
 * field and no field named like a path, PEM or certificate.
 */
export function checkArgStructs(files, exemptions = ARG_EXEMPTIONS) {
  const errors = [];
  const items = new Map(); // name -> {file, item}
  const argNames = new Map(); // name -> file of first use
  const handImpl = new Set();
  for (const [file, raw] of Object.entries(files)) {
    const src = stripTestModules(stripComments(raw));
    const parsed = parseItems(src);
    for (const item of parsed) items.set(item.name, { file, item });
    for (const m of src.matchAll(/\bArgs\s*<\s*(?:\w+\s*::\s*)*([A-Za-z_]\w*)\s*>/g)) {
      if (m[1].length > 1 && !argNames.has(m[1])) argNames.set(m[1], file);
    }
    for (const m of src.matchAll(/impl\s*<[^>]*>\s*(?:serde::)?Deserialize\s*<[^>]*>\s*for\s+(\w+)/g)) handImpl.add(m[1]);
    for (const item of parsed) {
      if (item.kind === "struct" && /Args$/.test(item.name) && item.name !== "Args" && !argNames.has(item.name)) {
        argNames.set(item.name, file);
      }
    }
  }
  const exempt = (file, name) => exemptions.includes(`${file}:${name}`);

  for (const [name, usedIn] of argNames) {
    const found = items.get(name);
    if (!found) {
      errors.push(`${usedIn}: argument struct ${name} is not defined under app/src-tauri/src/commands`);
      continue;
    }
    const { file, item } = found;
    if (exempt(file, name)) continue;
    if (item.kind !== "struct") errors.push(`${file}: argument type ${name} must be a struct`);
    if (!/#\[derive\([^)]*\bDeserialize\b/.test(item.attrs)) errors.push(`${file}: argument struct ${name} must derive Deserialize`);
    if (!/#\[serde\([^)]*\bdeny_unknown_fields\b/.test(item.attrs)) {
      errors.push(`${file}: argument struct ${name} lacks #[serde(deny_unknown_fields)]`);
    }
  }

  for (const [name, { file, item }] of items) {
    const derives = /#\[derive\([^)]*\bDeserialize\b/.test(item.attrs);
    if (!derives && !handImpl.has(name) && !argNames.has(name)) continue;
    if (exempt(file, name)) continue;
    if (derives && item.kind === "struct" && item.shape === "braced" && !/#\[serde\([^)]*\bdeny_unknown_fields\b/.test(item.attrs)) {
      errors.push(`${file}: ${name} derives Deserialize without #[serde(deny_unknown_fields)]`);
    }
    if (derives && item.kind === "enum" && /\{/.test(item.body) && !/#\[serde\([^)]*\bdeny_unknown_fields\b/.test(item.attrs)) {
      errors.push(`${file}: ${name} has struct variants but no #[serde(deny_unknown_fields)]`);
    }
    // T3's field naming (`dto::parse`, a thread-local the bounded newtypes set) holds only while
    // nothing retries after a failed inner deserialize: no untagged enum, no flatten, no default
    // around a bounded newtype (plain, `Option<>` or `Vec<>` fields only).
    const serdeAttrs = [...`${item.attrs}\n${item.body}`.matchAll(/#\[serde\(([^\]]*)\)\]/g)].map((m) => m[1]);
    for (const word of ["untagged", "flatten"]) {
      if (serdeAttrs.some((a) => new RegExp(`\\b${word}\\b`).test(a))) {
        errors.push(`${file}: ${name} uses #[serde(${word})]; it breaks the refused-field naming of dto::parse`);
      }
    }
    const bounded = [...handImpl].filter((t) => t !== name);
    const mentionsBounded = (type) => bounded.some((t) => new RegExp(`\\b${t}\\b`).test(type));
    if (/#\[serde\([^\]]*\bdefault\b/.test(item.attrs) && fields(item.body).some((f) => mentionsBounded(f.type))) {
      errors.push(`${file}: ${name} has #[serde(default)] around a bounded newtype field`);
    }
    for (const m of item.body.matchAll(/#\[serde\(([^\]]*)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*([^,}]+)/g)) {
      if (/\bdefault\b/.test(m[1]) && mentionsBounded(m[3])) {
        errors.push(`${file}: ${name}.${m[2]}: no #[serde(default)] on a bounded newtype field`);
      }
    }
    for (const re of FORBIDDEN_TYPES) {
      if (re.test(item.body)) errors.push(`${file}: ${name} has a field of a forbidden type (${re.source}); no command takes a path or bytes (§10.3)`);
    }
    // The wire name counts as much as the Rust one: `#[serde(rename = "ca_path")]` (also the
    // `rename(deserialize = "..")` form, `rename_all` and `alias`) is a field the webview can set.
    for (const attr of serdeAttrs) {
      const quoted = [...attr.matchAll(/\b(?:rename|rename_all|alias)\b\s*(?:=\s*"([^"]*)"|\(([^)]*)\))/g)].flatMap((m) =>
        m[1] !== undefined ? [m[1]] : [...m[2].matchAll(/"([^"]*)"/g)].map((q) => q[1]),
      );
      for (const wire of quoted) {
        if (FORBIDDEN_FIELD_NAME.test(wire)) {
          errors.push(`${file}: ${name}: serde name "${wire}": no wire name like a path, PEM or certificate (§10.3)`);
        }
      }
    }
    for (const f of fields(item.body)) {
      if (FORBIDDEN_FIELD_NAME.test(f.name)) {
        errors.push(`${file}: ${name}.${f.name}: no field named like a path, PEM or certificate (§10.3)`);
      }
    }
  }
  return errors;
}

/**
 * The parameters Tauri injects instead of reading a body key (T3 contract: a command takes these
 * plus its one `Args<…>`). `ipc::Channel` and `ipc::Request` are deliberately absent: both read
 * the invoke body and would bypass `Args`.
 */
export const INJECTED_PARAMS = ["AppHandle", "State", "Window", "WebviewWindow", "Webview"];

const COMMANDS_DIR = "app/src-tauri/src/commands/";
const INJECTED_TYPE = new RegExp(`^(?:tauri\\s*::\\s*(?:[a-z_]+\\s*::\\s*)?)?(?:${INJECTED_PARAMS.join("|")})\\s*(?:<|$)`);
const ARGS_TYPE = /^(?:\w+\s*::\s*)*Args\s*</;

/** Index just past the bracket group opening at `open` (`()`, `<>` or `[]`, nesting counted). */
function closeGroup(src, open) {
  const pairs = { "(": ")", "<": ">", "[": "]", "{": "}" };
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    const c = src[i];
    if (c === "-" && src[i + 1] === ">") {
      i += 1;
    } else if (c in pairs) {
      depth += 1;
    } else if (Object.values(pairs).includes(c)) {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return src.length;
}

/** `list` split on commas outside any bracket group. */
function splitTopLevel(list, sep) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < list.length; i += 1) {
    const c = list[i];
    if (c === "-" && list[i + 1] === ">") i += 1;
    else if ("(<[{".includes(c)) depth += 1;
    else if (")>]}".includes(c)) depth -= 1;
    else if (c === sep && depth === 0) {
      parts.push(list.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(list.slice(start));
  return parts.map((p) => p.trim()).filter(Boolean);
}

/** `{ name, params: [{ pattern, type }] }` per `#[tauri::command]` fn in comment-free `src`. */
export function parseCommandFns(src) {
  const fns = [];
  for (const m of src.matchAll(/#\[\s*(?:tauri\s*::\s*)?command\b[^\]]*\]/g)) {
    const rest = src.slice(m.index + m[0].length);
    const head = rest.match(/^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*/);
    if (!head) {
      fns.push({ name: null, params: null });
      continue;
    }
    let i = head[0].length;
    if (rest[i] === "<") i = closeGroup(rest, i);
    while (/\s/.test(rest[i] ?? "")) i += 1;
    if (rest[i] !== "(") {
      fns.push({ name: head[1], params: null });
      continue;
    }
    const end = closeGroup(rest, i);
    const params = splitTopLevel(rest.slice(i + 1, end - 1), ",").map((p) => {
      // The first `:` outside brackets that is not half of a `::`.
      let depth = 0;
      for (let k = 0; k < p.length; k += 1) {
        const c = p[k];
        if ("(<[{".includes(c)) depth += 1;
        else if (")>]}".includes(c)) depth -= 1;
        else if (c === ":" && depth === 0) {
          if (p[k + 1] === ":") k += 1;
          else return { pattern: p.slice(0, k).trim(), type: p.slice(k + 1).trim() };
        }
      }
      return { pattern: p, type: "" };
    });
    fns.push({ name: head[1], params });
  }
  return fns;
}

/**
 * T4 review I-2: every `#[tauri::command]` in `srcFiles` ({path: source}, all of
 * `app/src-tauri/src`) is defined under `commands/**`, is listed in `COMMANDS`, and takes exactly
 * one `Args<…>` besides the injected parameters (Tauri maps any other parameter to a body key,
 * outside `deny_unknown_fields` and the field rules); every `COMMANDS` entry has such a fn.
 */
export function checkCommandHandlers(srcFiles, commands) {
  const errors = [];
  const defined = new Set();
  for (const [file, raw] of Object.entries(srcFiles)) {
    const src = stripTestModules(stripComments(raw));
    for (const { name, params } of parseCommandFns(src)) {
      if (name === null || params === null) {
        errors.push(`${file}: cannot parse the fn after #[tauri::command]${name ? ` (${name})` : ""}`);
        continue;
      }
      defined.add(name);
      if (!file.startsWith(COMMANDS_DIR)) {
        errors.push(`${file}: #[tauri::command] ${name} is defined outside ${COMMANDS_DIR}**`);
      }
      if (commands && !commands.includes(name)) errors.push(`${file}: #[tauri::command] ${name} is not in COMMANDS`);
      const args = params.filter((p) => ARGS_TYPE.test(p.type));
      if (args.length !== 1) {
        errors.push(`${file}: command ${name} must take exactly one Args<…> argument struct (found ${args.length})`);
      }
      for (const p of params) {
        if (ARGS_TYPE.test(p.type) || INJECTED_TYPE.test(p.type)) continue;
        errors.push(
          `${file}: command ${name} parameter \`${p.pattern}: ${p.type}\` is neither Args<…> nor injected (${INJECTED_PARAMS.join("/")}); Tauri would read it from a body key`,
        );
      }
    }
  }
  for (const c of commands ?? []) {
    if (!defined.has(c)) errors.push(`COMMANDS lists ${c}, but no #[tauri::command] fn ${c} is defined`);
  }
  return errors;
}

/**
 * T3 review M-9: Tauri's default `dynamic-acl` feature ships `add_capability` and
 * `runtime_authority_mut`; app code never widens the capability files at run time (tests may).
 */
export function checkAclMutators(files) {
  const errors = [];
  for (const [file, raw] of Object.entries(files)) {
    const src = stripTestModules(stripComments(raw));
    for (const call of ["add_capability", "runtime_authority_mut"]) {
      if (new RegExp(`\\b${call}\\s*\\(`).test(src)) errors.push(`${file}: ${call} widens the capability files at run time (§10.3)`);
    }
  }
  return errors;
}

// ---------- CLI ----------

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

function rustFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...rustFiles(p));
    else if (name.endsWith(".rs")) out.push(p);
  }
  return out;
}

export function readRepo(repo = REPO) {
  const app = join(repo, "app", "src-tauri");
  const capDir = join(app, "capabilities");
  const caps = {};
  for (const name of readdirSync(capDir)) {
    if (!name.endsWith(".json")) continue;
    try {
      caps[name.slice(0, -5)] = JSON.parse(readFileSync(join(capDir, name), "utf8"));
    } catch (e) {
      caps[name.slice(0, -5)] = e;
    }
  }
  const conf = JSON.parse(readFileSync(join(app, "tauri.conf.json"), "utf8"));
  const files = {};
  const srcFiles = {};
  for (const p of rustFiles(join(app, "src"))) {
    const rel = relative(repo, p).replace(/\\/g, "/");
    srcFiles[rel] = readFileSync(p, "utf8");
    if (rel.startsWith("app/src-tauri/src/commands/")) files[rel] = srcFiles[rel];
  }
  return {
    namesRs: readFileSync(join(app, "src", "commands", "names.rs"), "utf8"),
    modRs: readFileSync(join(app, "src", "commands", "mod.rs"), "utf8"),
    caps,
    securityCapabilities: conf?.app?.security?.capabilities,
    isolationPath: join(repo, "app", "isolation", "index.html"),
    files,
    srcFiles,
  };
}

export function main(argv = process.argv.slice(2), repo = REPO) {
  const write = argv.includes("--write");
  const r = readRepo(repo);
  let html = readFileSync(r.isolationPath, "utf8");
  const input = {
    commands: parseCommandList(r.namesRs),
    handlerLists: parseHandlerLists(r.modRs),
    caps: r.caps,
    securityCapabilities: r.securityCapabilities,
    allowed: parseAllowedBlock(html),
  };
  if (write) {
    const { expectedAllowed } = checkSurface(input);
    const next = renderAllowedBlock(html, expectedAllowed);
    if (next !== html) {
      writeFileSync(r.isolationPath, next);
      html = next;
    }
    input.allowed = parseAllowedBlock(html);
  }
  const errors = [
    ...checkSurface(input).errors,
    ...checkCommandHandlers(r.srcFiles, input.commands),
    ...checkArgStructs(r.files),
    ...checkAclMutators(r.srcFiles),
  ];
  for (const e of errors) console.log(e);
  if (errors.length === 0) console.log("check-commands: ok");
  return errors.length === 0 ? 0 : 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
