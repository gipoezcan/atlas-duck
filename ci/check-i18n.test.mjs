// node --test ci/check-i18n.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  I18N_SAME_ALLOWLIST,
  SHORT_KEYS,
  checkErrorCodes,
  checkLeaves,
  main,
  parseCmdKinds,
  parseEnvelopeCodes,
  parseServerCodes,
  parseTsDict,
} from "./check-i18n.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------- fixtures ----------

const ENVELOPE_RS = `
pub enum ErrorCode { Usage, NeedsToken }
impl ErrorCode {
    pub const ALL: [ErrorCode; 2] = [
        ErrorCode::Usage,
        ErrorCode::NeedsToken,
    ];
}`;

const CMD_RS = `
pub enum CmdError {
    InvalidArgument {
        field: &'static str,
    },
    NotFound,
    Decision(DecisionError),
    AuditUnreadable {
        seq: u64,
    },
    Internal,
}
impl CmdError { fn x() { match self { CmdError::Other => 1 } } }`;

const ERRORS_RS = `
impl ApiError {
    pub const NOT_FOUND: ApiError = e(StatusCode::NOT_FOUND, "api/not_found", "Not found.");
    pub const INTERNAL: ApiError = e(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal error.",
    );
    pub fn rate_limited() -> ApiError {
        ApiError { ..e(StatusCode::TOO_MANY_REQUESTS, "auth/rate_limited", "x") }
    }
}
#[cfg(test)]
mod tests { fn t() { e(StatusCode::OK, "test/only", "x"); } }`;

const dict = (envelope, cmd, server) => `
export const errors = {
  envelope: { ${envelope} },
  cmd: { ${cmd} },
  server: { ${server} },
  generic: (code: string) => \`Something (\${code})\`,
} as const;`;

const FULL = {
  envelope: "usage: 'U', needs_token: 'N'",
  cmd: "invalid_argument: 'I', not_found: 'F', audit_unreadable: 'A', internal: 'X'",
  server: "'api/not_found': 'S', internal: 'Y', 'auth/rate_limited': 'R'",
};
const fullSrc = () => dict(FULL.envelope, FULL.cmd, FULL.server);
const rust = () => ({
  envelope: parseEnvelopeCodes(ENVELOPE_RS),
  cmd: parseCmdKinds(CMD_RS),
  server: parseServerCodes(ERRORS_RS),
});

// ---------- parsers ----------

test("parsers read the three Rust code sets", () => {
  assert.deepEqual(parseEnvelopeCodes(ENVELOPE_RS), ["usage", "needs_token"]);
  assert.deepEqual(parseCmdKinds(CMD_RS), ["invalid_argument", "not_found", "audit_unreadable", "internal"]);
  assert.deepEqual(parseServerCodes(ERRORS_RS), ["api/not_found", "internal", "auth/rate_limited"]);
});

test("parseTsDict builds a tree of string leaves and skips functions", () => {
  const tree = parseTsDict(fullSrc(), "errors");
  assert.equal(tree.server["api/not_found"], "S");
  assert.equal(tree.generic, null);
  assert.deepEqual(Object.keys(tree.envelope), ["usage", "needs_token"]);
});

test("parseTsDict handles a typed export, escapes, comments and nested braces in templates", () => {
  const src = `export const common: Dict['common'] = {
    // a comment, with a comma
    a: "it's \\"x\\"", /* c */ b: 'it\\'s',
    f: (n) => \`\${n} {x} \${n === 1 ? '}' : ','}\`,
    list: ['a', 'b'],
    nested: { c: 'd' },
  };`;
  const tree = parseTsDict(src, "common");
  assert.equal(tree.a, `it's "x"`);
  assert.equal(tree.b, "it's");
  assert.equal(tree.f, null);
  assert.equal(tree.list, null);
  assert.deepEqual(tree.nested, { c: "d" });
});

// ---------- (a) code coverage ----------

test("all codes present in both languages: ok", () => {
  const src = fullSrc();
  assert.deepEqual(checkErrorCodes(rust(), src, src), []);
});

test("a missing German code is a violation naming it", () => {
  const de = dict("usage: 'U'", FULL.cmd, FULL.server);
  const errors = checkErrorCodes(rust(), fullSrc(), de);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /de\/errors\.ts/);
  assert.match(errors[0], /needs_token/);
});

test("a stale UI code that Rust does not have is a violation", () => {
  const stale = dict(FULL.envelope, FULL.cmd, FULL.server + ", 'api/gone': 'G'");
  const errors = checkErrorCodes(rust(), fullSrc(), stale);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /api\/gone/);
  assert.match(errors[0], /not in Rust/);
});

test("a missing section is a violation, not a crash", () => {
  const errors = checkErrorCodes(rust(), "export const errors = { generic: () => 'x' } as const;", fullSrc());
  assert.ok(errors.some((e) => /envelope/.test(e)));
});

// ---------- (b)-(d) leaves ----------

const tree = (o) => o;

test("an identical leaf that is not allowlisted is a violation", () => {
  const errors = checkLeaves({ common: tree({ ok: "OK" }) }, { common: tree({ ok: "OK" }) }, {}, []);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /common\.ok/);
});

test("an allowlisted identical leaf is ok", () => {
  const errors = checkLeaves(
    { common: tree({ ok: "OK" }) },
    { common: tree({ ok: "OK" }) },
    { "common.ok": "same word in both languages" },
    [],
  );
  assert.deepEqual(errors, []);
});

test("an allowlist entry whose leaves differ is stale", () => {
  const errors = checkLeaves(
    { common: tree({ ok: "OK" }) },
    { common: tree({ ok: "In Ordnung" }) },
    { "common.ok": "reason" },
    [],
  );
  assert.equal(errors.length, 1);
  assert.match(errors[0], /stale allowlist/);
});

test("an empty leaf is a violation in either language", () => {
  const errors = checkLeaves({ common: tree({ a: "", b: "x" }) }, { common: tree({ a: "a", b: "" }) }, {}, []);
  assert.equal(errors.length, 2);
  assert.ok(errors.some((e) => /en .*common\.a/.test(e)));
  assert.ok(errors.some((e) => /de .*common\.b/.test(e)));
});

test("a short key longer than 1.5x English + 4 is a violation", () => {
  const en = { common: tree({ ok: "Save" }) };
  assert.deepEqual(checkLeaves(en, { common: tree({ ok: "Speichern!" }) }, {}, ["common.ok"]), []); // 10 <= 1.5*4+4
  const errors = checkLeaves(en, { common: tree({ ok: "Speichern jetzt" }) }, {}, ["common.ok"]); // 15 > 10
  assert.equal(errors.length, 1);
  assert.match(errors[0], /common\.ok/);
});

test("a key missing from German is a violation, and an extra German key too", () => {
  const errors = checkLeaves({ common: tree({ a: "A", b: "B" }) }, { common: tree({ a: "Ä", c: "C" }) }, {}, []);
  assert.equal(errors.length, 2);
  assert.ok(errors.some((e) => /common\.b/.test(e)));
  assert.ok(errors.some((e) => /common\.c/.test(e)));
});

test("allowlist entries carry a reason", () => {
  for (const [path, reason] of Object.entries(I18N_SAME_ALLOWLIST)) {
    assert.ok(typeof reason === "string" && reason.length > 8, path);
  }
  assert.ok("common.lang_de" in I18N_SAME_ALLOWLIST);
  assert.ok("common.lang_en" in I18N_SAME_ALLOWLIST);
  assert.ok(Array.isArray(SHORT_KEYS));
});

// ---------- the repository ----------

test("the repository passes", () => {
  const lines = [];
  const log = console.log;
  console.log = (l) => lines.push(l);
  try {
    assert.equal(main([], REPO), 0, lines.join("\n"));
  } finally {
    console.log = log;
  }
});
