import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fileURLToPath } from "node:url";

import { EXEMPT, findControlBytes, main, scan } from "./check-control-bytes.mjs";

const REPO = join(fileURLToPath(new URL(".", import.meta.url)), "..");

const bytes = (...parts) => Buffer.concat(parts.map((p) => (typeof p === "string" ? Buffer.from(p, "utf8") : Buffer.from(p))));

test("plain text, LF, CRLF and umlauts are clean", () => {
  assert.deepEqual(findControlBytes(bytes("a\nb\r\nc äöü —\n")), []);
});

test("TAB, BEL, FF, NUL and DEL are found with their position", () => {
  const hits = findControlBytes(bytes("ab\n", [0x09], "x", [0x07], [0x0c], [0x00], [0x7f]));
  assert.deepEqual(
    hits.map((h) => [h.line, h.column, h.byte]),
    [
      [2, 1, 0x09],
      [2, 3, 0x07],
      [2, 4, 0x0c],
      [2, 5, 0x00],
      [2, 6, 0x7f],
    ],
  );
});

test("a TAB is a finding in every file type, a CRLF line end is not, a lone CR is", () => {
  assert.equal(findControlBytes(bytes("a", [0x09], "b")).length, 1);
  assert.deepEqual(findControlBytes(bytes("a\r\nb\r\n")), []);
  const lone = findControlBytes(bytes("a\rb\n"));
  assert.deepEqual(lone.map((h) => [h.line, h.column, h.lone]), [[1, 2, true]]);
});
test("a byte order mark is reported", () => {
  const hits = findControlBytes(bytes([0xef, 0xbb, 0xbf], "x\n"));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].bom, true);
});

test("scan walks the roots, skips node_modules and honours the exemption list", () => {
  const dir = mkdtempSync(join(tmpdir(), "ctrl-"));
  try {
    mkdirSync(join(dir, "src", "sub"), { recursive: true });
    mkdirSync(join(dir, "src", "node_modules"), { recursive: true });
    writeFileSync(join(dir, "src", "ok.ts"), "const a = 1;\n");
    writeFileSync(join(dir, "src", "sub", "bad.tsx"), bytes("// the ", [0x09], "itle\n"));
    writeFileSync(join(dir, "src", "tab.rs"), bytes("let a = 1;", [0x09], "\n"));
    writeFileSync(join(dir, "src", "ci.yml"), bytes("a: 1\rb: 2\n"));
    writeFileSync(join(dir, "src", "node_modules", "skipped.ts"), bytes([0x00]));
    assert.deepEqual(scan(["src"], dir, {}), [
      "src/ci.yml:1:5: carriage return without line feed",
      "src/sub/bad.tsx:1:8: control byte 0x09",
      "src/tab.rs:1:11: control byte 0x09",
    ]);
    const exempt = { "src/tab.rs": "a reason", "src/ci.yml": "a reason" };
    assert.deepEqual(scan(["src"], dir, exempt), ["src/sub/bad.tsx:1:8: control byte 0x09"]);
    assert.equal(main(["src"], dir, {}), 1);
    assert.equal(main(["missing"], dir, {}), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("every exemption of the real tree exists, has a reason and is still needed", () => {
  for (const [file, reason] of Object.entries(EXEMPT)) {
    assert.ok(reason.length > 20, file);
    assert.ok(findControlBytes(readFileSync(join(REPO, file))).length > 0, `${file} no longer needs its exemption`);
  }
});
test("the real tree is clean", () => {
  assert.equal(main(), 0);
});
