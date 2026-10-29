import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { findControlBytes, main, scan } from "./check-control-bytes.mjs";

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

test("a TAB is allowed where the caller says so, other control bytes never", () => {
  assert.deepEqual(findControlBytes(bytes("a", [0x09], "b"), { tabOk: true }), []);
  assert.equal(findControlBytes(bytes("a", [0x07]), { tabOk: true }).length, 1);
});

test("a byte order mark is reported", () => {
  const hits = findControlBytes(bytes([0xef, 0xbb, 0xbf], "x\n"));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].bom, true);
});

test("scan walks the roots, skips node_modules and honours the TAB rule per extension", () => {
  const dir = mkdtempSync(join(tmpdir(), "ctrl-"));
  try {
    mkdirSync(join(dir, "src", "sub"), { recursive: true });
    mkdirSync(join(dir, "src", "node_modules"), { recursive: true });
    writeFileSync(join(dir, "src", "ok.ts"), "const a = 1;\n");
    writeFileSync(join(dir, "src", "sub", "bad.tsx"), bytes("// the ", [0x09], "itle\n"));
    writeFileSync(join(dir, "src", "tab.rs"), bytes("let a = 1;", [0x09], "\n"));
    writeFileSync(join(dir, "src", "node_modules", "skipped.ts"), bytes([0x00]));
    assert.deepEqual(scan(["src"], dir), ["src/sub/bad.tsx:1:8: control byte 0x09"]);
    assert.equal(main(["src"], dir), 1);
    assert.equal(main(["missing"], dir), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the real sources of the UI and the app are clean", () => {
  assert.equal(main(), 0);
});
