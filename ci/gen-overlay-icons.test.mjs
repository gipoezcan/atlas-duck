// node --test ci/gen-overlay-icons.test.mjs  (node:test, no npm dependencies)
// M10 Task 18 (PD-173): the committed taskbar overlay images are exactly what the generator makes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ICON_DIR, NAMES, render } from "./gen-overlay-icons.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "gen-overlay-icons.mjs");
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

test("the ten names are 1..9 and 9plus", () => {
  assert.deepEqual(NAMES, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "9plus"].map((n) => `overlay-${n}.png`));
});

test("overlay_icons_match_generator", () => {
  for (const name of NAMES) {
    const committed = readFileSync(join(ICON_DIR, name));
    assert.ok(committed.equals(render(name)), `${name} differs from the generator output`);
  }
});

test("the output is deterministic and every image is a distinct 16x16 RGBA PNG", () => {
  const seen = new Set();
  for (const name of NAMES) {
    const a = render(name);
    assert.ok(a.equals(render(name)), `${name} is not deterministic`);
    assert.ok(a.subarray(0, 8).equals(SIGNATURE), `${name} has no PNG signature`);
    assert.equal(a.readUInt32BE(16), 16, `${name} width`);
    assert.equal(a.readUInt32BE(20), 16, `${name} height`);
    assert.equal(a[24], 8, `${name} bit depth`);
    assert.equal(a[25], 6, `${name} colour type (RGBA)`);
    seen.add(a.toString("hex"));
  }
  assert.equal(seen.size, NAMES.length, "two overlay images are identical");
});

test("an unknown name is refused", () => {
  assert.throws(() => render("overlay-10.png"), /unknown overlay/);
});

test("the generator uses node built-ins only", () => {
  const src = readFileSync(SCRIPT, "utf8");
  const specs = [...src.matchAll(/^\s*import\s[^;]*?from\s+"([^"]+)"/gm)].map((m) => m[1]);
  assert.ok(specs.length > 0);
  for (const s of specs) assert.match(s, /^node:/, `non-builtin import ${s}`);
  assert.doesNotMatch(src, /require\(|import\(/);
});

function run(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", timeout: 60_000 });
}

test("--check passes on the committed files and fails on a changed or missing one", () => {
  assert.equal(run(["--check"]).status, 0);

  const dir = mkdtempSync(join(tmpdir(), "overlay-"));
  for (const name of NAMES) copyFileSync(join(ICON_DIR, name), join(dir, name));
  assert.equal(run(["--check", "--dir", dir]).status, 0);

  const bytes = readFileSync(join(dir, NAMES[0]));
  bytes[bytes.length - 20] ^= 0xff;
  writeFileSync(join(dir, NAMES[0]), bytes);
  const changed = run(["--check", "--dir", dir]);
  assert.equal(changed.status, 1);
  assert.match(changed.stdout, /overlay-1\.png/);

  const empty = mkdtempSync(join(tmpdir(), "overlay-"));
  assert.equal(run(["--check", "--dir", empty]).status, 1);
});

test("writing into a directory yields files that --check then accepts", () => {
  const dir = mkdtempSync(join(tmpdir(), "overlay-"));
  assert.equal(run(["--dir", dir]).status, 0);
  assert.equal(run(["--check", "--dir", dir]).status, 0);
  for (const name of NAMES) assert.ok(readFileSync(join(dir, name)).equals(render(name)));
});
