#!/usr/bin/env node
// Generator of the Windows taskbar overlay images (M10 Task 18, PD-173): ten 16x16 RGBA PNGs
// app/src-tauri/icons/overlay-{1..9,9plus}.png, a filled disc with the pending count drawn from an
// embedded 5x7 bitmap font. They are committed; the build does not run this. `--check` compares
// the committed files byte for byte (the `ci/gen-overlay-icons.test.mjs` test runs it).
//
// The IDAT is stored (level 0) deflate: byte-identical on every zlib and node version, and the
// app's reader (`attention::overlay`) decodes stored blocks only, so no PNG codec is linked.
//
// Usage: node ci/gen-overlay-icons.mjs [--check] [--dir <icons dir>]
// Exit 0 = written / identical. Exit 1 = a file differs or is missing (--check), one per line.
// No npm dependencies: node:fs, node:path, node:url, node:zlib only.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
export const ICON_DIR = join(HERE, "..", "app", "src-tauri", "icons");
export const NAMES = [..."123456789"].map((d) => `overlay-${d}.png`).concat("overlay-9plus.png");

const SIZE = 16;
const DISC = [0xc6, 0x28, 0x28, 0xff];
const INK = [0xff, 0xff, 0xff, 0xff];
const CLEAR = [0, 0, 0, 0];

// 5x7 digits (rows top to bottom, '#' = ink) and the 5x5 plus.
const DIGITS = {
  1: ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."],
  2: [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
  3: ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
  4: ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."],
  5: ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."],
  6: ["..##.", ".#...", "#....", "####.", "#...#", "#...#", ".###."],
  7: ["#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."],
  8: [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."],
  9: [".###.", "#...#", "#...#", ".####", "....#", "...#.", ".##.."],
};
const PLUS = ["..#..", "..#..", "#####", "..#..", "..#.."];

function glyphsOf(name) {
  const m = /^overlay-(?:([1-9])|(9plus))\.png$/.exec(name);
  if (!m) throw new Error(`unknown overlay image ${name}`);
  return m[1] ? [DIGITS[m[1]]] : [DIGITS[9], PLUS];
}

function pixels(name) {
  const glyphs = glyphsOf(name);
  const width = glyphs.length * 5 + (glyphs.length - 1);
  const left = Math.floor((SIZE - width) / 2);
  const grid = Array.from({ length: SIZE }, () => Array(SIZE).fill(CLEAR));
  const c = (SIZE - 1) / 2;
  for (let y = 0; y < SIZE; y++) {
    for (let x = 0; x < SIZE; x++) {
      if ((x - c) ** 2 + (y - c) ** 2 <= c * c + 0.25) grid[y][x] = DISC;
    }
  }
  glyphs.forEach((rows, i) => {
    const x0 = left + i * 6;
    const y0 = Math.floor((SIZE - rows.length) / 2);
    rows.forEach((row, dy) => {
      [...row].forEach((ch, dx) => {
        if (ch === "#") grid[y0 + dy][x0 + dx] = INK;
      });
    });
  });
  return grid;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "latin1");
  const tail = Buffer.alloc(4);
  tail.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, tail]);
}

/** The PNG bytes of one overlay image (`overlay-<n>.png`, `overlay-9plus.png`). */
export function render(name) {
  const grid = pixels(name);
  const raw = Buffer.alloc(SIZE * (1 + SIZE * 4));
  grid.forEach((row, y) => {
    const at = y * (1 + SIZE * 4);
    raw[at] = 0; // filter: none
    row.forEach((px, x) => Buffer.from(px).copy(raw, at + 1 + x * 4));
  });
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(SIZE, 0);
  ihdr.writeUInt32BE(SIZE, 4);
  ihdr.set([8, 6, 0, 0, 0], 8); // 8 bit, RGBA, deflate, adaptive filtering, no interlace
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 0 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function main(argv) {
  const check = argv.includes("--check");
  const at = argv.indexOf("--dir");
  const dir = at >= 0 && argv[at + 1] ? resolve(argv[at + 1]) : ICON_DIR;
  const problems = [];
  if (!check) mkdirSync(dir, { recursive: true });
  for (const name of NAMES) {
    const want = render(name);
    if (!check) {
      writeFileSync(join(dir, name), want);
      continue;
    }
    let have = null;
    try {
      have = readFileSync(join(dir, name));
    } catch {
      problems.push(`${name}: missing`);
      continue;
    }
    if (!have.equals(want)) problems.push(`${name}: differs from the generator output`);
  }
  for (const p of problems) console.log(p);
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
