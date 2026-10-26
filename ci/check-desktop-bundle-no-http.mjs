#!/usr/bin/env node
// The desktop UI bundle carries no HTTP transport (M12 PD-218): the server build selects it with
// a build-time constant, so the desktop `dist/` must not contain `/api/cmd/` or `EventSource(`.
//
// Usage: node ci/check-desktop-bundle-no-http.mjs <distDir>
// Exit 0 = ok. Exit 1 = violations (one `file: needle` per line on stdout) or unreadable dir.
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

export const NEEDLES = ["/api/cmd/", "EventSource("];

/** Every file under `dir` (absolute paths). */
function files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...files(p));
    else out.push(p);
  }
  return out;
}

/** Violations for `dir`: one `<relative file>: <needle>` per hit. */
export function checkDist(dir) {
  const out = [];
  for (const p of files(dir)) {
    const text = readFileSync(p, "latin1");
    for (const needle of NEEDLES) {
      if (text.includes(needle)) out.push(`${relative(dir, p).replace(/\\/g, "/")}: ${needle}`);
    }
  }
  return out;
}

export function main(argv = process.argv.slice(2)) {
  const dir = argv[0];
  if (dir === undefined) {
    console.log("usage: node ci/check-desktop-bundle-no-http.mjs <distDir>");
    return 1;
  }
  let violations;
  try {
    violations = checkDist(dir);
  } catch (err) {
    console.log(`check-desktop-bundle-no-http: ${err.message}`);
    return 1;
  }
  for (const v of violations) console.log(v);
  if (violations.length > 0) return 1;
  console.error("check-desktop-bundle-no-http: ok");
  return 0;
}

function isMain() {
  if (!process.argv[1]) return false;
  const self = realpathSync(fileURLToPath(import.meta.url));
  const invoked = realpathSync(process.argv[1]);
  return process.platform === "win32" ? self.toLowerCase() === invoked.toLowerCase() : self === invoked;
}

if (isMain()) {
  process.exitCode = main();
}
