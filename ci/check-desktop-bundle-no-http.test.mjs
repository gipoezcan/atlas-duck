// node --test ci/check-desktop-bundle-no-http.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { checkDist, main } from "./check-desktop-bundle-no-http.mjs";

function withDist(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), "dist-no-http-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(join(dir, rel, ".."), { recursive: true });
      writeFileSync(join(dir, rel), text);
    }
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a desktop bundle without the HTTP transport passes", () => {
  withDist({ "index.html": "<script src=a.js>", "assets/a.js": "invoke('queue_list')" }, (dir) => {
    assert.deepEqual(checkDist(dir), []);
    assert.equal(main([dir]), 0);
  });
});

test("/api/cmd/ or EventSource( in any file fails", () => {
  withDist(
    {
      "assets/a.js": "fetch('/api/cmd/'+c)",
      "assets/deep/b.js": "new EventSource('/api/events')",
    },
    (dir) => {
      assert.deepEqual(checkDist(dir).sort(), ["assets/a.js: /api/cmd/", "assets/deep/b.js: EventSource("]);
      assert.equal(main([dir]), 1);
    },
  );
});

test("a missing argument or directory fails", () => {
  assert.equal(main([]), 1);
  assert.equal(main([join(tmpdir(), "no-such-dist-dir-m12")]), 1);
});
