// node --test ci/check-audit-vectors.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_VECTORS, canonicalize, checkVectors, frame } from "./check-audit-vectors.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "check-audit-vectors.mjs");
const load = () => JSON.parse(readFileSync(DEFAULT_VECTORS, "utf8"));

function run(args = []) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
}

/** Writes `doc` to a temp file and runs the checker on it. */
function runOn(doc) {
  const dir = mkdtempSync(join(tmpdir(), "audit-vectors-"));
  try {
    const path = join(dir, "format_v1.json");
    writeFileSync(path, JSON.stringify(doc));
    return run([path]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Replaces the hex digit at `pos` of `s` with a different hex digit. */
function flipHexAt(s, pos) {
  assert.match(s[pos], /[0-9a-f]/);
  const flipped = s[pos] === "0" ? "1" : "0";
  return s.slice(0, pos) + flipped + s.slice(pos + 1);
}

test("the committed vectors pass", () => {
  const res = run();
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(
    res.stderr,
    /^check-audit-vectors: ok \(5 rows, 4 request sets, 3 prune rows, 5 jcs, 3 dek wraps, 7 query tags, recovery layout\)$/m,
  );
  assert.deepEqual(checkVectors(load()), []);
});

test("a flipped hex digit in canonical fails", () => {
  const doc = load();
  doc.rows[0].canonical = flipHexAt(doc.rows[0].canonical, 40);
  const res = runOn(doc);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /rows\[0\] genesis_null_epoch: canonical bytes differ/);
});

test("a flipped hex digit in aad fails", () => {
  const doc = load();
  doc.rows[1].aad = flipHexAt(doc.rows[1].aad, doc.rows[1].aad.length - 1);
  const res = runOn(doc);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /rows\[1\] request_received_all_columns: aad differs/);
});

test("a flipped hex digit in plaintext_jcs fails", () => {
  const doc = load();
  const p = doc.rows[0].plaintext_jcs;
  const pos = p.indexOf('"chain_id":"') + '"chain_id":"'.length;
  doc.rows[0].plaintext_jcs = flipHexAt(p, pos);
  const res = runOn(doc);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /rows\[0\] genesis_null_epoch: SHA-256\(plaintext_jcs\) != payload_sha256/);
});

test("tampering with a column, the ciphertext or a hash is caught", () => {
  const cases = [
    [(d) => (d.rows[2].fields.flags = 20), /rows\[2\] decision_and_flags: canonical bytes differ/],
    [(d) => (d.rows[1].fields.agent_name = null), /rows\[1\] .*canonical bytes differ/],
    [(d) => (d.rows[1].fields.epoch = null), /rows\[1\] .*AES-256-GCM/],
    [(d) => (d.rows[3].fields.payload_ct = flipHexAt(d.rows[3].fields.payload_ct, 0)), /rows\[3\] .*AES-256-GCM/],
    [(d) => (d.rows[3].compressed = flipHexAt(d.rows[3].compressed, 10)), /rows\[3\] .*decrypted payload_ct != compressed/],
    [(d) => (d.rows[3].record_hash = flipHexAt(d.rows[3].record_hash, 5)), /rows\[3\] .*record_hash differs/],
    [(d) => (d.rows[3].fields.payload_sha256 = "AB" + d.rows[3].fields.payload_sha256.slice(2)), /not lowercase hex/],
    [(d) => delete d.rows[0].fields.op_class, /exactly the 29 F\.2 columns/],
    [(d) => (d.request_sets[2].hash = flipHexAt(d.request_sets[2].hash, 0)), /request_sets\[2\]: hash differs/],
    [(d) => (d.request_sets[2].records[1].content_type = ""), /request_sets\[2\]: hash differs/],
    [(d) => (d.prune_rows[1].row_hash = flipHexAt(d.prune_rows[1].row_hash, 3)), /prune_rows\[1\]: row_hash differs/],
    [(d) => (d.prune_rows[0].cutoff_epoch = "2026-01-09"), /prune_rows\[0\]: row_hash differs/],
    [(d) => (d.jcs[1].output = d.jcs[1].output.replace('"1":"One",', "")), /jcs\[1\]: output differs/],
    [(d) => (d.jcs = []), /jcs must be a non-empty array/],
    // F.4: the AAD binds key_id and month (NULL ≠ "").
    [(d) => (d.dek_wraps[1].key_id = 3), /dek_wraps\[1\]: .*(unsupported state|authenticate)/],
    [(d) => (d.dek_wraps[1].month = "2026-11"), /dek_wraps\[1\]: .*(unsupported state|authenticate)/],
    [(d) => (d.dek_wraps[0].month = ""), /dek_wraps\[0\]: .*(unsupported state|authenticate)/],
    [(d) => (d.dek_wraps[2].dek = flipHexAt(d.dek_wraps[2].dek, 0)), /dek_wraps\[2\]: unwrapped DEK differs/],
    [(d) => (d.dek_wraps[2].nonce = flipHexAt(d.dek_wraps[2].nonce, 0)), /dek_wraps\[2\]: nonce differs/],
    [(d) => (d.dek_wraps = []), /dek_wraps must be a non-empty array/],
    // F.7: trim and NFC are part of the tag; the prefix names the kind; the key is the KEK's.
    [(d) => (d.query_tags[2].query = d.query_tags[2].query + "."), /query_tags\[2\]: tag differs/],
    [(d) => (d.query_tags[0].kind = "cql"), /query_tags\[0\]: tag differs/],
    [(d) => (d.query_tags[0].kek = d.query_tags[6].kek), /query_tags\[0\]: k_q differs/],
    [(d) => (d.query_tags[4].tag = flipHexAt(d.query_tags[4].tag, 10)), /query_tags\[4\]: tag differs/],
    // F.5 layout.
    [(d) => (d.recovery.blob = "02" + d.recovery.blob.slice(2)), /recovery: layout byte must be 1/],
    [(d) => (d.recovery.blob = d.recovery.blob.slice(0, 36) + "02" + d.recovery.blob.slice(38)), /recovery: argon2 parameters/],
    [(d) => (d.recovery.blob = d.recovery.blob.slice(2)), /recovery: blob must be 89 bytes/],
    [(d) => delete d.recovery, /recovery must be an object/],
  ];
  for (const [mutate, want] of cases) {
    const doc = load();
    mutate(doc);
    const mismatches = checkVectors(doc);
    assert.ok(mismatches.some((m) => want.test(m)), `${mutate}: ${JSON.stringify(mismatches)}`);
    assert.equal(runOn(doc).status, 1, String(mutate));
  }
});

test("frame layout", () => {
  assert.equal(frame("text", null).toString("hex"), "0000000000");
  assert.equal(frame("text", "").toString("hex"), "0100000000");
  assert.equal(frame("int", 1).toString("hex"), "01000000080000000000000001");
  assert.equal(frame("blob", "ff00").toString("hex"), "0100000002ff00");
  assert.throws(() => frame("int", 2 ** 53), /below 2\^53/);
  assert.throws(() => frame("blob", "f"), /lowercase hex/);
});

test("canonicalize follows RFC 8785", () => {
  const input =
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
    '"literals":[null,true,false]}';
  assert.equal(
    canonicalize(JSON.parse(input)),
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}',
  );
  // UTF-16 order: U+10000 (D800 DC00) before U+FFFF; U+1F600 before U+FB33.
  const bmp = String.fromCodePoint(0xffff);
  const astral = String.fromCodePoint(0x10000);
  assert.equal(canonicalize({ [bmp]: 1, [astral]: 2 }), `{"${astral}":2,"${bmp}":1}`);
  const dagesh = String.fromCodePoint(0xfb33);
  const emoji = String.fromCodePoint(0x1f600);
  assert.equal(canonicalize({ [dagesh]: 1, [emoji]: 2 }), `{"${emoji}":2,"${dagesh}":1}`);
  assert.equal(canonicalize([-0, 1e21, 1e-7]), "[0,1e+21,1e-7]");
});
