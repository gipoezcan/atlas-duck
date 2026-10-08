#!/usr/bin/env node
// Independent cross-check of the audit golden vectors (§8.4, §13 "canonical-encoding golden
// vectors"; plan M2 F.2, F.3, F.8, F.9). Re-implements, from the format description and not
// from the Rust code: the field frame, the 29-field canonical bytes of FIELD_LIST[1],
// record_hash, the AES-GCM AAD, request_set_hash, the prune-log row hash and RFC 8785 JCS
// (keys sorted by UTF-16 code units, numbers printed by ECMAScript), then checks every entry
// of crates/audit/tests/vectors/format_v1.json: AES-256-GCM decryption of payload_ct with the
// row's DEK, nonce and recomputed AAD must yield `compressed`, SHA-256 of plaintext_jcs must
// equal payload_sha256, and plaintext_jcs must be its own JCS form.
//
// Usage: node ci/check-audit-vectors.mjs [vectors.json]
// Exit 0 = ok (summary on stderr). Exit 1 = mismatches (one per line on stdout).
// No npm dependencies: node:crypto, node:fs, node:path, node:url, node:zlib only.

import { createDecipheriv, createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as zlib from "node:zlib";

export const DEFAULT_VECTORS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "crates",
  "audit",
  "tests",
  "vectors",
  "format_v1.json",
);

// F.2: every `events` column except record_hash, in order, with its encoding kind.
export const COLUMNS = [
  ["seq", "int"],
  ["format_version", "int"],
  ["chain_id", "text"],
  ["ts_utc", "text"],
  ["epoch", "text"],
  ["request_id", "text"],
  ["event_type", "text"],
  ["op_id", "text"],
  ["op_class", "text"],
  ["instance_id", "text"],
  ["target", "text"],
  ["agent_name", "text"],
  ["agent_name_source", "text"],
  ["client_kind", "text"],
  ["connection_id", "text"],
  ["peer_pid", "int"],
  ["peer_exe", "blob"],
  ["peer_origin_exe", "blob"],
  ["os_user", "text"],
  ["atlassian_user", "text"],
  ["atlassian_user_key", "text"],
  ["decision", "text"],
  ["flags", "int"],
  ["payload_len", "int"],
  ["payload_sha256", "blob"],
  ["key_id", "int"],
  ["nonce", "blob"],
  ["payload_ct", "blob"],
  ["prev_hash", "blob"],
];
const KIND = Object.fromEntries(COLUMNS);
const NOT_NULL = new Set([
  "seq", "format_version", "chain_id", "ts_utc", "event_type", "flags",
  "payload_len", "payload_sha256", "key_id", "nonce", "payload_ct", "prev_hash",
]);

// §8.4: the AAD fields, in this order.
export const AAD_COLUMNS = [
  "format_version", "chain_id", "seq", "ts_utc", "epoch", "event_type",
  "request_id", "op_id", "target", "key_id", "payload_sha256",
];

const ascii = (s) => Buffer.from(s, "latin1");
const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

/** Strict lowercase hex → bytes (Buffer.from(_, "hex") silently stops at a bad digit). */
export function hexBytes(s, what) {
  if (typeof s !== "string" || !/^(?:[0-9a-f]{2})*$/.test(s)) {
    throw new Error(`${what} is not lowercase hex`);
  }
  return Buffer.from(s, "hex");
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

function u64be(v, what) {
  if (!(Number.isSafeInteger(v) && v >= 0)) throw new Error(`${what} is not a u64 below 2^53`);
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v));
  return b;
}

/** Field frame: NULL = 00 00000000; present = 01 ‖ u32 BE length ‖ bytes; integers are 8 bytes. */
export function frame(kind, value, what = kind) {
  if (value === null) return Buffer.alloc(5);
  let data;
  if (kind === "int") data = u64be(value, what);
  else if (kind === "text") {
    if (typeof value !== "string") throw new Error(`${what} is not a string`);
    data = Buffer.from(value, "utf8");
  } else if (kind === "blob") data = hexBytes(value, what);
  else throw new Error(`unknown kind ${kind}`);
  if (data.length > 0xffffffff) {
    // Unreachable for real data (24 MiB frame cap); Rust's request-set/prune hashes would use
    // the 0x02 long frame of F.8/F.9 (L60), which this checker does not implement.
    throw new Error(`${what} is longer than u32::MAX bytes: 0x02 long frames are not supported`);
  }
  return Buffer.concat([Buffer.from([1]), u32be(data.length), data]);
}

function checkFieldSet(fields) {
  const keys = Object.keys(fields).sort();
  const want = COLUMNS.map(([c]) => c).sort();
  if (keys.join(",") !== want.join(",")) throw new Error("fields must hold exactly the 29 F.2 columns");
  for (const c of NOT_NULL) if (fields[c] === null) throw new Error(`${c} is NULL`);
}

export function canonicalBytes(fields) {
  checkFieldSet(fields);
  return Buffer.concat(COLUMNS.map(([c, kind]) => frame(kind, fields[c], c)));
}

export function recordHash(formatVersion, prevHash, canonical) {
  return sha256(ascii(`atlas-duck/audit/v${formatVersion}`), prevHash, canonical);
}

export function aad(fields) {
  checkFieldSet(fields);
  return Buffer.concat([ascii("atlas-duck/aad/v1"), ...AAD_COLUMNS.map((c) => frame(KIND[c], fields[c], c))]);
}

/** F.8; `records` use the vectors-file shape {index, method, url, content_type, body(hex)}. */
export function requestSetHash(records) {
  const parts = [ascii("atlas-duck/request-set/v1"), u32be(records.length)];
  for (const r of records) {
    parts.push(
      frame("int", r.index, "index"),
      frame("text", r.method, "method"),
      frame("text", r.url, "url"),
      frame("text", r.content_type, "content_type"),
      frame("blob", r.body, "body"),
    );
  }
  return sha256(...parts);
}

/** F.9 */
export function pruneRowHash(r) {
  return sha256(
    ascii("atlas-duck/prune-log/v1"),
    hexBytes(r.prev_row_hash, "prev_row_hash"),
    frame("int", r.prune_seq, "prune_seq"),
    frame("int", r.range_start, "range_start"),
    frame("text", r.cutoff_epoch, "cutoff_epoch"),
    frame("blob", r.last_pruned_record_hash, "last_pruned_record_hash"),
    frame("int", r.first_retained_seq, "first_retained_seq"),
  );
}

/** RFC 8785: ECMAScript serialization of primitives, object keys sorted by UTF-16 code units. */
export function canonicalize(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  // Default sort compares UTF-16 code units, which is what RFC 8785 §3.2.3 requires.
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
}

function decryptGcm(key, nonce, aadBytes, ctAndTag) {
  if (ctAndTag.length < 16) throw new Error("payload_ct shorter than the GCM tag");
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aadBytes);
  d.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
  return Buffer.concat([d.update(ctAndTag.subarray(0, ctAndTag.length - 16)), d.final()]);
}

const ZERO_HASH = "0".repeat(64);

/** `prev`: {chain_id, seq, record_hash} of the previous row, or null. */
function checkRow(row, i, prev, out, notes) {
  const name = `rows[${i}] ${row.name}`;
  const fail = (m) => out.push(`${name}: ${m}`);
  const f = row.fields;
  let canonical;
  let aadBytes;
  try {
    canonical = canonicalBytes(f);
    aadBytes = aad(f);
  } catch (e) {
    fail(e.message);
    return null;
  }
  if (canonical.toString("hex") !== row.canonical) fail("canonical bytes differ");
  if (aadBytes.toString("hex") !== row.aad) fail("aad differs");
  const rh = recordHash(f.format_version, hexBytes(f.prev_hash, "prev_hash"), canonical).toString("hex");
  if (rh !== row.record_hash) fail("record_hash differs");
  // GENESIS (seq 1) has a zero prev_hash; a row following the previous one in the same chain
  // links to it; a row of another chain (or after a gap) is checked on its own.
  if (f.seq === 1 && f.prev_hash !== ZERO_HASH) fail("seq 1 must have a zero prev_hash");
  if (prev && prev.chain_id === f.chain_id && prev.seq + 1 === f.seq && f.prev_hash !== prev.record_hash) {
    fail("prev_hash does not link to the previous row's record_hash");
  }

  const plain = Buffer.from(row.plaintext_jcs, "utf8");
  if (sha256(plain).toString("hex") !== f.payload_sha256) fail("SHA-256(plaintext_jcs) != payload_sha256");
  if (plain.length !== f.payload_len) fail("payload_len differs from the plaintext length");
  try {
    if (canonicalize(JSON.parse(row.plaintext_jcs)) !== row.plaintext_jcs) fail("plaintext_jcs is not in JCS form");
  } catch (e) {
    fail(`plaintext_jcs: ${e.message}`);
  }
  try {
    const key = hexBytes(row.dek, "dek");
    const nonce = hexBytes(f.nonce, "nonce");
    if (key.length !== 32 || nonce.length !== 12) throw new Error("dek must be 32 bytes and nonce 12");
    const compressed = decryptGcm(key, nonce, aadBytes, hexBytes(f.payload_ct, "payload_ct"));
    if (compressed.toString("hex") !== row.compressed) fail("decrypted payload_ct != compressed");
    // zstd is in node:zlib from Node 22.15/23.8 on; older Node checks the ciphertext only.
    if (typeof zlib.zstdDecompressSync === "function") {
      if (!zlib.zstdDecompressSync(compressed).equals(plain)) fail("zstd(compressed) != plaintext_jcs");
    } else {
      notes.add(`note: node ${process.version} has no zstd (needs >= 22.15): compressed checked by AES-GCM only`);
    }
  } catch (e) {
    fail(`AES-256-GCM: ${e.message}`);
  }
  return rh;
}

/** Returns the list of mismatches (empty = ok). */
export function checkVectors(doc, notes = new Set()) {
  const out = [];
  if (doc.format_version !== 1) out.push("format_version must be 1");
  for (const k of ["rows", "request_sets", "prune_rows", "jcs"]) {
    if (!Array.isArray(doc[k]) || doc[k].length === 0) out.push(`${k} must be a non-empty array`);
  }
  if (out.length > 0) return out;

  let prev = null;
  doc.rows.forEach((row, i) => {
    const rh = checkRow(row, i, prev, out, notes);
    prev = rh ? { chain_id: row.fields.chain_id, seq: row.fields.seq, record_hash: rh } : null;
  });

  doc.request_sets.forEach((set, i) => {
    try {
      if (requestSetHash(set.records).toString("hex") !== set.hash) out.push(`request_sets[${i}]: hash differs`);
    } catch (e) {
      out.push(`request_sets[${i}]: ${e.message}`);
    }
  });

  let prevRow = ZERO_HASH;
  doc.prune_rows.forEach((r, i) => {
    try {
      if (r.prev_row_hash !== prevRow) out.push(`prune_rows[${i}]: prev_row_hash does not link to the previous row`);
      const h = pruneRowHash(r).toString("hex");
      if (h !== r.row_hash) out.push(`prune_rows[${i}]: row_hash differs`);
      prevRow = r.row_hash;
    } catch (e) {
      out.push(`prune_rows[${i}]: ${e.message}`);
    }
  });

  doc.jcs.forEach((j, i) => {
    try {
      if (canonicalize(JSON.parse(j.input)) !== j.output) out.push(`jcs[${i}]: output differs`);
    } catch (e) {
      out.push(`jcs[${i}]: ${e.message}`);
    }
  });
  return out;
}

export function main(argv = process.argv.slice(2)) {
  const path = argv[0] ?? DEFAULT_VECTORS;
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    console.log(`check-audit-vectors: cannot read ${path}: ${err.message}`);
    return 1;
  }
  const notes = new Set();
  const mismatches = checkVectors(doc, notes);
  for (const n of notes) console.error(n);
  for (const m of mismatches) console.log(m);
  if (mismatches.length > 0) return 1;
  console.error(
    `check-audit-vectors: ok (${doc.rows.length} rows, ${doc.request_sets.length} request sets, ` +
      `${doc.prune_rows.length} prune rows, ${doc.jcs.length} jcs)`,
  );
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
