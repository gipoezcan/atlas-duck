#!/usr/bin/env node
// Independent cross-check of the audit golden vectors (§8.4, §8.6, §13 "canonical-encoding
// golden vectors", L38; plan M2 F.2–F.5, F.7–F.9). Re-implements, from the format description
// and not from the Rust code: the field frame, the 29-field canonical bytes of FIELD_LIST[1],
// record_hash, the AES-GCM AAD, request_set_hash, the prune-log row hash, RFC 8785 JCS (keys
// sorted by UTF-16 code units, numbers printed by ECMAScript), the DEK-wrap AAD and the keyed
// query tag, then checks every entry of crates/audit/tests/vectors/format_v1.json:
// AES-256-GCM decryption of payload_ct with the row's DEK, nonce and recomputed AAD must
// yield `compressed`, SHA-256 of plaintext_jcs must equal payload_sha256, plaintext_jcs must
// be its own JCS form, each wrapped DEK must decrypt under its KEK, key_id and month to its
// DEK, and each query tag must equal HMAC-SHA256(HKDF-SHA256(KEK), NFC(query).trim()). The
// recovery blob (Argon2id, which node:crypto 22 lacks) is checked for its layout only; Rust
// checks it in full (crates/audit/tests/golden.rs).
//
// Without an argument it also checks the pinned SHA-256 of the frozen files (FROZEN_SHA256:
// the vectors and the schema-v1 fixture): a regenerated file fails until the pin is edited on
// purpose, here and in crates/audit/tests/golden.rs.
//
// Usage: node ci/check-audit-vectors.mjs [vectors.json]
// Exit 0 = ok (summary on stderr). Exit 1 = mismatches (one per line on stdout).
// No npm dependencies: node:crypto, node:fs, node:path, node:url, node:zlib only.

import { createDecipheriv, createHash, createHmac, hkdfSync } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as zlib from "node:zlib";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export const DEFAULT_VECTORS = join(
  REPO_ROOT,
  "crates",
  "audit",
  "tests",
  "vectors",
  "format_v1.json",
);

// SHA-256 of the files frozen at the end of M2, as committed (LF, .gitattributes). Same table
// as FROZEN in crates/audit/tests/golden.rs.
export const FROZEN_SHA256 = {
  "crates/audit/tests/vectors/format_v1.json":
    "13fdb8203185676d94fac5d43b3ccf097938b63afe57894c0f9a12b05498502a",
  "crates/audit/tests/fixtures/schema/v1.db":
    "ac6b4fc3bc163ac5502387db4014c3702bd2ca722cb2d08de276c8ee4e58df65",
  "crates/audit/tests/fixtures/schema/v1.keyring.json":
    "be7e54c8b7073edd587f98099dd342826f86359b67d79c59d1052caf605dbd78",
};

/** One line per frozen file under `root` that is missing or whose bytes changed. */
export function checkFrozen(root = REPO_ROOT) {
  const out = [];
  for (const [rel, want] of Object.entries(FROZEN_SHA256)) {
    let got;
    try {
      got = createHash("sha256").update(readFileSync(join(root, ...rel.split("/")))).digest("hex");
    } catch (err) {
      out.push(`${rel}: cannot read (${err.code ?? err.message})`);
      continue;
    }
    if (got !== want) out.push(`${rel}: sha256 ${got} is not the pinned ${want} (the file is frozen)`);
  }
  return out;
}

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
  if (ctAndTag.length < 16) throw new Error("ciphertext shorter than the GCM tag");
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(aadBytes);
  d.setAuthTag(ctAndTag.subarray(ctAndTag.length - 16));
  return Buffer.concat([d.update(ctAndTag.subarray(0, ctAndTag.length - 16)), d.final()]);
}

const ZERO_HASH = "0".repeat(64);

/** F.4: AAD of a wrapped DEK = "atlas-duck/dek/v1" ‖ frame(int key_id) ‖ frame(month or NULL). */
export function dekWrapAad(keyId, month) {
  return Buffer.concat([ascii("atlas-duck/dek/v1"), frame("int", keyId, "key_id"), frame("text", month, "month")]);
}

/** F.4: wrapped = nonce(12) ‖ ct(32) ‖ tag(16); returns the DEK. */
export function unwrapDek(kek, keyId, month, wrapped) {
  if (wrapped.length !== 60) throw new Error("wrapped DEK must be 60 bytes");
  return decryptGcm(kek, wrapped.subarray(0, 12), dekWrapAad(keyId, month), wrapped.subarray(12));
}

/**
 * F.7: K_q = HKDF-SHA256(salt none, ikm KEK, info "atlas-duck/query-tag/v1", 32). An empty
 * salt equals "no salt" (RFC 5869: HMAC zero-pads the key to the block size either way).
 */
export function queryKey(kek) {
  return Buffer.from(hkdfSync("sha256", kek, Buffer.alloc(0), "atlas-duck/query-tag/v1", 32));
}

/**
 * F.7: `<kind>:` + hex(HMAC-SHA256(K_q, NFC(query).trim())). JS `trim()` also strips U+FEFF,
 * which Rust's `str::trim` keeps, and keeps U+0085 (NEL), which Rust strips; the vectors use
 * only ASCII spaces, tabs and newlines around queries, where both agree.
 */
export function queryTag(kek, kind, query) {
  if (kind !== "jql" && kind !== "cql") throw new Error(`unknown query kind ${kind}`);
  const mac = createHmac("sha256", queryKey(kek));
  mac.update(Buffer.from(query.normalize("NFC").trim(), "utf8"));
  return `${kind}:${mac.digest("hex")}`;
}

/** F.5 layout only (no Argon2 in node:crypto 22): 0x01 ‖ salt ‖ m ‖ t ‖ p ‖ nonce ‖ ct(48). */
function checkRecovery(r, out) {
  const fail = (m) => out.push(`recovery: ${m}`);
  try {
    const blob = hexBytes(r.blob, "blob");
    if (blob.length !== 89) return fail("blob must be 89 bytes");
    if (blob[0] !== 1) fail("layout byte must be 1");
    if (blob.subarray(1, 17).toString("hex") !== r.salt) fail("salt differs from blob[1..17]");
    const [m, t, p] = [17, 21, 25].map((o) => blob.readUInt32BE(o));
    if (m !== 65536 || t !== 3 || p !== 4) fail(`argon2 parameters must be m=65536 t=3 p=4, got m=${m} t=${t} p=${p}`);
    if (blob.subarray(29, 41).toString("hex") !== r.nonce) fail("nonce differs from blob[29..41]");
    if (typeof r.passphrase !== "string" || [...r.passphrase.normalize("NFC")].length < 12) {
      fail("passphrase must be at least 12 characters");
    }
    if (hexBytes(r.kek, "kek").length !== 32) fail("kek must be 32 bytes");
  } catch (e) {
    fail(e.message);
  }
}

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

/** Checks each row and the links between consecutive rows of one chain; appends to `out`. */
function checkRows(rows, out, notes) {
  let prev = null;
  rows.forEach((row, i) => {
    const rh = checkRow(row, i, prev, out, notes);
    prev = rh ? { chain_id: row.fields.chain_id, seq: row.fields.seq, record_hash: rh } : null;
  });
}

// M12 PD-216: the server-mode kinds, one row each, in a file of their own (format_v1.json is
// frozen; the kinds change no format, only the event_type text of an ordinary record).
export const DEFAULT_SERVER_VECTORS = join(REPO_ROOT, "crates", "audit", "tests", "vectors", "server_kinds_v1.json");
export const SERVER_KINDS = ["LOGIN", "API_KEY_CREATED", "API_KEY_REVOKED", "AUDITOR_READ"];

/** The server-kind vectors: rows only, exactly one per server kind in SERVER_KINDS order. */
export function checkServerKindVectors(doc, notes = new Set()) {
  const out = [];
  if (doc.format_version !== 1) out.push("server kinds: format_version must be 1");
  if (!Array.isArray(doc.rows)) return [...out, "server kinds: rows must be an array"];
  const kinds = doc.rows.map((r) => r?.fields?.event_type);
  if (kinds.join(",") !== SERVER_KINDS.join(",")) {
    out.push(`server kinds: rows must be one each of ${SERVER_KINDS.join(", ")} in order, found ${kinds.join(", ")}`);
  }
  const rowsOut = [];
  checkRows(doc.rows, rowsOut, notes);
  return [...out, ...rowsOut.map((m) => `server kinds ${m}`)];
}

// M12 PD-217: the server anchor chain (rows v2, user-head leaves, the HEADS body).
export const DEFAULT_SERVER_ANCHOR_VECTORS = join(REPO_ROOT, "crates", "audit", "tests", "vectors", "server_anchor_v2.json");

/** `SHA-256("atlas-duck/anchor-leaf/v1\0" || user_id || "\0" || chain_id || "\0" || seq_be || record_hash)`. */
export function anchorLeaf(userId, chainId, seq, recordHashHex) {
  return sha256(
    Buffer.from("atlas-duck/anchor-leaf/v1\0", "utf8"),
    Buffer.from(userId, "utf8"),
    Buffer.from([0]),
    Buffer.from(chainId, "utf8"),
    Buffer.from([0]),
    u64be(seq, "seq"),
    hexBytes(recordHashHex, "record_hash"),
  );
}

/** `SHA-256("atlas-duck/anchor/v2\0" || seq_be || ts_utc || kind || SHA-256(body_jcs) || prev_hash)`. */
export function anchorRowHash(seq, tsUtc, kind, bodyJcs, prevHashHex) {
  return sha256(
    Buffer.from("atlas-duck/anchor/v2\0", "utf8"),
    u64be(seq, "seq"),
    Buffer.from(tsUtc, "utf8"),
    Buffer.from(kind, "utf8"),
    sha256(Buffer.from(bodyJcs, "utf8")),
    hexBytes(prevHashHex, "prev_hash"),
  );
}

// M14 PD-253: the anchor-chain excerpt lines.
export const DEFAULT_SERVER_EXCERPT_VECTORS = join(
  REPO_ROOT,
  "crates",
  "audit",
  "tests",
  "vectors",
  "server_anchor_excerpt_v1.json",
);

/** The v2 row hash from the body's SHA-256 (an opaque excerpt line). */
export function anchorRowHashFromBodyHash(seq, tsUtc, kind, bodyShaHex, prevHashHex) {
  return sha256(
    Buffer.from("atlas-duck/anchor/v2\0", "utf8"),
    u64be(seq, "seq"),
    Buffer.from(tsUtc, "utf8"),
    Buffer.from(kind, "utf8"),
    hexBytes(bodyShaHex, "body_sha256"),
    hexBytes(prevHashHex, "prev_hash"),
  );
}

const EXCERPT_KEYS = new Set(["v", "seq", "ts_utc", "kind", "body_sha256", "prev_hash", "hash", "body", "leaf_entry"]);

export function checkServerExcerptVectors(doc) {
  const out = [];
  if (doc.format !== "atlas-duck-anchor-excerpt/1") out.push("excerpt: format must be atlas-duck-anchor-excerpt/1");
  if (!Array.isArray(doc.lines) || doc.lines.length === 0) out.push("excerpt: lines must be a non-empty array");
  if (out.length > 0) return out;
  let prev = null;
  let full = 0;
  doc.lines.forEach((text, i) => {
    try {
      const l = JSON.parse(text);
      if (canonicalize(l) !== text) out.push(`excerpt lines[${i}]: not JCS`);
      for (const k of Object.keys(l)) if (!EXCERPT_KEYS.has(k)) out.push(`excerpt lines[${i}]: unknown key ${k}`);
      if (l.v !== 2) out.push(`excerpt lines[${i}]: v must be 2`);
      if (prev !== null && l.prev_hash !== prev) out.push(`excerpt lines[${i}]: prev_hash does not link`);
      const h = anchorRowHashFromBodyHash(l.seq, l.ts_utc, l.kind, l.body_sha256, l.prev_hash).toString("hex");
      if (h !== l.hash) out.push(`excerpt lines[${i}]: hash differs`);
      if (l.body !== undefined) {
        full += 1;
        if (sha256(Buffer.from(l.body, "utf8")).toString("hex") !== l.body_sha256) {
          out.push(`excerpt lines[${i}]: body_sha256 differs`);
        }
      }
      if (l.leaf_entry !== undefined) {
        const e = l.leaf_entry;
        const body = JSON.parse(l.body);
        const leaves = body.leaves ?? [body.leaf];
        const leaf = anchorLeaf(e.user_id, e.chain_id, e.head_seq, e.record_hash).toString("hex");
        if (leaves[e.leaf_index] !== leaf) out.push(`excerpt lines[${i}]: leaf not at leaf_index`);
      }
      prev = l.hash;
    } catch (e) {
      out.push(`excerpt lines[${i}]: ${e.message}`);
    }
  });
  if (full === 0) out.push("excerpt: no full line");
  try {
    const m = JSON.parse(doc.manifest);
    if (canonicalize(m) !== doc.manifest) out.push("excerpt manifest: not JCS");
    const last = JSON.parse(doc.lines[doc.lines.length - 1]);
    if (m.format !== doc.format) out.push("excerpt manifest: format differs");
    if (m.last_seq !== last.seq || m.last_hash !== last.hash) out.push("excerpt manifest: last row differs");
    if (m.first_seq !== JSON.parse(doc.lines[0]).seq) out.push("excerpt manifest: first_seq differs");
  } catch (e) {
    out.push(`excerpt manifest: ${e.message}`);
  }
  return out;
}

export function checkServerAnchorVectors(doc) {
  const out = [];
  if (doc.format !== "server-anchor/v2") out.push("server anchor: format must be server-anchor/v2");
  for (const k of ["leaves", "rows"]) {
    if (!Array.isArray(doc[k]) || doc[k].length === 0) out.push(`server anchor: ${k} must be a non-empty array`);
  }
  if (out.length > 0) return out;
  const leaves = [];
  doc.leaves.forEach((l, i) => {
    try {
      const leaf = anchorLeaf(l.user_id, l.chain_id, l.seq, l.record_hash).toString("hex");
      if (leaf !== l.leaf) out.push(`server anchor leaves[${i}]: leaf differs`);
      leaves.push(leaf);
    } catch (e) {
      out.push(`server anchor leaves[${i}]: ${e.message}`);
    }
  });
  const body = canonicalize({ leaves: [...leaves].sort() });
  if (body !== doc.heads_body) out.push("server anchor: heads_body is not the sorted JCS of the leaves");
  let prev = "00".repeat(32);
  doc.rows.forEach((r, i) => {
    try {
      if (r.seq !== i + 1) out.push(`server anchor rows[${i}]: seq must be ${i + 1}`);
      if (r.prev_hash !== prev) out.push(`server anchor rows[${i}]: prev_hash does not link`);
      if (canonicalize(JSON.parse(r.body_jcs)) !== r.body_jcs) out.push(`server anchor rows[${i}]: body is not JCS`);
      const h = anchorRowHash(r.seq, r.ts_utc, r.kind, r.body_jcs, r.prev_hash).toString("hex");
      if (h !== r.hash) out.push(`server anchor rows[${i}]: hash differs`);
      prev = r.hash;
    } catch (e) {
      out.push(`server anchor rows[${i}]: ${e.message}`);
    }
  });
  return out;
}

/** Returns the list of mismatches (empty = ok). */
export function checkVectors(doc, notes = new Set()) {
  const out = [];
  if (doc.format_version !== 1) out.push("format_version must be 1");
  for (const k of ["rows", "request_sets", "prune_rows", "jcs", "dek_wraps", "query_tags"]) {
    if (!Array.isArray(doc[k]) || doc[k].length === 0) out.push(`${k} must be a non-empty array`);
  }
  if (doc.recovery === null || typeof doc.recovery !== "object" || Array.isArray(doc.recovery)) {
    out.push("recovery must be an object");
  }
  if (out.length > 0) return out;

  checkRows(doc.rows, out, notes);

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

  doc.dek_wraps.forEach((w, i) => {
    try {
      const kek = hexBytes(w.kek, "kek");
      if (kek.length !== 32) throw new Error("kek must be 32 bytes");
      const wrapped = hexBytes(w.wrapped, "wrapped");
      if (wrapped.subarray(0, 12).toString("hex") !== w.nonce) out.push(`dek_wraps[${i}]: nonce differs from wrapped[0..12]`);
      if (unwrapDek(kek, w.key_id, w.month, wrapped).toString("hex") !== w.dek) {
        out.push(`dek_wraps[${i}]: unwrapped DEK differs`);
      }
    } catch (e) {
      out.push(`dek_wraps[${i}]: ${e.message}`);
    }
  });

  doc.query_tags.forEach((q, i) => {
    try {
      const kek = hexBytes(q.kek, "kek");
      if (kek.length !== 32) throw new Error("kek must be 32 bytes");
      if (queryKey(kek).toString("hex") !== q.k_q) out.push(`query_tags[${i}]: k_q differs`);
      if (queryTag(kek, q.kind, q.query) !== q.tag) out.push(`query_tags[${i}]: tag differs`);
    } catch (e) {
      out.push(`query_tags[${i}]: ${e.message}`);
    }
  });

  checkRecovery(doc.recovery, out);
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
  let serverRows = 0;
  if (argv[0] === undefined) {
    mismatches.push(...checkFrozen());
    try {
      const server = JSON.parse(readFileSync(DEFAULT_SERVER_VECTORS, "utf8"));
      mismatches.push(...checkServerKindVectors(server, notes));
      serverRows = server.rows?.length ?? 0;
    } catch (err) {
      mismatches.push(`server kinds: cannot read ${DEFAULT_SERVER_VECTORS}: ${err.message}`);
    }
    try {
      const anchor = JSON.parse(readFileSync(DEFAULT_SERVER_ANCHOR_VECTORS, "utf8"));
      mismatches.push(...checkServerAnchorVectors(anchor));
    } catch (err) {
      mismatches.push(`server anchor: cannot read ${DEFAULT_SERVER_ANCHOR_VECTORS}: ${err.message}`);
    }
    try {
      const excerpt = JSON.parse(readFileSync(DEFAULT_SERVER_EXCERPT_VECTORS, "utf8"));
      mismatches.push(...checkServerExcerptVectors(excerpt));
    } catch (err) {
      mismatches.push(`excerpt: cannot read ${DEFAULT_SERVER_EXCERPT_VECTORS}: ${err.message}`);
    }
  }
  for (const n of notes) console.error(n);
  for (const m of mismatches) console.log(m);
  if (mismatches.length > 0) return 1;
  console.error(
    `check-audit-vectors: ok (${doc.rows.length} rows, ${doc.request_sets.length} request sets, ` +
      `${doc.prune_rows.length} prune rows, ${doc.jcs.length} jcs, ${doc.dek_wraps.length} dek wraps, ` +
      `${doc.query_tags.length} query tags, recovery layout` +
      (argv[0] === undefined ? `; ${serverRows} server-kind rows; server anchor vectors)` : ")"),
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
