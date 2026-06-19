import crypto from "node:crypto";
import { AuditRecord } from "../../domain/models";
import { config } from "../../config/env";

// Hash-chained audit signing. Each daily NDJSON file is treated as an
// append-only log. Every record carries:
//   - seq: 1-based sequence within the file
//   - hmac: HMAC-SHA256(key, prevHmac_hex || "\n" || canonicalJson)
// where prevHmac_hex is "" for the first record. canonicalJson is the
// JSON.stringify of the record with the `hmac` field omitted.
//
// The HMAC key is derived from CREDENTIAL_ENCRYPTION_KEY via HKDF with
// a fixed info label so the operator does not have to manage a second
// secret. If the encryption key is later rotated, prior records remain
// readable but no longer verify under the new key — the verifier reports
// that explicitly rather than silently passing or failing.

const HKDF_INFO = Buffer.from("groupselfservice/audit-hmac/v1", "utf-8");

function deriveAuditKey(): Buffer {
  // Use the encryption key as the IKM. If it's a 32-byte base64 value the
  // raw bytes are used directly as the secret; otherwise SHA-256 of the
  // string. HKDF-Extract is implicit (we use a fixed empty salt) and
  // HKDF-Expand gives us 32 deterministic bytes for HMAC-SHA256.
  let ikm = Buffer.from(config.CREDENTIAL_ENCRYPTION_KEY, "base64");
  if (ikm.length !== 32) {
    ikm = crypto.createHash("sha256").update(config.CREDENTIAL_ENCRYPTION_KEY, "utf-8").digest();
  }
  return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), HKDF_INFO, 32));
}

let cachedKey: Buffer | undefined;
function getKey(): Buffer {
  if (!cachedKey) cachedKey = deriveAuditKey();
  return cachedKey;
}

// Stable JSON: omit the hmac field, preserve insertion order of the rest.
// Order matters because JSON.stringify on an object literal preserves the
// own-property order set by the caller, and AuditRepository always builds
// records in the same order. We don't sort keys — that would silently
// break the chain for any historical record written with a different
// stringify order.
export function canonicalJsonWithoutHmac(record: AuditRecord): string {
  const { hmac: _ignore, ...rest } = record;
  void _ignore;
  return JSON.stringify(rest);
}

export function computeRecordHmac(prevHmacHex: string, record: AuditRecord): string {
  const h = crypto.createHmac("sha256", getKey());
  h.update(prevHmacHex);
  h.update("\n");
  h.update(canonicalJsonWithoutHmac(record));
  return h.digest("hex");
}

export interface ChainTail {
  // Highest seq seen in the file so the next append uses seq+1.
  lastSeq: number;
  // Hex HMAC of the last record. "" if file is empty.
  lastHmac: string;
}

// Replay every record in a daily file and return the tail state, or an
// error describing the first break in the chain.
export interface VerificationResult {
  fileName: string;
  recordCount: number;
  ok: boolean;
  // Reason and 0-based line index of the first failure, when ok=false.
  failure?: { reason: string; lineIndex: number };
  tail?: ChainTail;
}

export function verifyChain(fileContents: string, fileName: string): VerificationResult {
  const lines = fileContents.split(/\r?\n/);
  let recordCount = 0;
  let lastHmac = "";
  let lastSeq = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line) continue;
    let record: AuditRecord;
    try {
      record = JSON.parse(line) as AuditRecord;
    } catch {
      return { fileName, recordCount, ok: false, failure: { reason: "Line is not valid JSON", lineIndex: i } };
    }
    recordCount += 1;
    if (typeof record.seq !== "number") {
      return { fileName, recordCount, ok: false, failure: { reason: "Record missing `seq`", lineIndex: i } };
    }
    if (record.seq !== lastSeq + 1) {
      return {
        fileName,
        recordCount,
        ok: false,
        failure: { reason: `Sequence break: expected ${lastSeq + 1}, got ${record.seq}`, lineIndex: i },
      };
    }
    if (!record.hmac) {
      return { fileName, recordCount, ok: false, failure: { reason: "Record missing `hmac`", lineIndex: i } };
    }
    const expected = computeRecordHmac(lastHmac, record);
    if (expected !== record.hmac) {
      return {
        fileName,
        recordCount,
        ok: false,
        failure: { reason: "HMAC mismatch — record was modified, inserted, or written under a different key", lineIndex: i },
      };
    }
    lastHmac = record.hmac;
    lastSeq = record.seq;
  }
  return { fileName, recordCount, ok: true, tail: { lastHmac, lastSeq } };
}
