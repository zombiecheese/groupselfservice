import crypto from "node:crypto";
import { config } from "../../config/env";

// Simple AES-256-GCM string cipher used for at-rest encryption of secret-like
// fields in portal-settings.json. Values written by older builds (or hand-edited
// plaintext) round-trip through `decryptSecret` unchanged because of the marker
// prefix check, so the file transparently upgrades on the next save.

const MARKER = "enc:v1:";

function deriveKey(): Buffer {
  const raw = Buffer.from(config.CREDENTIAL_ENCRYPTION_KEY, "base64");
  if (raw.length === 32) {
    return raw;
  }
  return crypto.createHash("sha256").update(config.CREDENTIAL_ENCRYPTION_KEY, "utf-8").digest();
}

export function encryptSecret(plaintext: string): string {
  if (!plaintext) {
    return "";
  }
  if (plaintext.startsWith(MARKER)) {
    return plaintext;
  }
  const key = deriveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return MARKER + Buffer.concat([iv, tag, enc]).toString("base64");
}

export function decryptSecret(value: string): string {
  if (!value || !value.startsWith(MARKER)) {
    return value ?? "";
  }
  try {
    const blob = Buffer.from(value.slice(MARKER.length), "base64");
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const enc = blob.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", deriveKey(), iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return dec.toString("utf-8");
  } catch {
    return "";
  }
}
