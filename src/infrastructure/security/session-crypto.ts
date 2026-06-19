import crypto from "node:crypto";
import { DirectorySessionCredentials } from "../../application/contracts";

interface EncryptedPayload {
  iv: string;
  tag: string;
  data: string;
}

function normalizeKey(keyMaterial: string): Buffer {
  const raw = Buffer.from(keyMaterial, "base64");
  if (raw.length === 32) {
    return raw;
  }
  return crypto.createHash("sha256").update(keyMaterial, "utf-8").digest();
}

export function encryptDirectoryCredentials(
  credentials: DirectorySessionCredentials,
  keyMaterial: string
): string {
  const key = normalizeKey(keyMaterial);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(credentials), "utf-8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  };

  return Buffer.from(JSON.stringify(payload), "utf-8").toString("base64");
}

export function decryptDirectoryCredentials(
  payloadB64: string,
  keyMaterial: string
): DirectorySessionCredentials | null {
  try {
    const key = normalizeKey(keyMaterial);
    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf-8")) as EncryptedPayload;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(payload.iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(payload.tag, "base64"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(payload.data, "base64")),
      decipher.final(),
    ]);

    const parsed = JSON.parse(decrypted.toString("utf-8")) as DirectorySessionCredentials;
    if (!parsed.username || !parsed.password) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function encryptEntraAccessToken(token: string, keyMaterial: string): string {
  const key = normalizeKey(keyMaterial);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(token, "utf-8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload: EncryptedPayload = {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  };

  return Buffer.from(JSON.stringify(payload), "utf-8").toString("base64");
}

export function decryptEntraAccessToken(
  payloadB64: string,
  keyMaterial: string
): string | null {
  try {
    const key = normalizeKey(keyMaterial);
    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf-8")) as EncryptedPayload;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(payload.iv, "base64")
    );
    decipher.setAuthTag(Buffer.from(payload.tag, "base64"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(payload.data, "base64")),
      decipher.final(),
    ]);

    return decrypted.toString("utf-8");
  } catch {
    return null;
  }
}
