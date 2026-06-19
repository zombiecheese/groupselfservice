import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  SESSION_SECRET: z.string().min(16).default("change-me-in-production"),
  SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(28800),
  CREDENTIAL_ENCRYPTION_KEY: z.string().min(16).default("replace-with-32-byte-base64-or-long-random-secret"),
  AUTH_MODE: z.enum(["forms"]).default("forms"),
  SETTINGS_FILE_PATH: z.string().default("./data/portal-settings.json"),
  DEFAULT_PAGE_SIZE: z.coerce.number().int().min(10).max(500).default(100),
  MAX_BATCH_SIZE: z.coerce.number().int().min(1).max(1000).default(200),
  // Hard cap on the number of groups returned per /groups list call,
  // for both the AD and Entra repositories. Keeps a single render from
  // pulling an unbounded directory in one request. Default mirrors the
  // historical magic value.
  MAX_GROUPS_PER_LIST: z.coerce.number().int().min(50).max(5000).default(500),
  // Hard cap on the number of members returned per group-members read.
  // 999 is the LDAP/Graph practical ceiling per request.
  MAX_MEMBERS_PER_GROUP: z.coerce.number().int().min(50).max(5000).default(999),
  // Trust proxy setting passed through to Express. Accepts the same values
  // Express does: 'false' (default), 'true', a positive integer hop count, or
  // a CSV of trusted IPs/subnets such as 'loopback,linklocal,uniquelocal'.
  // Required when running behind a reverse proxy so rate-limiting keys on the
  // real client IP and request.ip / request.secure reflect upstream values.
  TRUST_PROXY: z.string().default("false"),
});

export type AppConfig = z.infer<typeof envSchema>;

export const config: AppConfig = envSchema.parse(process.env);

const DEFAULT_SESSION_SECRET = "change-me-in-production";
const DEFAULT_CREDENTIAL_KEY = "replace-with-32-byte-base64-or-long-random-secret";

// Placeholder secrets shipped in the .env template. A deployment that copies
// the template but forgets to replace a value must never boot in production
// with one of these well-known strings, even when the value happens to satisfy
// the length checks below (e.g. the SESSION_SECRET placeholder is 34 chars).
const PLACEHOLDER_SECRETS = new Set<string>([
  DEFAULT_SESSION_SECRET,
  DEFAULT_CREDENTIAL_KEY,
  "replace-with-32-char-random-secret",
]);

function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER_SECRETS.has(value) || /^(replace-with|change-me)/i.test(value);
}

// In production, refuse to start with placeholder secrets.
// In dev, emit a one-time warning so the issue is visible without breaking the inner loop.
function validateProductionSecurity(): void {
  const issues: string[] = [];
  if (looksLikePlaceholder(config.SESSION_SECRET)) {
    issues.push("SESSION_SECRET is a placeholder value; set a strong random value (>=32 chars).");
  } else if (config.SESSION_SECRET.length < 32) {
    issues.push("SESSION_SECRET is shorter than 32 characters.");
  }
  if (looksLikePlaceholder(config.CREDENTIAL_ENCRYPTION_KEY)) {
    issues.push("CREDENTIAL_ENCRYPTION_KEY is a placeholder value; set a 32-byte base64 value.");
  } else if (config.NODE_ENV === "production") {
    // In production we require a true 32-byte AES key, supplied as
    // base64 (44 chars with padding, or 43 without). A passphrase is
    // hashed to 32 bytes by `secrets-cipher.ts` but greatly reduces
    // entropy compared to a random key, so we refuse it in prod.
    const raw = Buffer.from(config.CREDENTIAL_ENCRYPTION_KEY, "base64");
    if (raw.length !== 32) {
      issues.push(
        "CREDENTIAL_ENCRYPTION_KEY must be a 32-byte value encoded as base64 in production. " +
          "Generate one with: " +
          "node -e \"console.log(require('node:crypto').randomBytes(32).toString('base64'))\"."
      );
    }
  } else if (config.CREDENTIAL_ENCRYPTION_KEY.length < 24) {
    issues.push("CREDENTIAL_ENCRYPTION_KEY is too short; provide a 32-byte base64 value or a long passphrase.");
  }

  if (issues.length === 0) {
    return;
  }

  if (config.NODE_ENV === "production") {

    console.error("Refusing to start in production with the following security issues:\n - " + issues.join("\n - "));
    process.exit(1);
  } else {

    console.warn("[security] Non-production warnings:\n - " + issues.join("\n - "));
  }
}

validateProductionSecurity();

// Normalize TRUST_PROXY into the shape Express expects:
//   'false' -> false (default; no proxy in front)
//   'true'  -> true  (trust every hop — unsafe in most setups)
//   '1', '2'  -> integer hop count
//   anything else (CSV) -> verbatim string for Express's IP/subnet parser
export function resolveTrustProxy(raw: string): boolean | number | string {
  const value = (raw || "").trim();
  if (!value || value.toLowerCase() === "false") return false;
  if (value.toLowerCase() === "true") return true;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}
