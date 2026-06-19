import fs from "node:fs/promises";
import { PortalSettings, PortalSettingsRepository } from "../../application/contracts";
import { PortalSettingsService } from "../../application/portal-settings-service";
import { decryptSecret, encryptSecret } from "../security/secrets-cipher";
import { writeFileAtomic } from "../atomic-write";
import { logger } from "../logger";

// Sensitive fields persisted in portal-settings.json. They are stored as
// AES-256-GCM ciphertext on disk and decrypted when settings are read so the
// rest of the app continues to see plaintext.
const SECRET_PATHS: Array<(s: PortalSettings) => { get: () => string; set: (v: string) => void }> = [
  (s) => ({ get: () => s.entra.clientSecret, set: (v) => (s.entra.clientSecret = v) }),
  (s) => ({ get: () => s.mail.smtp.password, set: (v) => (s.mail.smtp.password = v) }),
  (s) => ({ get: () => s.mail.entra.clientSecret, set: (v) => (s.mail.entra.clientSecret = v) }),
  (s) => ({ get: () => s.webTls.keyPem, set: (v) => (s.webTls.keyPem = v) }),
  (s) => ({ get: () => s.webTls.passphrase, set: (v) => (s.webTls.passphrase = v) }),
];

function decryptInPlace(settings: PortalSettings): PortalSettings {
  for (const accessor of SECRET_PATHS) {
    const slot = accessor(settings);
    const current = slot.get();
    if (current) {
      slot.set(decryptSecret(current));
    }
  }
  return settings;
}

function encryptForDisk(settings: PortalSettings): PortalSettings {
  // Operate on a deep clone so callers keep their plaintext copy intact.
  const clone: PortalSettings = JSON.parse(JSON.stringify(settings));
  for (const accessor of SECRET_PATHS) {
    const slot = accessor(clone);
    const current = slot.get();
    if (current) {
      slot.set(encryptSecret(current));
    }
  }
  return clone;
}

export class FilePortalSettingsRepository implements PortalSettingsRepository {
  constructor(private readonly filePath: string) {}

  async get(): Promise<PortalSettings> {
    let raw: string;
    try {
      raw = await fs.readFile(this.filePath, "utf-8");
    } catch (err) {
      // ENOENT is the expected first-run state: no settings file yet, write
      // defaults and return them. Anything else (EACCES, EIO, etc.) must
      // not silently rotate defaults — that would clobber a real settings
      // file the operator hasn't fixed yet, including the break-glass
      // password hash.
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        logger.error("Settings file unreadable; refusing to overwrite with defaults", {
          path: this.filePath,
          code,
          message: (err as Error).message,
        });
        throw err;
      }
      const defaults = PortalSettingsService.createDefaultSettings();
      await this.save(defaults);
      return defaults;
    }

    if (!raw.trim()) {
      // Empty file. Almost always means a previous write was interrupted
      // before the new contents could be committed, and the (long-fixed)
      // non-atomic write left a zero-byte file behind. Fail loudly instead
      // of overwriting with defaults — the operator can investigate and
      // restore from backup, then restart.
      logger.error("Settings file is empty; refusing to overwrite with defaults", { path: this.filePath });
      throw new Error(`Settings file '${this.filePath}' is empty. Restore from backup or delete to re-create defaults.`);
    }

    let parsed: Partial<PortalSettings>;
    try {
      parsed = JSON.parse(raw) as Partial<PortalSettings>;
    } catch (err) {
      logger.error("Settings file is not valid JSON; refusing to overwrite with defaults", {
        path: this.filePath,
        message: (err as Error).message,
      });
      throw new Error(
        `Settings file '${this.filePath}' is not valid JSON. Restore from backup or delete to re-create defaults.`,
        { cause: err }
      );
    }

    const defaults = PortalSettingsService.createDefaultSettings();

    const merged: PortalSettings = {
      ...defaults,
      ...parsed,
      breakGlass: {
        ...defaults.breakGlass,
        ...(parsed.breakGlass ?? {}),
      },
      ad: {
        ...defaults.ad,
        ...(parsed.ad ?? {}),
      },
      entra: {
        ...defaults.entra,
        ...(parsed.entra ?? {}),
      },
      audit: {
        ...defaults.audit,
        ...(parsed.audit ?? {}),
      },
      mail: {
        ...defaults.mail,
        ...(parsed.mail ?? {}),
        smtp: {
          ...defaults.mail.smtp,
          ...((parsed.mail ?? {}).smtp ?? {}),
        },
        entra: {
          ...defaults.mail.entra,
          ...((parsed.mail ?? {}).entra ?? {}),
        },
      },
      notifications: {
        ...defaults.notifications,
        ...(parsed.notifications ?? {}),
      },
      delegatedAdmin: {
        ...defaults.delegatedAdmin,
        ...(parsed.delegatedAdmin ?? {}),
      },
      branding: {
        ...defaults.branding,
        ...(parsed.branding ?? {}),
      },
      webTls: {
        ...defaults.webTls,
        ...(parsed.webTls ?? {}),
      },
      groupDisplay: {
        ...defaults.groupDisplay,
        ...(parsed.groupDisplay ?? {}),
      },
    };
    return decryptInPlace(merged);
  }

  async save(settings: PortalSettings): Promise<void> {
    const onDisk = encryptForDisk(settings);
    await writeFileAtomic(
      this.filePath,
      JSON.stringify(onDisk, null, 2),
      { mode: 0o600 }
    );
  }
}
