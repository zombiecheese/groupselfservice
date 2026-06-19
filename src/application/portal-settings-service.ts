import crypto from "node:crypto";
import {
  AdIntegrationSettings,
  AuditIntegrationSettings,
  BrandingSettings,
  EntraIntegrationSettings,
  MailIntegrationSettings,
  NotificationSettings,
  PortalSettings,
  PortalSettingsRepository,
} from "./contracts";

// PBKDF2 iteration target. OWASP 2023 password storage cheat sheet recommends
// at least 600,000 iterations for PBKDF2-HMAC-SHA256. Existing hashes with
// fewer iterations remain valid (see `passwordHashIterations`) and are
// re-hashed on the next successful sign-in.
const PBKDF2_ITERATIONS = 600_000;
const LEGACY_PBKDF2_ITERATIONS = 120_000;

export class PortalSettingsService {
  constructor(private readonly repository: PortalSettingsRepository) {}

  async getSettings(): Promise<PortalSettings> {
    return this.repository.get();
  }

  async authenticateBreakGlass(username: string, password: string): Promise<boolean> {
    const settings = await this.repository.get();
    if (username.toLowerCase() !== settings.breakGlass.username.toLowerCase()) {
      return false;
    }
    const storedIterations = settings.breakGlass.passwordHashIterations || LEGACY_PBKDF2_ITERATIONS;
    const computed = this.hashPassword(password, settings.breakGlass.passwordSalt, storedIterations);
    const storedBuf = Buffer.from(settings.breakGlass.passwordHash, "hex");
    const computedBuf = Buffer.from(computed, "hex");
    if (storedBuf.length !== computedBuf.length) {
      return false;
    }
    const isMatch = crypto.timingSafeEqual(computedBuf, storedBuf);
    if (!isMatch) {
      return false;
    }
    // Transparent upgrade: if the stored hash uses fewer iterations than the
    // current target, re-hash and persist. Best-effort — a failed save must
    // never block the user from signing in, so errors are swallowed.
    if (storedIterations < PBKDF2_ITERATIONS) {
      try {
        const newSalt = crypto.randomBytes(16).toString("hex");
        const newHash = this.hashPassword(password, newSalt, PBKDF2_ITERATIONS);
        const next: PortalSettings = {
          ...settings,
          breakGlass: {
            ...settings.breakGlass,
            passwordSalt: newSalt,
            passwordHash: newHash,
            passwordHashIterations: PBKDF2_ITERATIONS,
          },
        };
        await this.repository.save(next);
      } catch {
        /* best-effort upgrade only */
      }
    }
    return true;
  }

  async updateSettings(input: {
    breakGlassUsername: string;
    breakGlassPassword?: string;
    ad: AdIntegrationSettings;
    entra: EntraIntegrationSettings;
    audit: AuditIntegrationSettings;
    mail: MailIntegrationSettings;
    notifications: NotificationSettings;
    delegatedAdGroupDns: string[];
    delegatedEntraGroupIds: string[];
    branding?: BrandingSettings;
    webTls?: {
      enabled: boolean;
      certPem: string;
      keyPem: string;
      passphrase: string;
      redirectHttpEnabled: boolean;
      redirectHttpPort: number;
    };
    groupDisplay?: { excludedTypes: string[] };
  }): Promise<void> {
    const current = await this.repository.get();

    const breakGlassUsername = input.breakGlassUsername.trim() || current.breakGlass.username;
    let breakGlassSalt = current.breakGlass.passwordSalt;
    let breakGlassHash = current.breakGlass.passwordHash;

    const newPassword = (input.breakGlassPassword || "").trim();
    if (newPassword) {
      breakGlassSalt = crypto.randomBytes(16).toString("hex");
      breakGlassHash = this.hashPassword(newPassword, breakGlassSalt, PBKDF2_ITERATIONS);
    }

    const next: PortalSettings = {
      breakGlass: {
        username: breakGlassUsername,
        passwordSalt: breakGlassSalt,
        passwordHash: breakGlassHash,
        passwordHashIterations: newPassword
          ? PBKDF2_ITERATIONS
          : current.breakGlass.passwordHashIterations,
      },
      ad: {
        ...input.ad,
      },
      entra: {
        ...input.entra,
      },
      audit: {
        ...input.audit,
      },
      mail: {
        ...input.mail,
        smtp: { ...input.mail.smtp },
        entra: { ...input.mail.entra },
      },
      notifications: {
        ...input.notifications,
      },
      delegatedAdmin: {
        adGroupDns: input.delegatedAdGroupDns,
        entraGroupIds: input.delegatedEntraGroupIds,
      },
      branding: input.branding
        ? { ...input.branding }
        : { ...current.branding },
      webTls: input.webTls
        ? { ...input.webTls }
        : { ...current.webTls },
      groupDisplay: input.groupDisplay
        ? { excludedTypes: [...input.groupDisplay.excludedTypes] }
        : { ...current.groupDisplay, excludedTypes: [...current.groupDisplay.excludedTypes] },
    };

    await this.repository.save(next);
  }

  static createDefaultSettings(): PortalSettings {
    const salt = crypto.randomBytes(16).toString("hex");
    const defaultPassword = "ChangeMeNow!123";
    const hash = crypto.pbkdf2Sync(defaultPassword, salt, PBKDF2_ITERATIONS, 32, "sha256").toString("hex");

    return {
      breakGlass: {
        username: "breakglass",
        passwordSalt: salt,
        passwordHash: hash,
        passwordHashIterations: PBKDF2_ITERATIONS,
      },
      ad: {
        enabled: false,
        ldapUrl: "ldaps://dc01.contoso.local:636",
        baseDn: "DC=contoso,DC=local",
        includeNestedManagedBy: true,
        tlsCaPem: "",
        tlsRejectUnauthorized: true,
        tlsServerName: "",
        ipv4Only: false,
      },
      entra: {
        enabled: false,
        tenantId: "",
        clientId: "",
        clientSecret: "",
        scope: "GroupMember.ReadWrite.All Group.Read.All User.Read openid profile",
        redirectUri: "http://localhost:3000/auth/entra/callback",
        allowMemberWrites: false,
      },
      audit: {
        enabled: true,
        filePath: "./data/audit",
        retentionDays: 90,
        syslogEnabled: false,
        syslogHost: "127.0.0.1",
        syslogPort: 514,
        syslogProtocol: "udp4",
        syslogAppName: "groupselfservice",
      },
      mail: {
        enabled: false,
        mode: "smtp",
        fromAddress: "no-reply@contoso.local",
        smtp: {
          host: "smtp.contoso.local",
          port: 587,
          secure: false,
          requireAuth: true,
          username: "",
          password: "",
          ignoreTls: false,
          allowUntrustedTls: false,
        },
        entra: {
          tenantId: "",
          clientId: "",
          clientSecret: "",
          senderUpn: "",
        },
      },
      notifications: {
        memberAddedEnabled: false,
        memberAddedSubject: "You have been added to %groupname%",
        memberAddedBody:
          "Hello %targetuser%,\n\nYou have been added to the group %groupname% in %domain% by %performedby%.\n\nIf you believe this was done in error, please contact your administrator.",
        memberRemovedEnabled: false,
        memberRemovedSubject: "You have been removed from %groupname%",
        memberRemovedBody:
          "Hello %targetuser%,\n\nYou have been removed from the group %groupname% in %domain% by %performedby%.\n\nIf you believe this was done in error, please contact your administrator.",
      },
      delegatedAdmin: {
        adGroupDns: [],
        entraGroupIds: [],
      },
      branding: {
        siteName: "Group Self Service",
        headerTitle: "Group Self Service",
        themeMode: "auto",
        themePrimary: "#0d9488",
        themeSecondary: "#7c3aed",
        notificationSuccessColor: "#198754",
        notificationFailColor: "#dc3545",
        logoDataUrl: "",
      },
      webTls: {
        enabled: false,
        certPem: "",
        keyPem: "",
        passphrase: "",
        redirectHttpEnabled: false,
        redirectHttpPort: 80,
      },
      groupDisplay: {
        excludedTypes: [],
      },
    };
  }

  private hashPassword(password: string, salt: string, iterations: number = PBKDF2_ITERATIONS): string {
    return crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex");
  }
}
