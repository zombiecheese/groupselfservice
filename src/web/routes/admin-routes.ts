import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { Client as LdapClient } from "ldapts";
import nodemailer from "nodemailer";
import { z } from "zod";
import { AdDirectoryRepository } from "../../application/contracts";
import { MailService } from "../../application/mail-service";
import { PortalAdminAuthorizationService } from "../../application/portal-admin-authorization-service";
import { PortalSettingsService } from "../../application/portal-settings-service";
import { buildLdapTlsOptions, pickReachableHost } from "../../infrastructure/ad/ldap-ad-repository";
import { logger } from "../../infrastructure/logger";
import { groupListLatency } from "../../infrastructure/metrics";
import { asyncHandler } from "../async-handler";
import { requireAuth } from "../auth-middleware";
import { getDirectoryCredentials, getEntraAccessToken } from "../session-directory-credentials";

// Application metadata shown in the settings "About" tab. Read once from
// package.json (copied next to dist/ in the container image) so the version,
// description, author and repository links stay in sync with the manifest.
const APP_INFO = (() => {
  const fallback = {
    name: "groupselfservice",
    version: "0.0.0",
    description: "",
    author: "",
    repositoryUrl: "",
    issuesUrl: "",
    homepageUrl: "",
    license: "",
  };
  try {
    const pkgPath = path.join(__dirname, "..", "..", "..", "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    const repoUrl = typeof pkg.repository === "string" ? pkg.repository : pkg.repository?.url || "";
    const normalizedRepo = repoUrl.replace(/^git\+/, "").replace(/\.git$/, "");
    return {
      name: pkg.name || fallback.name,
      version: pkg.version || fallback.version,
      description: pkg.description || fallback.description,
      author: typeof pkg.author === "string" ? pkg.author : pkg.author?.name || "",
      repositoryUrl: normalizedRepo,
      issuesUrl: pkg.bugs?.url || (normalizedRepo ? normalizedRepo + "/issues" : ""),
      homepageUrl: pkg.homepage || normalizedRepo,
      license: pkg.license || fallback.license,
    };
  } catch {
    return fallback;
  }
})();

// Semantic check for an LDAP URL admin-input. Empty is allowed because
// settings may be partially populated; non-empty must parse to ldap:// or
// ldaps:// with a hostname. Returns null on success, or a short error string
// suitable for the flash banner on failure.
function validateLdapUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return "LDAP URL is not a valid URL.";
  }
  if (parsed.protocol !== "ldap:" && parsed.protocol !== "ldaps:") {
    return "LDAP URL must use the ldap:// or ldaps:// scheme.";
  }
  if (!parsed.hostname) {
    return "LDAP URL must include a hostname.";
  }
  return null;
}

// Same shape for the Entra OAuth redirect URI. http is allowed for localhost
// development only; everything else must be https.
function validateRedirectUri(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return "Redirect URI is not a valid URL.";
  }
  const isLocalhost =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "::1";
  if (parsed.protocol === "https:") return null;
  if (parsed.protocol === "http:" && isLocalhost) return null;
  return "Redirect URI must use https:// (http://localhost is allowed for dev).";
}

// Audit file path. Admins legitimately use absolute paths for log shipping,
// but `..` traversal is never appropriate for a log directory and is almost
// always either a typo or an attempted escape. Control characters are also
// rejected. Returns null on success, or a short error string on failure.
function validateAuditPath(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return "Audit file path is required.";
  if (/[\u0000-\u001f]/.test(trimmed)) {
    return "Audit file path must not contain control characters.";
  }
  // Split on either separator so Windows-style paths are checked too.
  const segments = trimmed.split(/[\\/]/);
  if (segments.some((seg) => seg === "..")) {
    return "Audit file path must not contain '..' segments.";
  }
  return null;
}

function describeError(error: unknown): { message: string; details: Record<string, unknown> } {
  if (error instanceof Error) {
    const anyErr = error as Error & { code?: string; errno?: number; cause?: unknown };
    const causeMessage =
      anyErr.cause instanceof Error ? anyErr.cause.message : anyErr.cause ? String(anyErr.cause) : undefined;
    const parts: string[] = [error.message];
    if (anyErr.code) parts.push(`code=${anyErr.code}`);
    if (causeMessage) parts.push(`cause=${causeMessage}`);
    return {
      message: parts.join(" | "),
      details: {
        name: error.name,
        message: error.message,
        code: anyErr.code,
        errno: anyErr.errno,
        cause: causeMessage,
        stack: error.stack,
      },
    };
  }
  return { message: String(error), details: { value: String(error) } };
}

function parseLines(input?: string): string[] {
  return (input || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function trim(value: unknown): string {
  return String(value ?? "").trim();
}

// Form posts of <input type="checkbox" name="excludedGroupTypes" value="...">
// arrive as either a single string (one checkbox ticked) or an array (two or
// more). Empty/missing input means no exclusions. Whitespace is trimmed,
// blanks dropped, and duplicates removed so the persisted list is canonical.
// Mirror the same allow-list used by groups-routes. Flash values come from
// redirect query strings and must not carry arbitrary HTML into the template.
function sanitizeFlash(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  if (!/^[a-zA-Z0-9 ,+\-.':()]*$/.test(value)) return undefined;
  return value;
}

function collectExcludedGroupTypes(raw: unknown): string[] {
  const list = Array.isArray(raw) ? raw : raw === undefined || raw === null ? [] : [raw];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of list) {
    const cleaned = String(value ?? "").trim();
    if (!cleaned) continue;
    const key = cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(cleaned);
  }
  return out;
}

const generalSchema = z.object({
  brandingSiteName: z.string().optional(),
  brandingHeaderTitle: z.string().optional(),
  brandingThemeMode: z.enum(["auto", "light", "dark"]).optional(),
  brandingThemePrimary: z.string().optional(),
  brandingThemeSecondary: z.string().optional(),
  brandingNotificationSuccessColor: z.string().optional(),
  brandingNotificationFailColor: z.string().optional(),
  brandingLogoDataUrl: z.string().optional(),
});

const securitySchema = z.object({
  breakGlassUsername: z.string().min(1),
  breakGlassPassword: z.string().optional(),
  delegatedAdGroupDns: z.string().optional(),
  delegatedEntraGroupIds: z.string().optional(),
  webTlsCertPem: z.string().optional(),
  webTlsKeyPem: z.string().optional(),
  webTlsPassphrase: z.string().optional(),
  webTlsRedirectHttpPort: z.coerce.number().int().min(1).max(65535).optional(),
});

const directorySchema = z.object({
  adLdapUrl: z.string().optional(),
  adBaseDn: z.string().optional(),
  adTlsCaPem: z.string().optional(),
  adTlsServerName: z.string().optional(),
  entraTenantId: z.string().optional(),
  entraClientId: z.string().optional(),
  entraClientSecret: z.string().optional(),
  entraScope: z.string().optional(),
  entraRedirectUri: z.string().optional(),
});

const mailSchema = z.object({
  mailFromAddress: z.string().optional(),
  mailMode: z.enum(["smtp", "entra"]).optional(),
  mailSmtpHost: z.string().optional(),
  mailSmtpPort: z.coerce.number().int().positive().optional(),
  mailSmtpUsername: z.string().optional(),
  mailSmtpPassword: z.string().optional(),
  mailEntraTenantId: z.string().optional(),
  mailEntraClientId: z.string().optional(),
  mailEntraClientSecret: z.string().optional(),
  mailEntraSenderUpn: z.string().optional(),
});

const notificationsSchema = z.object({
  notifyMemberAddedSubject: z.string().optional(),
  notifyMemberAddedBody: z.string().optional(),
  notifyMemberRemovedSubject: z.string().optional(),
  notifyMemberRemovedBody: z.string().optional(),
});

const auditSchema = z.object({
  auditFilePath: z.string().optional(),
  auditRetentionDays: z.coerce.number().int().positive().optional(),
  auditSyslogHost: z.string().optional(),
  auditSyslogPort: z.coerce.number().int().positive().optional(),
  auditSyslogProtocol: z.enum(["udp4", "udp6"]).optional(),
  auditSyslogAppName: z.string().optional(),
});

export function createAdminRoutes(
  settingsService: PortalSettingsService,
  adminAuthorizationService: PortalAdminAuthorizationService,
  mailService: MailService,
  adRepository: AdDirectoryRepository,
  auditReader: { read: (q: { fromIso: string; toIso: string; limit?: number; actorContains?: string; actionEquals?: string; sourceEquals?: "ad" | "entra"; groupContains?: string; statusEquals?: "success" | "failure" }) => Promise<import("../../domain/models").AuditRecord[]> }
): Router {
  const router = Router();

  router.use(requireAuth);

  // Cache window for delegated-portal-admin checks per session. Group
  // membership is the slowest and most-repeated lookup on /admin/*; without
  // a cache, every request triggers N AD + M Entra group reads. 60 s is
  // short enough that a removed delegated admin loses access promptly, and
  // long enough to coalesce a typical browsing session into one check.
  const ADMIN_CHECK_TTL_MS = 60_000;

    router.use(asyncHandler(async (req, res, next) => {
    const now = Date.now();
    const cachedAt = req.session.isPortalAdminCheckedAt ?? 0;
    const cachedToken = req.session.isPortalAdminCheckEntraToken ?? "";
    const currentToken = getEntraAccessToken(req.session) ?? "";
    // Re-check whenever the cache has expired, the cached decision is
    // missing, or the Entra token presence/identity changed (a fresh
    // /entra/callback could grant admin via a Entra group).
    const cacheValid =
      typeof req.session.isPortalAdmin === "boolean" &&
      now - cachedAt < ADMIN_CHECK_TTL_MS &&
      cachedToken === currentToken;

    let isAdmin: boolean;
    if (cacheValid) {
      isAdmin = req.session.isPortalAdmin === true;
    } else {
      isAdmin = await adminAuthorizationService.isPortalAdmin(
        req.user!,
        req.session.isBreakGlass === true,
        getDirectoryCredentials(req.session),
        currentToken || undefined
      );
      req.session.isPortalAdmin = isAdmin;
      req.session.isPortalAdminCheckedAt = now;
      req.session.isPortalAdminCheckEntraToken = currentToken;
    }

    if (!isAdmin) {
      // If the user might be a delegated portal admin via an Entra group but
      // hasn't yet connected to Entra in this session, surface a tailored
      // message with a direct link to the OAuth flow instead of a flat 403.
      // The settings file is read once per request anyway via the service.
      const settings = await settingsService.getSettings();
      const couldBeEntraAdmin =
        settings.entra.enabled &&
        !getEntraAccessToken(req.session) &&
        Array.isArray(settings.delegatedAdmin?.entraGroupIds) &&
        settings.delegatedAdmin.entraGroupIds.length > 0;
      if (couldBeEntraAdmin) {
        res.status(403).render("error", {
          title: "Connect to Microsoft Entra ID",
          message:
            "Portal administration may be granted to you via Entra group membership. Connect to Microsoft Entra ID to verify.",
          correlationId: req.correlationId,
          actionHref: "/auth/entra/start",
          actionLabel: "Connect Entra ID",
        });
        return;
      }
      res.status(403).render("error", {
        title: "Access denied",
        message: "Only break-glass or delegated portal admins can access this page.",
        correlationId: req.correlationId,
      });
      return;
    }

        next();
  }));

  // First-run wizard. Shown only while neither AD nor Entra is enabled —
  // once either toggle is on, this page redirects to the regular settings
  // tabs so the wizard doesn't keep nagging the operator.
  router.get("/setup", asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    if (settings.ad.enabled || settings.entra.enabled) {
      res.redirect("/admin/settings");
      return;
    }
    res.render("admin-setup", {
      title: "Welcome — first-run setup",
      csrfToken: req.csrfToken!(),
      user: req.user,
            settings,
    });
  }));

  router.get("/settings", asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    const credentials = getDirectoryCredentials(req.session);

    // Resolve display names for existing delegated AD groups so chips can show
    // friendly labels. Failures fall back to the raw DN. Skipped when AD is
    // disabled to avoid pointless mock lookups.
    const delegatedAdGroups = await Promise.all(
      settings.delegatedAdmin.adGroupDns.map(async (dn) => {
        if (!settings.ad.enabled) {
          return { dn, name: dn };
        }
        try {
          const g = await adRepository.getGroup(dn, credentials);
          return { dn, name: g?.name || dn, description: g?.description };
        } catch {
          return { dn, name: dn };
        }
      })
    );

        res.render("admin-settings", {
      title: "Portal Settings",
      csrfToken: req.csrfToken!(),
      user: req.user,
      flash: sanitizeFlash(req.query.flash),
      flashKind: sanitizeFlash(req.query.flashKind),
      tab: sanitizeFlash(req.query.tab),
      settings,
      delegatedAdGroups,
      isBreakGlass: req.session.isBreakGlass === true,
      appInfo: APP_INFO,
    });
  }));

  // AD group lookup for the delegated-admin picker. Returns up to 25 matches
  // by CN/sAMAccountName/displayName containing the query. Requires the admin
  // to have signed in with directory credentials (mock repo is used otherwise
  // when AD is disabled in settings).
  router.get("/lookup/ad-groups", asyncHandler(async (req, res) => {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) {
      res.json([]);
      return;
    }
    const credentials = getDirectoryCredentials(req.session);
    const settings = await settingsService.getSettings();
    if (settings.ad.enabled && !credentials) {
      res.status(412).json({
        error: "ad_credentials_required",
        message: "AD is enabled but you signed in without directory credentials. Sign in with an AD account to search AD groups, or temporarily disable AD to use mock results.",
      });
      return;
    }
    try {
      const results = await adRepository.searchAdGroups(q, 25, credentials);
      res.json(results.map((g) => ({ dn: g.dn, name: g.name, description: g.description })));
    } catch (err) {
      const message = (err as Error).message || "lookup_failed";
      logger.warn("ad-groups lookup failed", { err: message, query: q });
            res.status(502).json({ error: "lookup_failed", message });
    }
  }));

  // Entra group lookup. Uses the admin's current Graph access token (set after
  // /auth/entra/callback). If no token is present we return 401 so the UI can
  // prompt the admin to sign in to Entra first.
  router.get("/lookup/entra-groups", asyncHandler(async (req, res) => {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) {
      res.json([]);
      return;
    }
    const token = getEntraAccessToken(req.session);
    if (!token) {
      res.status(401).json({ error: "entra_signin_required" });
      return;
    }
    try {
      const url =
        "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description&$top=25" +
        `&$filter=${encodeURIComponent(`startswith(displayName,'${q.replace(/'/g, "''")}')`)}`;
      const response = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) {
        res.status(502).json({ error: "graph_error", status: response.status });
        return;
      }
      const data = (await response.json()) as { value?: Array<{ id: string; displayName: string; description?: string }> };
      res.json((data.value || []).map((g) => ({ id: g.id, displayName: g.displayName, description: g.description })));
    } catch (err) {
      logger.warn("entra-groups lookup failed", { err: (err as Error).message });
            res.status(502).json({ error: "lookup_failed" });
    }
  }));

  // ----- Health snapshot -----
  // Aggregated status used by the admin Health tab. All probes are best-effort,
  // capped with short timeouts, and failures are reported as `fail` without
  // throwing so the page always renders. Sensitive values (secrets, full URLs)
  // are not echoed back; only booleans and short messages.
  router.get("/health", asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    const startedAtMs = Date.now();

    // App self-check
    const memory = process.memoryUsage();
    const app = {
      status: "ok" as "ok" | "warn" | "fail",
      message: "Application running.",
      uptimeSeconds: Math.round(process.uptime()),
      nodeVersion: process.version,
      pid: process.pid,
      platform: process.platform,
      heapUsedMb: Math.round((memory.heapUsed / 1024 / 1024) * 100) / 100,
      rssMb: Math.round((memory.rss / 1024 / 1024) * 100) / 100,
      settingsLoaded: !!settings,
      auditEnabled: settings.audit.enabled,
    };

    // AD connectivity probe (DNS + TCP only — keeps it cheap and credential-free)
    const ad: {
      status: "ok" | "warn" | "fail" | "disabled";
      message: string;
      enabled: boolean;
      ldapUrl?: string;
      tlsRejectUnauthorized?: boolean;
      durationMs?: number;
    } = {
      status: settings.ad.enabled ? "warn" : "disabled",
      message: settings.ad.enabled ? "Probing..." : "AD integration disabled in settings.",
      enabled: settings.ad.enabled,
      ldapUrl: settings.ad.enabled ? settings.ad.ldapUrl : undefined,
      tlsRejectUnauthorized: settings.ad.enabled ? settings.ad.tlsRejectUnauthorized : undefined,
    };
    if (settings.ad.enabled && settings.ad.ldapUrl) {
      const adStart = Date.now();
      try {
        const parsed = new URL(settings.ad.ldapUrl);
        const isTls = parsed.protocol === "ldaps:";
        const port = Number(parsed.port) || (isTls ? 636 : 389);
        const dns = await import("node:dns/promises");
        const addrs = await dns.lookup(parsed.hostname, { all: true, family: settings.ad.ipv4Only ? 4 : 0 });
        if (addrs.length === 0) {
          throw new Error("DNS returned no addresses");
        }
        const net = await import("node:net");
        await new Promise<void>((resolve, reject) => {
          const sock = net.connect({ host: addrs[0].address, port, timeout: 4000 });
          sock.once("connect", () => { sock.end(); resolve(); });
          sock.once("timeout", () => { sock.destroy(); reject(new Error("timeout")); });
          sock.once("error", reject);
        });
        ad.status = "ok";
        ad.message = `Reachable at ${addrs[0].address}:${port}.`;
      } catch (err) {
        ad.status = "fail";
        ad.message = `${(err as Error).message}`;
      }
      ad.durationMs = Date.now() - adStart;
    }

    // Entra connectivity probe — checks tenant metadata, plus uses the admin's
    // current bearer token (if any) to call /me as a delegated permission proof.
    const entra: {
      status: "ok" | "warn" | "fail" | "disabled";
      message: string;
      enabled: boolean;
      tenantId?: string;
      hasUserToken: boolean;
      scope?: string;
      allowMemberWrites: boolean;
      meDisplayName?: string;
      durationMs?: number;
    } = {
      status: settings.entra.enabled ? "warn" : "disabled",
      message: settings.entra.enabled ? "Probing..." : "Entra integration disabled in settings.",
      enabled: settings.entra.enabled,
      tenantId: settings.entra.enabled ? settings.entra.tenantId : undefined,
      hasUserToken: !!getEntraAccessToken(req.session),
      scope: settings.entra.enabled ? settings.entra.scope : undefined,
      allowMemberWrites: settings.entra.allowMemberWrites,
    };
    if (settings.entra.enabled && settings.entra.tenantId) {
      const entraStart = Date.now();
      try {
        const wellKnown = await fetch(
          `https://login.microsoftonline.com/${encodeURIComponent(settings.entra.tenantId)}/v2.0/.well-known/openid-configuration`,
          { signal: AbortSignal.timeout(5000) }
        );
        if (!wellKnown.ok) {
          throw new Error(`tenant metadata HTTP ${wellKnown.status}`);
        }
        if (getEntraAccessToken(req.session)) {
          const me = await fetch("https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName", {
            headers: { Authorization: `Bearer ${getEntraAccessToken(req.session)}` },
            signal: AbortSignal.timeout(5000),
          });
          if (me.ok) {
            const body = (await me.json()) as { displayName?: string; userPrincipalName?: string };
            entra.status = "ok";
            entra.meDisplayName = body.displayName || body.userPrincipalName;
            const writeNote = settings.entra.allowMemberWrites
              ? /GroupMember\.ReadWrite\.All/i.test(settings.entra.scope)
                ? "member writes enabled and scope includes GroupMember.ReadWrite.All"
                : "member writes enabled but scope is missing GroupMember.ReadWrite.All"
              : "member writes disabled (read-only)";
            entra.message = `Tenant reachable; signed in as ${entra.meDisplayName || "unknown"}; ${writeNote}.`;
            if (settings.entra.allowMemberWrites && !/GroupMember\.ReadWrite\.All/i.test(settings.entra.scope)) {
              entra.status = "warn";
            }
          } else if (me.status === 401) {
            entra.status = "warn";
            entra.message = "Tenant reachable but admin token expired or invalid (HTTP 401). Sign out and back in.";
          } else {
            entra.status = "warn";
            entra.message = `Tenant reachable but Graph /me returned HTTP ${me.status}.`;
          }
        } else {
          entra.status = "warn";
          entra.message = "Tenant metadata reachable. Sign in to Entra to verify delegated permissions.";
        }
      } catch (err) {
        entra.status = "fail";
        entra.message = (err as Error).message || "Entra probe failed.";
      }
      entra.durationMs = Date.now() - entraStart;
    }

    // Mail config status — config-only check (no SMTP/Graph round-trip). Use
    // the existing test-mail endpoint for an active probe.
    const mail: {
      status: "ok" | "warn" | "fail" | "disabled";
      message: string;
      enabled: boolean;
      mode?: string;
      fromAddress?: string;
      smtpHost?: string;
      smtpPort?: number;
      smtpRequireAuth?: boolean;
      tenantConfigured?: boolean;
    } = {
      status: settings.mail.enabled ? "warn" : "disabled",
      message: settings.mail.enabled ? "Configured but not actively probed (use Test Mail)." : "Mail integration disabled in settings.",
      enabled: settings.mail.enabled,
    };
    if (settings.mail.enabled) {
      mail.mode = settings.mail.mode;
      mail.fromAddress = settings.mail.fromAddress;
      const issues: string[] = [];
      if (!settings.mail.fromAddress) issues.push("missing from address");
      if (settings.mail.mode === "smtp") {
        mail.smtpHost = settings.mail.smtp.host;
        mail.smtpPort = settings.mail.smtp.port;
        mail.smtpRequireAuth = settings.mail.smtp.requireAuth;
        if (!settings.mail.smtp.host) issues.push("missing SMTP host");
        if (!settings.mail.smtp.port) issues.push("missing SMTP port");
        if (settings.mail.smtp.requireAuth && !settings.mail.smtp.username) issues.push("auth enabled but no username");
      } else {
        mail.tenantConfigured =
          !!settings.mail.entra.tenantId && !!settings.mail.entra.clientId && !!settings.mail.entra.clientSecret;
        if (!mail.tenantConfigured) issues.push("Graph credentials incomplete");
        if (!settings.mail.entra.senderUpn) issues.push("missing sender UPN");
      }
      if (issues.length === 0) {
        mail.status = "ok";
        mail.message = `Configured (${settings.mail.mode}).`;
      } else {
        mail.status = "warn";
        mail.message = `Configured but: ${issues.join("; ")}.`;
      }
    }

    res.json({
      generatedAt: new Date().toISOString(),
      generationDurationMs: Date.now() - startedAtMs,
      app,
      ad,
      entra,
      mail,
      metrics: {
        groupList: groupListLatency.stats(),
            },
    });
  }));

  router.post("/settings/general", asyncHandler(async (req, res) => {
    const parsed = generalSchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=general&flashKind=error&flash=Invalid+general+settings");
      return;
    }
    const current = await settingsService.getSettings();
    const siteName = trim(parsed.data.brandingSiteName) || current.branding.siteName || "Group Self Service";
    const headerTitle = trim(parsed.data.brandingHeaderTitle) || siteName;
    const HEX = /^#[0-9a-fA-F]{6}$/;
    const themeMode = parsed.data.brandingThemeMode ?? current.branding.themeMode ?? "auto";
    const primaryRaw = trim(parsed.data.brandingThemePrimary);
    const secondaryRaw = trim(parsed.data.brandingThemeSecondary);
    const themePrimary = HEX.test(primaryRaw) ? primaryRaw.toLowerCase() : current.branding.themePrimary || "#0d9488";
    const themeSecondary = HEX.test(secondaryRaw) ? secondaryRaw.toLowerCase() : current.branding.themeSecondary || "#7c3aed";
    const successRaw = trim(parsed.data.brandingNotificationSuccessColor);
    const failRaw = trim(parsed.data.brandingNotificationFailColor);
    const notificationSuccessColor = HEX.test(successRaw)
      ? successRaw.toLowerCase()
      : current.branding.notificationSuccessColor || "#198754";
    const notificationFailColor = HEX.test(failRaw)
      ? failRaw.toLowerCase()
      : current.branding.notificationFailColor || "#dc3545";
    const logoDataUrl = String(parsed.data.brandingLogoDataUrl ?? "").trim();

    if (logoDataUrl && !/^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml);base64,/i.test(logoDataUrl)) {
      res.redirect("/admin/settings?tab=general&flashKind=error&flash=Logo+must+be+a+PNG%2C+JPG%2C+GIF%2C+WebP%2C+or+SVG+image+upload.");
      return;
    }

    if (logoDataUrl.length > 2_000_000) {
      res.redirect("/admin/settings?tab=general&flashKind=error&flash=Logo+image+is+too+large.+Choose+a+file+under+2+MB+or+compress+the+image+and+try+again.");
      return;
    }

    // Branding + group-display only. Break-glass, delegated-admin, and web
    // TLS settings live on the Security tab and are preserved verbatim from
    // `current` so a General save never wipes them.
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: current.entra,
      audit: current.audit,
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      branding: { siteName, headerTitle, themeMode, themePrimary, themeSecondary, notificationSuccessColor, notificationFailColor, logoDataUrl },
      groupDisplay: {
        excludedTypes: collectExcludedGroupTypes(req.body.excludedGroupTypes),
      },
    });
        res.redirect("/admin/settings?tab=general&flash=General+settings+saved");
  }));

  // Save Security tab: break-glass admin, web TLS, delegated admin groups.
  // Branding + group-display are preserved verbatim (the General tab owns
  // those).
  router.post("/settings/security", asyncHandler(async (req, res) => {
    const parsed = securitySchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=security&flashKind=error&flash=Invalid+security+settings");
      return;
    }
    const current = await settingsService.getSettings();
    const webTlsEnabled = req.body.webTlsEnabled === "on";
    const webTlsCertPem = String(parsed.data.webTlsCertPem ?? "").trim();
    const webTlsKeyPem = String(parsed.data.webTlsKeyPem ?? "").trim();
    const webTlsPassphrase = String(parsed.data.webTlsPassphrase ?? "");
    const webTlsRedirectHttpEnabled = req.body.webTlsRedirectHttpEnabled === "on";
    const webTlsRedirectHttpPort = parsed.data.webTlsRedirectHttpPort ?? current.webTls.redirectHttpPort ?? 80;

    if (webTlsEnabled && (!webTlsCertPem || !webTlsKeyPem)) {
      res.redirect("/admin/settings?tab=security&flashKind=error&flash=TLS+requires+both+a+certificate+and+private+key");
      return;
    }
    if (webTlsRedirectHttpEnabled && !webTlsEnabled) {
      res.redirect("/admin/settings?tab=security&flashKind=error&flash=Enable+native+HTTPS+before+turning+on+HTTP+redirects");
      return;
    }

    await settingsService.updateSettings({
      breakGlassUsername: parsed.data.breakGlassUsername,
      breakGlassPassword: parsed.data.breakGlassPassword,
      ad: current.ad,
      entra: current.entra,
      audit: current.audit,
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: parseLines(parsed.data.delegatedAdGroupDns),
      delegatedEntraGroupIds: parseLines(parsed.data.delegatedEntraGroupIds),
      webTls: {
        enabled: webTlsEnabled,
        certPem: webTlsCertPem,
        keyPem: webTlsKeyPem,
        passphrase: webTlsPassphrase,
        redirectHttpEnabled: webTlsRedirectHttpEnabled,
        redirectHttpPort: webTlsRedirectHttpPort,
      },
    });
        res.redirect("/admin/settings?tab=security&flash=Security+settings+saved");
  }));

  // Save AD settings only. Entra fields in the same payload (if any) are
  // ignored; the user explicitly chose to save the AD card.
  router.post("/settings/directory/ad", asyncHandler(async (req, res) => {
    const parsed = directorySchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=directory&flashKind=error&flash=Invalid+directory+settings");
      return;
    }
    const current = await settingsService.getSettings();
    const adLdapUrl = trim(parsed.data.adLdapUrl);
    const adLdapUrlError = validateLdapUrl(adLdapUrl);
    if (adLdapUrlError) {
      res.redirect(
        `/admin/settings?tab=directory&flashKind=error&flash=${encodeURIComponent(adLdapUrlError)}`
      );
      return;
    }
    const adTlsAllowUntrusted = req.body.adTlsAllowUntrusted === "on";
    if (adTlsAllowUntrusted && current.ad.tlsRejectUnauthorized !== false) {
      logger.warn("AD_TLS_VALIDATION_DISABLED", {
        actor: req.user?.samAccountName,
        ldapUrl: adLdapUrl,
      });
    } else if (!adTlsAllowUntrusted && current.ad.tlsRejectUnauthorized === false) {
      logger.info("AD_TLS_VALIDATION_REENABLED", { actor: req.user?.samAccountName });
    }
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: {
        enabled: req.body.adEnabled === "on",
        ldapUrl: adLdapUrl,
        baseDn: trim(parsed.data.adBaseDn),
        includeNestedManagedBy: req.body.adIncludeNestedManagedBy === "on",
        tlsCaPem: String(parsed.data.adTlsCaPem ?? ""),
        tlsRejectUnauthorized: !adTlsAllowUntrusted,
        tlsServerName: trim(parsed.data.adTlsServerName),
        ipv4Only: req.body.adIpv4Only === "on",
      },
      entra: current.entra,
      audit: current.audit,
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      webTls: current.webTls,
    });
        res.redirect("/admin/settings?tab=directory&flash=Active+Directory+settings+saved");
  }));

  // Save Entra settings only.
  router.post("/settings/directory/entra", asyncHandler(async (req, res) => {
    const parsed = directorySchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=directory&flashKind=error&flash=Invalid+directory+settings");
      return;
    }
    const current = await settingsService.getSettings();
    const entraRedirectUri = trim(parsed.data.entraRedirectUri);
    const entraRedirectError = validateRedirectUri(entraRedirectUri);
    if (entraRedirectError) {
      res.redirect(
        `/admin/settings?tab=directory&flashKind=error&flash=${encodeURIComponent(entraRedirectError)}`
      );
      return;
    }
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: {
        enabled: req.body.entraEnabled === "on",
        tenantId: trim(parsed.data.entraTenantId),
        clientId: trim(parsed.data.entraClientId),
        clientSecret: trim(parsed.data.entraClientSecret),
        scope: trim(parsed.data.entraScope),
        redirectUri: entraRedirectUri,
        allowMemberWrites: req.body.entraAllowMemberWrites === "on",
      },
      audit: current.audit,
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      webTls: current.webTls,
    });
        res.redirect("/admin/settings?tab=directory&flash=Entra+ID+settings+saved");
  }));

  // Save mail server settings only. The view posts both delivery-mode blocks
  // (the hidden one too), so the inactive mode's values are preserved; the
  // selected `mailMode` decides which transport is actually used.
  router.post("/settings/mail", asyncHandler(async (req, res) => {
    const parsed = mailSchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=notifications&flashKind=error&flash=Invalid+mail+settings");
      return;
    }
    const current = await settingsService.getSettings();
    const smtpIgnoreTls = req.body.mailSmtpIgnoreTls === "on";
    const smtpAllowUntrustedTls = req.body.mailSmtpAllowUntrustedTls === "on";
    const smtpRequireAuth = req.body.mailSmtpRequireAuth === "on";
    if (smtpIgnoreTls && !current.mail.smtp.ignoreTls) {
      logger.warn("SMTP_STARTTLS_DISABLED", { actor: req.user?.samAccountName });
    }
    if (smtpAllowUntrustedTls && !current.mail.smtp.allowUntrustedTls) {
      logger.warn("SMTP_TLS_VALIDATION_DISABLED", { actor: req.user?.samAccountName });
    }
    if (!smtpRequireAuth && current.mail.smtp.requireAuth) {
      logger.warn("SMTP_AUTH_DISABLED", { actor: req.user?.samAccountName });
    }
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: current.entra,
      audit: current.audit,
      mail: {
        enabled: req.body.mailEnabled === "on",
        mode: parsed.data.mailMode || "smtp",
        fromAddress: trim(parsed.data.mailFromAddress),
        smtp: {
          host: trim(parsed.data.mailSmtpHost),
          port: parsed.data.mailSmtpPort || 587,
          secure: req.body.mailSmtpSecure === "on",
          requireAuth: smtpRequireAuth,
          username: trim(parsed.data.mailSmtpUsername),
          password: trim(parsed.data.mailSmtpPassword),
          ignoreTls: smtpIgnoreTls,
          allowUntrustedTls: smtpAllowUntrustedTls,
        },
        entra: {
          tenantId: trim(parsed.data.mailEntraTenantId),
          clientId: trim(parsed.data.mailEntraClientId),
          clientSecret: trim(parsed.data.mailEntraClientSecret),
          senderUpn: trim(parsed.data.mailEntraSenderUpn),
        },
      },
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      webTls: current.webTls,
    });
        res.redirect("/admin/settings?tab=notifications&flash=Mail+settings+saved");
  }));

  router.post("/settings/notifications", asyncHandler(async (req, res) => {
    const parsed = notificationsSchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=notifications&flash=Invalid+notification+settings");
      return;
    }
    const current = await settingsService.getSettings();
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: current.entra,
      audit: current.audit,
      mail: current.mail,
      notifications: {
        memberAddedEnabled: req.body.notifyMemberAddedEnabled === "on",
        memberAddedSubject: parsed.data.notifyMemberAddedSubject || "",
        memberAddedBody: parsed.data.notifyMemberAddedBody || "",
        memberRemovedEnabled: req.body.notifyMemberRemovedEnabled === "on",
        memberRemovedSubject: parsed.data.notifyMemberRemovedSubject || "",
        memberRemovedBody: parsed.data.notifyMemberRemovedBody || "",
      },
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      webTls: current.webTls,
    });
        res.redirect("/admin/settings?tab=notifications&flash=Notification+settings+saved");
  }));

  router.post("/settings/audit", asyncHandler(async (req, res) => {
    const parsed = auditSchema.safeParse(req.body);
    if (!parsed.success) {
      res.redirect("/admin/settings?tab=audit&flash=Invalid+audit+settings");
      return;
    }
    const auditPath = trim(parsed.data.auditFilePath);
    const auditPathError = validateAuditPath(auditPath);
    if (auditPathError) {
      res.redirect(
        `/admin/settings?tab=audit&flashKind=error&flash=${encodeURIComponent(auditPathError)}`
      );
      return;
    }
    const current = await settingsService.getSettings();
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: current.entra,
      audit: {
        enabled: req.body.auditEnabled === "on",
        filePath: auditPath,
        retentionDays: parsed.data.auditRetentionDays || 90,
        syslogEnabled: req.body.auditSyslogEnabled === "on",
        syslogHost: trim(parsed.data.auditSyslogHost),
        syslogPort: parsed.data.auditSyslogPort || 514,
        syslogProtocol: parsed.data.auditSyslogProtocol || "udp4",
        syslogAppName: trim(parsed.data.auditSyslogAppName),
      },
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
      webTls: current.webTls,
    });
        res.redirect("/admin/settings?tab=audit&flash=Audit+settings+saved");
  }));

  router.post("/settings/test-ad", asyncHandler(async (req, res) => {
    const ldapUrl = trim(req.body.adLdapUrl);
    const baseDn = trim(req.body.adBaseDn);
    if (!ldapUrl || !baseDn) {
      res.json({ ok: false, message: "LDAP URL and Base DN are required." });
      return;
    }

    const sessionCreds = getDirectoryCredentials(req.session);
    const overrideUser = trim(req.body.adTestUsername);
    const overridePass = String(req.body.adTestPassword ?? "");
    const credentials = overrideUser
      ? { username: overrideUser, password: overridePass }
      : sessionCreds;

    const caPem = String(req.body.adTlsCaPem ?? "");
    const allowUntrusted = String(req.body.adTlsAllowUntrusted ?? "") === "on";
    const serverName = trim(req.body.adTlsServerName);

    const steps: Array<{ step: string; ok: boolean; detail: string }> = [];
    const record = (step: string, ok: boolean, detail: string) =>
      steps.push({ step, ok, detail });

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(ldapUrl);
    } catch {
      res.json({ ok: false, message: `Invalid LDAP URL: ${ldapUrl}`, steps: [] });
      return;
    }
    const isTls = parsedUrl.protocol === "ldaps:";
    const host = parsedUrl.hostname;
    const port = Number(parsedUrl.port) || (isTls ? 636 : 389);

    let resolvedAddresses: string[] = [];
    // 1) DNS
    try {
      const dns = await import("node:dns/promises");
      const ipv4Only = req.body.adIpv4Only === "on";
      const addrs = await dns.lookup(host, { all: true, family: ipv4Only ? 4 : 0 });
      const filtered = ipv4Only ? addrs.filter((a) => a.family === 4) : addrs;
      resolvedAddresses = filtered.map((a) => a.address);
      record("dns", true, `${host} → ${resolvedAddresses.join(", ")}${ipv4Only ? " (ipv4-only)" : ""}`);
    } catch (e) {
      const { message } = describeError(e);
      record("dns", false, message);
      logger.warn("LDAP test step failed", { phase: "dns", host, error: message });
      res.json({ ok: false, message: `DNS lookup failed: ${message}`, steps });
      return;
    }

    // 2) Raw TCP connect — try every resolved address so multi-A records aren't a footgun
    let workingAddress: string | null = null;
    const tcpResults: string[] = [];
    const candidates = resolvedAddresses.length > 0 ? resolvedAddresses : [host];
    for (const addr of candidates) {
      try {
        const net = await import("node:net");
        await new Promise<void>((resolve, reject) => {
          const sock = net.connect({ host: addr, port, timeout: 4000 });
          sock.once("connect", () => {
            sock.end();
            resolve();
          });
          sock.once("timeout", () => {
            sock.destroy();
            reject(new Error("timeout"));
          });
          sock.once("error", (err) => reject(err));
        });
        tcpResults.push(`${addr}:${port} OK`);
        if (!workingAddress) workingAddress = addr;
      } catch (e) {
        const { message } = describeError(e);
        tcpResults.push(`${addr}:${port} ${message}`);
      }
    }
    if (workingAddress) {
      record("tcp", true, tcpResults.join("; "));
    } else {
      record("tcp", false, tcpResults.join("; "));
      logger.warn("LDAP test step failed", { phase: "tcp", host, port, results: tcpResults });
      res.json({
        ok: false,
        message: `TCP connect failed for all ${candidates.length} address(es). Either pick a single-DC FQDN, or add a hosts entry / DNS view that excludes unreachable DC IPs.`,
        steps,
      });
      return;
    }

    // 3) TLS handshake (LDAPS only) — capture cert info even if validation would fail
    if (isTls) {
      try {
        const tls = await import("node:tls");
        const peer = await new Promise<import("node:tls").PeerCertificate>((resolve, reject) => {
          const sock = tls.connect({
            host: workingAddress || host,
            port,
            servername: serverName || host,
            ca: caPem && caPem.trim() ? caPem : undefined,
            rejectUnauthorized: !allowUntrusted,
            timeout: 8000,
          });
          sock.once("secureConnect", () => {
            const cert = sock.getPeerCertificate(true);
            sock.end();
            resolve(cert);
          });
          sock.once("timeout", () => {
            sock.destroy();
            reject(new Error("TLS handshake timeout"));
          });
          sock.once("error", (err) => reject(err));
        });
        const subject = peer && peer.subject ? (peer.subject as { CN?: string }).CN || "" : "";
        const altNames = peer && peer.subjectaltname ? String(peer.subjectaltname) : "(none)";
        record("tls", true, `subject CN=${subject || "(empty)"}; SAN=${altNames}`);
      } catch (e) {
        const { message, details } = describeError(e);
        record("tls", false, message);
        logger.warn("LDAP test step failed", { phase: "tls", host, port, ...details });
        res.json({ ok: false, message: `TLS handshake failed: ${message}`, steps });
        return;
      }
    }

    // 4) LDAP bind + search
    const tlsOptions = buildLdapTlsOptions({
      caPem,
      rejectUnauthorized: !allowUntrusted,
      serverName,
    });
    const client = new LdapClient({
      url: ldapUrl,
      timeout: 15000,
      connectTimeout: 15000,
      ...(tlsOptions ? { tlsOptions } : {}),
    });
    let phase = "bind";
    try {
      if (credentials?.username && credentials.password) {
        await client.bind(credentials.username, credentials.password);
        record("bind", true, `Bound as ${credentials.username}`);
      } else {
        record("bind", true, "Skipped (anonymous)");
      }
      phase = "search";
      const result = await client.search(baseDn, {
        scope: "base",
        filter: "(objectClass=*)",
        attributes: ["distinguishedName"],
        sizeLimit: 1,
      });
      record("search", true, `Base DN reachable (${result.searchEntries.length} entry)`);
      logger.info("LDAP test succeeded", { ldapUrl, baseDn, bound: !!credentials?.username, steps });
      res.json({ ok: true, message: "LDAP test passed.", steps });
    } catch (error) {
      const { message, details } = describeError(error);
      record(phase, false, message);
      logger.warn("LDAP test failed", { ldapUrl, baseDn, phase, ...details, steps });
      res.json({ ok: false, message: `LDAP test failed at ${phase}: ${message}`, steps });
    } finally {
      try {
        await client.unbind();
      } catch {
        /* ignore */
            }
    }
  }));

  router.post("/settings/fetch-ad-ca", asyncHandler(async (req, res) => {
    const ldapUrl = trim(req.body.adLdapUrl);
    if (!ldapUrl) {
      res.json({ ok: false, message: "LDAP URL is required." });
      return;
    }
    let parsed: URL;
    try {
      parsed = new URL(ldapUrl);
    } catch {
      res.json({ ok: false, message: "LDAP URL is not a valid URL." });
      return;
    }
    if (parsed.protocol !== "ldaps:") {
      res.json({
        ok: false,
        message: "Server CA can only be fetched from an ldaps:// URL.",
      });
      return;
    }
    const host = parsed.hostname;
    const port = Number(parsed.port) || 636;
    const serverName = trim(req.body.adTlsServerName) || host;
    const ipv4Only = req.body.adIpv4Only === "on";

    try {
      const reachable = await pickReachableHost(host, port, ipv4Only);
      if (!reachable) {
        res.json({
          ok: false,
          message: `No reachable IP for ${host}:${port}. Verify firewall / DNS.`,
        });
        return;
      }
      const tls = await import("node:tls");
      const chain = await new Promise<import("node:tls").DetailedPeerCertificate>(
        (resolve, reject) => {
          const sock = tls.connect({
            host: reachable,
            port,
            servername: serverName,
            rejectUnauthorized: false,
            timeout: 8000,
          });
          sock.once("secureConnect", () => {
            const cert = sock.getPeerCertificate(true);
            sock.end();
            resolve(cert as import("node:tls").DetailedPeerCertificate);
          });
          sock.once("timeout", () => {
            sock.destroy();
            reject(new Error("TLS handshake timeout"));
          });
          sock.once("error", (err) => reject(err));
        }
      );

      // Walk the issuer chain. Self-signed root has issuerCertificate === itself.
      const collected: Array<{
        subject: string;
        issuer: string;
        fingerprint: string;
        pem: string;
      }> = [];
      const seen = new Set<string>();
      let current: import("node:tls").DetailedPeerCertificate | undefined = chain;
      while (current && current.raw && !seen.has(current.fingerprint256)) {
        seen.add(current.fingerprint256);
        const pem =
          "-----BEGIN CERTIFICATE-----\n" +
          current.raw.toString("base64").match(/.{1,64}/g)!.join("\n") +
          "\n-----END CERTIFICATE-----";
        collected.push({
          subject: (current.subject as { CN?: string })?.CN || JSON.stringify(current.subject),
          issuer: (current.issuer as { CN?: string })?.CN || JSON.stringify(current.issuer),
          fingerprint: current.fingerprint256,
          pem,
        });
        const next: import("node:tls").DetailedPeerCertificate | undefined = current.issuerCertificate;
        if (!next || next === current) break;
        current = next;
      }

      if (collected.length === 0) {
        res.json({ ok: false, message: "Server did not present any certificate." });
        return;
      }

      // Bundle full chain so any of them can validate; the root is last.
      const pemBundle = collected.map((c) => c.pem).join("\n");
      const summary = collected
        .map((c, i) => `${i === collected.length - 1 ? "[root]" : "[chain]"} CN=${c.subject} (issuer=${c.issuer})`)
        .join("\n");
      logger.info("Fetched LDAPS CA chain", { host, port, count: collected.length });
      res.json({
        ok: true,
        message: `Fetched ${collected.length} certificate(s) from ${host}:${port}.`,
        pem: pemBundle,
        summary,
        certs: collected.map((c) => ({
          subject: c.subject,
          issuer: c.issuer,
          fingerprint: c.fingerprint,
        })),
      });
    } catch (e) {
      const { message, details } = describeError(e);
      logger.warn("Fetch LDAPS CA failed", { host, port, ...details });
            res.json({ ok: false, message: `Could not fetch certificate: ${message}` });
    }
  }));

  router.post("/settings/test-entra", asyncHandler(async (req, res) => {
    const tenantId = trim(req.body.entraTenantId);
    const clientId = trim(req.body.entraClientId);
    const clientSecret = trim(req.body.entraClientSecret);
    if (!tenantId) {
      res.json({ ok: false, message: "Tenant ID is required." });
      return;
    }
    let phase = "metadata";
    try {
      const wellKnown = await fetch(
        `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/v2.0/.well-known/openid-configuration`,
        { signal: AbortSignal.timeout(5000) }
      );
      if (!wellKnown.ok) {
        const body = await wellKnown.text();
        logger.warn("Entra metadata not reachable", { tenantId, status: wellKnown.status, body: body.slice(0, 500) });
        res.json({
          ok: false,
          message: `Tenant metadata not reachable (HTTP ${wellKnown.status}). ${body.slice(0, 200)}`,
        });
        return;
      }

      if (clientId && clientSecret) {
        phase = "client_credentials";
        const tokenResp = await fetch(
          `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              client_id: clientId,
              client_secret: clientSecret,
              scope: "https://graph.microsoft.com/.default",
            }),
            signal: AbortSignal.timeout(5000),
          }
        );
        if (!tokenResp.ok) {
          const text = await tokenResp.text();
          logger.warn("Entra client_credentials failed", {
            tenantId,
            clientId,
            status: tokenResp.status,
            body: text.slice(0, 500),
          });
          res.json({
            ok: false,
            message: `Tenant reachable, but client credentials check failed (HTTP ${tokenResp.status}). ${text.slice(0, 400)}`,
          });
          return;
        }
        logger.info("Entra test succeeded", { tenantId, clientId });
        res.json({ ok: true, message: "Tenant metadata reachable and client credentials accepted." });
        return;
      }
      res.json({
        ok: true,
        message: "Tenant metadata reachable. Provide client id/secret to also validate the app registration.",
      });
    } catch (error) {
      const { message, details } = describeError(error);
      logger.warn("Entra test failed", { tenantId, phase, ...details });
            res.json({ ok: false, message: `Entra test failed at ${phase}: ${message}` });
    }
  }));

  router.post("/settings/test-mail", asyncHandler(async (req, res) => {
    const mode = String(req.body.mailMode || "smtp") as "smtp" | "entra";
    const phase = mode === "smtp" ? "smtp_verify" : "graph_token";
    try {
      if (mode === "smtp") {
        const host = trim(req.body.mailSmtpHost);
        const port = Number(req.body.mailSmtpPort || 587);
        const secureRaw = String(req.body.mailSmtpSecure || "");
        const secure = secureRaw === "on" || secureRaw === "true";
        const requireAuthRaw = String(req.body.mailSmtpRequireAuth || "");
        const requireAuth = requireAuthRaw === "on" || requireAuthRaw === "true";
        const ignoreTlsRaw = String(req.body.mailSmtpIgnoreTls || "");
        const ignoreTls = ignoreTlsRaw === "on" || ignoreTlsRaw === "true";
        const allowUntrustedRaw = String(req.body.mailSmtpAllowUntrustedTls || "");
        const allowUntrustedTls = allowUntrustedRaw === "on" || allowUntrustedRaw === "true";
        const username = trim(req.body.mailSmtpUsername);
        const password = trim(req.body.mailSmtpPassword);
        if (!host) {
          res.json({ ok: false, message: "SMTP host is required." });
          return;
        }
        const useAuth = requireAuth && !!username;
        const transport = nodemailer.createTransport({
          host,
          port,
          secure,
          ignoreTLS: ignoreTls,
          auth: useAuth ? { user: username, pass: password } : undefined,
          tls: allowUntrustedTls ? { rejectUnauthorized: false } : undefined,
          connectionTimeout: 8000,
          greetingTimeout: 8000,
          socketTimeout: 8000,
        });
        await transport.verify();
        logger.info("SMTP test succeeded", { host, port, secure, ignoreTls, allowUntrustedTls, authenticated: useAuth });
        res.json({ ok: true, message: `SMTP connection to ${host}:${port} verified${useAuth ? " (authenticated)" : " (unauthenticated)"}.` });
        return;
      }

      const tenantId = trim(req.body.mailEntraTenantId);
      const clientId = trim(req.body.mailEntraClientId);
      const clientSecret = trim(req.body.mailEntraClientSecret);
      if (!tenantId || !clientId || !clientSecret) {
        res.json({ ok: false, message: "Tenant ID, Client ID, and Client Secret are required." });
        return;
      }
      const tokenResp = await fetch(
        `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            client_id: clientId,
            client_secret: clientSecret,
            scope: "https://graph.microsoft.com/.default",
          }),
          signal: AbortSignal.timeout(5000),
        }
      );
      if (!tokenResp.ok) {
        const text = await tokenResp.text();
        logger.warn("Mail Graph token request failed", {
          tenantId,
          clientId,
          status: tokenResp.status,
          body: text.slice(0, 500),
        });
        res.json({
          ok: false,
          message: `Graph token request failed (HTTP ${tokenResp.status}). ${text.slice(0, 400)}`,
        });
        return;
      }
      logger.info("Mail Entra test succeeded", { tenantId, clientId });
      res.json({
        ok: true,
        message: "Graph client credentials accepted. Mail.Send permission is not verified by this test.",
      });
    } catch (error) {
      const { message, details } = describeError(error);
      logger.warn("Mail test failed", { mode, phase, ...details });
            res.json({ ok: false, message: `Mail test failed at ${phase}: ${message}` });
    }
  }));

  router.post("/settings/send-test-mail", asyncHandler(async (req, res) => {
    const to = trim(req.body.testMailTo);
    if (!to) {
      res.redirect("/admin/settings?tab=notifications&flash=Provide+a+recipient+to+test");
      return;
    }
    try {
      await mailService.sendTestMessage(to);
      res.redirect("/admin/settings?tab=notifications&flash=Test+email+sent");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
            res.redirect(`/admin/settings?tab=notifications&flash=${encodeURIComponent(`Test email failed: ${message}`)}`);
    }
  }));

  router.get(["/wizards/entra-mail", "/wizards/entra-mail/:step"], asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    const step = Number((req.params as Record<string, string | undefined>).step || 1);
        res.render("wizard-entra-mail", {
      title: "Entra Mail Setup Wizard",
      csrfToken: req.csrfToken!(),
      user: req.user,
      step,
      settings,
      flash: sanitizeFlash(req.query.flash),
    });
  }));

  router.post("/wizards/entra-mail/save", asyncHandler(async (req, res) => {
    const current = await settingsService.getSettings();
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: current.entra,
      audit: current.audit,
      mail: {
        ...current.mail,
        enabled: true,
        mode: "entra",
        fromAddress: trim(req.body.mailFromAddress) || current.mail.fromAddress,
        entra: {
          tenantId: trim(req.body.mailEntraTenantId),
          clientId: trim(req.body.mailEntraClientId),
          clientSecret: trim(req.body.mailEntraClientSecret),
          senderUpn: trim(req.body.mailEntraSenderUpn),
        },
      },
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
    });
        res.redirect("/admin/settings?tab=notifications&flash=Entra+mail+wizard+completed");
  }));

  router.get(["/wizards/entra-directory", "/wizards/entra-directory/:step"], asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    const step = Number((req.params as Record<string, string | undefined>).step || 1);
        res.render("wizard-entra-directory", {
      title: "Entra Directory Setup Wizard",
      csrfToken: req.csrfToken!(),
      user: req.user,
      step,
      settings,
      flash: sanitizeFlash(req.query.flash),
    });
  }));

  router.post("/wizards/entra-directory/save", asyncHandler(async (req, res) => {
    const current = await settingsService.getSettings();
    await settingsService.updateSettings({
      breakGlassUsername: current.breakGlass.username,
      ad: current.ad,
      entra: {
        ...current.entra,
        enabled: true,
        tenantId: trim(req.body.entraTenantId),
        clientId: trim(req.body.entraClientId),
        clientSecret: trim(req.body.entraClientSecret),
        scope: trim(req.body.entraScope) || current.entra.scope,
        redirectUri: trim(req.body.entraRedirectUri) || current.entra.redirectUri,
      },
      audit: current.audit,
      mail: current.mail,
      notifications: current.notifications,
      delegatedAdGroupDns: current.delegatedAdmin.adGroupDns,
      delegatedEntraGroupIds: current.delegatedAdmin.entraGroupIds,
    });
        res.redirect("/admin/settings?tab=directory&flash=Entra+directory+wizard+completed");
  }));

  // ---- Audit log viewer + CSV export ------------------------------------
  // GET /admin/audit  → renders the filter form + results table.
  // GET /admin/audit.csv  → streams the same filter as a CSV download.
  // Filters: date range (defaults to last 7 days), actor substring, exact
  // action, source (ad/entra), group DN substring, status. Capped at 1000
  // rows in the UI and 10000 rows in CSV; an operator with longer audit
  // windows should use the NDJSON files directly.
  function parseAuditQuery(q: Record<string, string | string[] | undefined>): {
    fromIso: string;
    toIso: string;
    limit: number;
    actorContains?: string;
    actionEquals?: string;
    sourceEquals?: "ad" | "entra";
    groupContains?: string;
    statusEquals?: "success" | "failure";
  } {
    function asString(v: unknown): string | undefined {
      if (Array.isArray(v)) v = v[0];
      const s = typeof v === "string" ? v.trim() : "";
      return s ? s : undefined;
    }
    const now = Date.now();
    const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
    const fromInput = asString(q.from);
    const toInput = asString(q.to);
    const fromIso = fromInput && !Number.isNaN(Date.parse(fromInput))
      ? new Date(fromInput).toISOString()
      : new Date(sevenDaysAgo).toISOString();
    const toIso = toInput && !Number.isNaN(Date.parse(toInput))
      ? new Date(toInput).toISOString()
      : new Date(now).toISOString();
    const limit = Math.min(10_000, Math.max(1, Number(asString(q.limit)) || 500));
    const action = asString(q.action);
    const source = asString(q.source);
    const status = asString(q.status);
    return {
      fromIso,
      toIso,
      limit,
      actorContains: asString(q.actor),
      actionEquals: action,
      sourceEquals: source === "ad" || source === "entra" ? source : undefined,
      groupContains: asString(q.group),
      statusEquals: status === "success" || status === "failure" ? status : undefined,
    };
  }

  router.get("/audit", asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    if (!settings.audit?.enabled) {
      res.status(404).render("error", {
        title: "Audit log unavailable",
        message:
          "Hosted auditing is not enabled. Turn on \"Enable hosted auditing\" in Admin Settings → Audit to record and view events.",
      });
      return;
    }
    const params = parseAuditQuery(req.query as Record<string, string | string[] | undefined>);
    let records: import("../../domain/models").AuditRecord[] = [];
    let error: string | undefined;
    try {
      records = await auditReader.read({ ...params, limit: Math.min(params.limit, 1000) });
    } catch (err) {
      error = err instanceof Error ? err.message : "Failed to read audit log";
      logger.warn("audit-viewer read failed", { err: error });
    }
    res.render("admin-audit", {
      title: "Audit Log",
      csrfToken: req.csrfToken!(),
      user: req.user,
      params,
      records,
      error,
      // Re-serialise as a query string for the CSV link so the user keeps
      // their filters.
      csvHref:
        "/admin/audit.csv?" +
        new URLSearchParams({
          from: params.fromIso,
          to: params.toIso,
          limit: String(params.limit),
          actor: params.actorContains ?? "",
          action: params.actionEquals ?? "",
          source: params.sourceEquals ?? "",
          status: params.statusEquals ?? "",
          group: params.groupContains ?? "",
                }).toString(),
    });
  }));

  router.get("/audit.csv", asyncHandler(async (req, res) => {
    const settings = await settingsService.getSettings();
    if (!settings.audit?.enabled) {
      res.status(404).type("text/plain").send("Hosted auditing is not enabled.");
      return;
    }
    const params = parseAuditQuery(req.query as Record<string, string | string[] | undefined>);
    let records: import("../../domain/models").AuditRecord[] = [];
    try {
      records = await auditReader.read(params);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to read audit log";
      res.status(500).type("text/plain").send(message);
      return;
    }
    // Build CSV inline to avoid pulling csv-stringify into the request path;
    // values are escaped per RFC 4180 (wrap in quotes, double internal
    // quotes). All record fields are short alphanumeric or DN strings; no
    // streaming required for our 10k row cap.
    const header = [
      "id",
      "timestampUtc",
      "actorUpn",
      "actorSamAccountName",
      "correlationId",
      "action",
      "source",
      "status",
      "targetGroupDn",
      "targetMemberDn",
      "details",
    ];
    function esc(value: unknown): string {
      const s = value === null || value === undefined ? "" : String(value);
      if (s.indexOf(",") === -1 && s.indexOf("\"") === -1 && s.indexOf("\n") === -1 && s.indexOf("\r") === -1) {
        return s;
      }
      return `"${s.replace(/"/g, '""')}"`;
    }
    const lines: string[] = [header.join(",")];
    for (const r of records) {
      lines.push([
        esc(r.id),
        esc(r.timestampUtc),
        esc(r.actorUpn),
        esc(r.actorSamAccountName),
        esc(r.correlationId),
        esc(r.action),
        esc(r.source),
        esc(r.status),
        esc(r.targetGroupDn),
        esc(r.targetMemberDn),
        esc(r.details),
      ].join(","));
    }
    res.header("Content-Type", "text/csv");
    res.attachment(`audit-${new Date().toISOString().slice(0, 10)}.csv`);
        res.send(lines.join("\n"));
  }));

  return router;
}
