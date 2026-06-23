import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import express, { NextFunction, Request, Response } from "express";
import session from "express-session";
import sessionFileStore from "session-file-store";
import helmet from "helmet";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import rateLimit from "express-rate-limit";
import { doubleCsrf } from "csrf-csrf";

import { config } from "./config/env";
import { resolveTrustProxy } from "./config/env";
import { GroupManagementService } from "./application/group-management-service";
import { MailService } from "./application/mail-service";
import { PortalAdminAuthorizationService } from "./application/portal-admin-authorization-service";
import { PortalSettingsService } from "./application/portal-settings-service";
import { startCleanupInterval, stopCleanupInterval } from "./application/login-lockout";
import { ConfigurableAdRepository } from "./infrastructure/ad/configurable-ad-repository";
import { CachedAdRepository } from "./infrastructure/ad/cached-ad-repository";
import { ConfigurableHostedAuditRepository } from "./infrastructure/audit/configurable-hosted-audit-repository";
import { ConfigurableEntraDirectoryRepository } from "./infrastructure/entra/configurable-entra-directory-repository";
import { logger } from "./infrastructure/logger";
import { FilePortalSettingsRepository } from "./infrastructure/settings/file-portal-settings-repository";
import { LoginHistoryStore } from "./infrastructure/login-history";
import { acquireSingleInstanceLock, releaseSingleInstanceLock } from "./infrastructure/single-instance-lock";
import { isHttpError } from "./domain/http-error";
import { createAdminRoutes } from "./web/routes/admin-routes";
import { createAuthRoutes } from "./web/routes/auth-routes";
import { createGroupRoutes } from "./web/routes/groups-routes";
import { asyncHandler } from "./web/async-handler";
import { attachUserFromSession } from "./web/auth-middleware";

const app = express();

// Static-asset version stamp appended to <link>/<script> URLs as ?v=...
// Browsers and shared proxies treat each value as a fresh URL, so a deploy
// that changes the CSS/JS never serves the stale version to anyone who
// happened to visit the previous build. The stamp combines process start
// time (millisecond precision) with a short random suffix so multi-replica
// deployments don't accidentally share a value.
const ASSET_VERSION = `${Date.now().toString(36)}-${crypto.randomBytes(3).toString("hex")}`;

// Honor the configured TRUST_PROXY setting before any middleware that depends
// on req.ip / req.secure (rate limiter, session cookie defaults, helmet HSTS).
app.set("trust proxy", resolveTrustProxy(process.env.TRUST_PROXY || "false"));

// Public liveness probe fast path. Keep this ahead of cookie/session/CSRF
// and settings-loading middleware so orchestrator probes are effectively free.
app.get("/healthz", (_req, res) => {
  res.status(204).end();
});

app.set("view engine", "ejs");
// Anchor to __dirname (always the compiled dist/ directory) rather than
// process.cwd() so the app works regardless of what directory the container
// or the operator launches Node from.
app.set("views", path.join(__dirname, "..", "views"));

// Helmet ships a CSP that includes `upgrade-insecure-requests` by default,
// and HSTS with a one-year max-age. Both are appropriate for production over
// HTTPS, but break dev: a cached HSTS entry on localhost causes the browser
// to silently rewrite form actions and links to https://, the upgraded URL
// no longer matches `'self'` (the document loaded over http://), and the
// browser blocks the submit with a misleading CSP message. We strip both
// directives when the process is not serving HTTPS natively in production;
// everything else in Helmet's defaults is kept (form-action 'self',
// script-src 'self', X-Frame-Options, etc.).
//
// `form-action` is enforced across the entire redirect chain, not just the
// immediate POST target. The login form submits to /auth/login which can
// redirect to /auth/entra/start which then redirects to Microsoft's OAuth
// endpoints. Allow those endpoints explicitly so the chain validates.
//
// Script policy (XSS hardening):
//   - `script-src 'self'` and `script-src-attr 'none'` are pinned
//     explicitly. The codebase contains zero inline `<script>` blocks and
//     zero inline event handlers — the audit step is part of the lint /
//     review checklist. New inline scripts must NOT be added; convert to
//     data-attributes consumed by the existing /public/*.js bundles
//     (`data-confirm`, `data-member-count`, etc.) or, if absolutely
//     required, introduce a per-request nonce in this directive.
// Style policy: `style-src` keeps Helmet's `'unsafe-inline'` default
// because the per-request `<html style="--accent: ...; --accent-2: ...">`
// theme variables and the admin theme-preset color swatches rely on
// inline `style=`. Those values come from validated hex inputs, not user
// content. Inline style is not a script-execution vector.
const isProduction = process.env.NODE_ENV === "production";
const cspDirectives: Record<string, null | string[]> = {
  "form-action": ["'self'", "https://login.microsoftonline.com", "https://login.live.com"],
  "script-src": ["'self'"],
  "script-src-attr": ["'none'"],
};
if (!isProduction) {
  cspDirectives["upgrade-insecure-requests"] = null;
}
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: cspDirectives,
    },
    strictTransportSecurity: isProduction,
  })
);

// Permissions-Policy: deny browser features the portal never uses. Keeps
// content-injected scripts (in the unlikely event of a CSP escape) from
// silently asking for camera/microphone/geolocation/etc.
// Referrer-Policy: strict-origin-when-cross-origin to prevent leaking internal
// URL paths to external services (e.g., Microsoft's sign-in page).
app.use((_req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) { next(); return; }
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    [
      "accelerometer=()",
      "autoplay=()",
      "camera=()",
      "display-capture=()",
      "encrypted-media=()",
      "fullscreen=(self)",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "microphone=()",
      "midi=()",
      "payment=()",
      "picture-in-picture=()",
      "publickey-credentials-get=()",
      "screen-wake-lock=()",
      "sync-xhr=()",
      "usb=()",
      "xr-spatial-tracking=()",
    ].join(", ")
  );
  next();
});

// Authenticated/admin pages contain organisation-specific content and
// short-lived form tokens; never let a browser or shared proxy cache them.
// Static assets under public/ are served by express.static below and use the
// default 'public, max-age=...' behaviour, so this rule only fires for the
// rendered HTML.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (
    !res.headersSent &&
    (req.path.startsWith("/auth/") ||
    req.path.startsWith("/admin/") ||
    req.path === "/groups" ||
    req.path.startsWith("/groups/"))
  ) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
  }
  next();
});

// Structured JSON access log. Replaces morgan's "combined" plain-text format
// so a SIEM (Splunk / Elastic / Loki) can ingest without per-line parsing.
// Logs once per request at response-finish; never blocks the response.
function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const startedAt = Date.now();
  res.on("finish", () => {
    const durationMs = Date.now() - startedAt;
    const actor = req.session?.user?.samAccountName;
    logger.info("http", {
      method: req.method,
      path: req.originalUrl || req.url,
      status: res.statusCode,
      durationMs,
      contentLength: Number(res.getHeader("content-length")) || undefined,
      correlationId: (req as Request & { correlationId?: string }).correlationId,
      ip: req.ip,
      actor,
      ua: req.headers["user-agent"],
    });
  });
  next();
}
app.use(requestLogger);
// Body limits sized to accommodate the branding logo upload (capped at 2 MB of
// base64-encoded data URL). The CSRF token, settings fields, and any small
// supporting fields easily fit alongside, so 4 MB gives comfortable headroom.
app.use(express.urlencoded({ extended: false, limit: "4mb" }));
app.use(express.json({ limit: "4mb" }));
app.use(cookieParser());
// Persistent session store. The portal is **intentionally single-instance**
// (one Node process per data directory; see README + docker-compose), so we
// don't need a network-shared store. We do need persistence across process
// restarts and rolling deploys — `MemoryStore` evaporates every session on
// reload, which would sign out every active user on every restart and would
// also defeat the "Sign out other sessions" feature for any session that
// outlived the process. `session-file-store` writes one JSON-per-sid into
// `data/sessions/`, fsynced and atomic-renamed by the library, with TTL
// matching the session cookie. The store reference is kept so we can call
// `store.destroy(sid)` when the user clicks "Sign out other sessions".
const FileStore = sessionFileStore(session);
const sessionsDir = path.join(path.dirname(config.SETTINGS_FILE_PATH), "sessions");
const sessionStore = new FileStore({
  path: sessionsDir,
  ttl: config.SESSION_TTL_SECONDS,
  // Sweep expired session files once per hour. 15 minutes is aggressive on
  // network-attached storage (EFS/NFS) where a directory readdir+unlink sweep
  // consumes burst I/O credits and adds measurable latency to concurrent
  // requests. Session expiry is enforced on read by the TTL check regardless
  // of whether the file has been reaped, so a longer interval is safe.
  reapInterval: 60 * 60,
  // Keep the on-disk format opaque; logs go to our winston logger.
  logFn: (msg: string) => logger.warn("session-file-store", { message: msg }),
  fileExtension: ".json",
});

// On Windows, session-file-store always uses write-file-atomic which writes to
// a temp file and then calls fs.rename() over the existing session file. Win32
// rejects that rename with EPERM when another concurrent request still holds
// the target file open. Override the store's set() to write directly with
// fs.writeFile instead — safe here because express-session serialises saves
// per session-id and we run single-instance.
if (process.platform === "win32") {
  const _set = (sessionStore as session.Store & { set: Function }).set.bind(sessionStore);
  (sessionStore as session.Store & { set: Function }).set = function (
    sid: string,
    sessionData: session.SessionData,
    callback?: (err?: unknown) => void
  ) {
    const sessionPath = require("path").join(sessionsDir, sid + ".json");
    const json = JSON.stringify({ ...sessionData, __lastAccess: Date.now() });
    fs.writeFile(sessionPath, json, "utf8", (err) => {
      if (err) {
        // Fall back to the original atomic implementation so a one-off
        // write error doesn't silently swallow the session.
        logger.warn("session direct-write failed, retrying with atomic", { err });
        _set(sid, sessionData, callback);
      } else {
        callback?.();
      }
    });
  };
}

app.use(
  session({
    secret: config.SESSION_SECRET,
    saveUninitialized: false,
    resave: false,
    store: sessionStore as unknown as session.Store,
        cookie: {
      httpOnly: true,
      sameSite: "lax",
      // "auto" lets express-session inspect each request's `req.secure`
      // (which honours the `trust proxy` setting) and set the Secure flag
      // only when the connection is actually HTTPS end-to-end. This avoids
      // the common reverse-proxy pitfall where a static `secure: true`
      // prevents the session cookie from being sent when the proxy
      // terminates TLS but forwards plain HTTP to Node.
      secure: "auto" as boolean | "auto",
      maxAge: config.SESSION_TTL_SECONDS * 1000,
    },
  })
);

// CSRF protection using the double-submit cookie pattern (csrf-csrf). The
// signed CSRF cookie is set automatically when `req.csrfToken!()` is called,
// and the matching token is embedded in forms via the `csrfToken` local.
// AJAX clients can submit the token in either the `_csrf` body field or the
// `x-csrf-token` header.
const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } = doubleCsrf({
  getSecret: () => config.SESSION_SECRET,
  getSessionIdentifier: (req) => (req as Request).session?.id ?? "",
    // Use a consistent cookie name in all environments. The previous
  // approach switched between "__Host-psifi.x-csrf-token" (production)
  // and "x-csrf-token" (dev). The __Host- prefix requires Secure + no
  // Domain, but when an admin toggles native TLS on/off, the browser
  // retains the old-name cookie and every POST silently fails with a
  // CSRF rejection. A fixed name eliminates the class of mismatch
  // entirely. httpOnly + SameSite=lax + Secure (when over HTTPS) still
  // provides strong cookie protection.
  cookieName: "_csrf-token",
  cookieOptions: {
    httpOnly: true,
    sameSite: "lax" as const,
    // Match the session cookie: mark Secure only when the request
    // actually arrived over HTTPS (respects trust proxy). `csrf-csrf`
    // does not support "auto", so we compute it per-request via a
    // getter. Fall back to the static production flag for the initial
    // registration; the per-request cookie-set call in csrf-csrf
    // re-evaluates `res.cookie()` which honours `req.secure`.
    secure: config.NODE_ENV === "production",
    path: "/",
  },
  getCsrfTokenFromRequest: (req) => {
    const body = (req as Request).body as Record<string, unknown> | undefined;
    const fromBody = body && typeof body._csrf === "string" ? (body._csrf as string) : undefined;
    const header = req.headers["x-csrf-token"];
    const fromHeader = Array.isArray(header) ? header[0] : header;
    return fromBody ?? fromHeader ?? "";
  },
});

// Bridge `req.csrfToken!()` so existing routes/views keep working unchanged.
// Also pin the session on first issue so the CSRF token (which is bound to
// the session identifier) survives the next request when `saveUninitialized`
// is false.
app.use((req: Request, res: Response, next: NextFunction) => {
  (req as unknown as { csrfToken: () => string }).csrfToken = () => {
    if (req.session && !(req.session as unknown as { csrfInit?: boolean }).csrfInit) {
      (req.session as unknown as { csrfInit?: boolean }).csrfInit = true;
    }
    return generateCsrfToken(req, res);
  };
  next();
});
app.use(doubleCsrfProtection);
app.use(express.static(path.join(__dirname, "..", "public"), {
  // Assets are served with a cache-busting version stamp appended as
  // ?v=<ASSET_VERSION> (set at startup and used in every <link>/<script>
  // tag). Each new deploy produces a unique stamp, so browsers and CDN
  // edges treat the URL as a brand-new resource. 'immutable' tells the
  // browser it never needs to revalidate this URL — the stamp changes
  // instead. Combined, this gives zero-latency repeat loads without any
  // risk of serving stale CSS/JS after a deploy.
  maxAge: "1y",
  immutable: true,
}));

app.use((req: Request, _res: Response, next: NextFunction) => {
  req.correlationId = req.header("x-correlation-id") ?? crypto.randomUUID();
  next();
});

const settingsRepository = new FilePortalSettingsRepository(config.SETTINGS_FILE_PATH);
const settingsService = new PortalSettingsService(settingsRepository);
const adRepository = new CachedAdRepository(new ConfigurableAdRepository(settingsRepository), 60_000);
const entraRepository = new ConfigurableEntraDirectoryRepository(settingsRepository);
const adminAuthorizationService = new PortalAdminAuthorizationService(settingsService, adRepository, entraRepository);
const auditRepository = new ConfigurableHostedAuditRepository(settingsRepository);
const mailService = new MailService(settingsRepository);
// Per-user login history (previous-login display + active sessions list +
// sign-out-other-sessions). Persisted JSON at data/login-history.json for the
// last-login fact; active sessions are tracked in process memory.
const loginHistory = new LoginHistoryStore(
  path.join(path.dirname(config.SETTINGS_FILE_PATH), "login-history.json")
);
const service = new GroupManagementService(
  adRepository,
  entraRepository,
  auditRepository,
  settingsService,
  mailService,
  config.MAX_BATCH_SIZE,
  config.MAX_GROUPS_PER_LIST,
  config.MAX_MEMBERS_PER_GROUP
);

app.use(attachUserFromSession);
app.use(asyncHandler(async (req, res, next) => {
  res.locals.user = req.user;
  res.locals.isPortalAdmin = req.session.isPortalAdmin === true;
  res.locals.assetVersion = ASSET_VERSION;
  try {
    res.locals.csrfToken = req.csrfToken!();
  } catch {
    res.locals.csrfToken = "";
  }
  try {
    const settings = await settingsService.getSettings();
    // Stash the full settings object for reuse by route handlers within this
    // request (e.g. groups page) so they don't need a second repository read.
    res.locals.settings = settings;
    res.locals.branding = settings.branding;
    res.locals.auditEnabled = settings.audit?.enabled === true;
  } catch {
    res.locals.branding = { siteName: "Group Self Service", headerTitle: "Group Self Service", themeMode: "auto", themePrimary: "#0d9488", themeSecondary: "#7c3aed", notificationSuccessColor: "#198754", notificationFailColor: "#dc3545" };
    res.locals.auditEnabled = false;
  }
    next();
}));
app.get("/", (_req, res) => {
  res.redirect("/groups");
});

// Rate-limit authentication attempts to slow down credential-stuffing / brute force.
// Successful logins do not count toward the limit.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: "Too many login attempts. Please wait a few minutes and try again.",
});
app.use("/auth/login", loginLimiter);

// Lighter throttle for principal search to protect the directory from wildcard abuse.
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.use("/groups/search", searchLimiter);

// Member-count endpoint is convenient and cheap *for the user*, but each
// uncached miss is a directory query. An authenticated client could iterate
// it to enumerate group sizes for every owned group. Cap to a comfortable
// browser burst (60 / minute is more than the largest realistic groups
// list × initial render).
const memberCountLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.use(["/groups/members/count", "/groups/members/counts"], memberCountLimiter);

// Audit viewer reads NDJSON from disk and (for CSV) can return up to 10k
// rows. A misbehaving authenticated admin client could hammer the route to
// either DoS the disk or scrape history rapidly. Generous but bounded.
const auditViewerLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.use(["/admin/audit", "/admin/audit.csv"], auditViewerLimiter);

app.use("/auth", createAuthRoutes(adRepository, entraRepository, settingsService, adminAuthorizationService, loginHistory, sessionStore));
app.use("/groups", createGroupRoutes(service, settingsService, loginHistory, sessionStore));
app.use("/admin", createAdminRoutes(settingsService, adminAuthorizationService, mailService, adRepository, auditRepository));

app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  // If the response has already been (partially) sent — e.g. res.render()
  // started flushing the template and then threw — we cannot set new headers
  // or send a second body. Log the error and let Node close the socket.
  if (res.headersSent) {
    logger.error("Error after headers sent — connection will be reset", {
      correlationId: req.correlationId,
      path: req.originalUrl,
      err: err instanceof Error ? { message: err.message, stack: err.stack } : err,
    });
    return;
  }

  const code = (err as { code?: string; type?: string; status?: number } | null)?.code;
  const type = (err as { type?: string } | null)?.type;
  const status = (err as { status?: number; statusCode?: number } | null)?.status
    ?? (err as { statusCode?: number } | null)?.statusCode;

  // Body parser rejected an oversized payload. The most likely culprit is a
  // logo upload above the cap, so bounce admins back to the General tab with a
  // visible error flash instead of a generic 500.
  if (status === 413 || code === "LIMIT_FILE_SIZE" || type === "entity.too.large") {
    logger.warn("Request body rejected as too large", {
      correlationId: req.correlationId,
      path: req.originalUrl,
    });
    if (req.method === "POST" && req.originalUrl.startsWith("/admin/settings")) {
      res.redirect("/admin/settings?tab=general&flashKind=error&flash=Upload+too+large.+The+header+logo+must+be+under+2+MB.");
      return;
    }
    res.status(413).render("error", {
      title: "Upload too large",
      message: "The submitted form payload exceeds the 4 MB request limit.",
      correlationId: req.correlationId,
    });
    return;
  }

  // Stale CSRF token (e.g. server restarted, session cookie outlived store, multi-tab):
  // bounce the user back to the originating page with a friendly message instead of 500.
  const isCsrfError =
    code === "EBADCSRFTOKEN" ||
    err === invalidCsrfTokenError ||
    (err instanceof Error && err.message === invalidCsrfTokenError.message);
  if (isCsrfError) {
    logger.warn("CSRF token rejected", {
      correlationId: req.correlationId,
      path: req.originalUrl,
    });
    if (req.method === "POST" && req.originalUrl.startsWith("/auth/login")) {
      res.redirect("/auth/login?flash=Your+session+expired.+Please+sign+in+again.");
      return;
    }
    res.status(403).render("error", {
      title: "Session expired",
      message: "Your form expired. Please reload the page and try again.",
      correlationId: req.correlationId,
    });
    return;
  }

  // Typed HTTP errors thrown by service / route code. The publicMessage is
  // explicitly intended for end-user display, so it bypasses the
  // production-only message scrubbing below.
  if (isHttpError(err)) {
    logger.info("HttpError", {
      correlationId: req.correlationId,
      path: req.originalUrl,
      status: err.status,
      code: err.code,
      message: err.publicMessage,
    });
    // For JSON-preferred clients (XHR, fetch with Accept: application/json),
    // respond JSON so the client-side toast / form-error handlers stay in
    // their existing branch rather than rendering an HTML error page into a
    // detail panel.
    const wantsJson =
      req.xhr ||
      (typeof req.headers.accept === "string" && req.headers.accept.indexOf("application/json") !== -1);
    if (wantsJson) {
      res.status(err.status).json({ ok: false, message: err.publicMessage, code: err.code });
      return;
    }
    res.status(err.status).render("error", {
      title: err.status === 404 ? "Not found" : err.status === 403 ? "Access denied" : "Request failed",
      message: err.publicMessage,
      correlationId: req.correlationId,
    });
    return;
  }

  logger.error("Unhandled request failure", {
    correlationId: req.correlationId,
    err,
  });
  // In production, never echo the raw error message to the browser — it can
  // leak internal paths, dependency versions, or implementation details
  // ("Cannot read properties of undefined"). The full error is logged with the
  // correlation id so an operator can still diagnose. In development the
  // original message comes through to keep the inner loop fast.
  const rawMessage = err instanceof Error ? err.message : "Unknown error";
  const message =
    config.NODE_ENV === "production"
      ? "An unexpected error occurred. Reference the correlation id when reporting this issue."
      : rawMessage;
  res.status(500).render("error", {
    title: "Request failed",
    message,
    correlationId: req.correlationId,
  });
});

async function start(): Promise<void> {
  // Single-instance enforcement. The portal is intentionally one-process-
  // per-data-directory: running two against the same data dir would silently
  // halve the per-account login lockout threshold (each replica counts only
  // its own failures), undercount active sessions, and race on the settings
  // and login-history JSON files. Refuse to start if another live process
  // already owns the lock; reclaim a stale lock if the previous owner is
  // gone. The lock is released on graceful shutdown.
  const dataDir = path.dirname(config.SETTINGS_FILE_PATH);
  const lock = await acquireSingleInstanceLock(dataDir);
  if (!lock.acquired) {
    logger.error(
      "Refusing to start: another Group Self Service process is already running against this data directory.",
      { dataDir, lockPath: lock.lockPath, conflictingPid: lock.conflictingPid }
    );
    process.exit(1);
  }

  const settings = await settingsService.getSettings();
  const wantsTls = settings.webTls.enabled;
  const hasTlsMaterial = settings.webTls.certPem.trim() && settings.webTls.keyPem.trim();

  if (wantsTls && !hasTlsMaterial) {
    throw new Error("Web TLS is enabled but the certificate or private key is missing in portal settings.");
  }

  const server = wantsTls
    ? https.createServer(
        {
          cert: settings.webTls.certPem,
          key: settings.webTls.keyPem,
          passphrase: settings.webTls.passphrase || undefined,
        },
        app
      )
    : http.createServer(app);

  server.listen(config.PORT, () => {
    startCleanupInterval();
    logger.info("Group Self Service started", {
      port: config.PORT,
      protocol: wantsTls ? "https" : "http",
      authMode: config.AUTH_MODE,
      adProvider: adRepository.constructor.name,
      entraProvider: entraRepository.constructor.name,
      nodeEnv: config.NODE_ENV,
      mockEntraCallbackEnabled: config.NODE_ENV !== "production",
    });
  });

  if (wantsTls && settings.webTls.redirectHttpEnabled) {
    if (
      settings.webTls.redirectHttpPort < 1024 &&
      process.platform !== "win32" &&
      typeof process.getuid === "function" &&
      process.getuid() !== 0
    ) {
      logger.warn("HTTP redirect port may require elevated bind permissions", {
        port: settings.webTls.redirectHttpPort,
        platform: process.platform,
        hint: "Use a higher port or grant CAP_NET_BIND_SERVICE to the process.",
      });
    }

    const redirectServer = http.createServer((req, res) => {
      const hostHeader = req.headers.host || "localhost";
      const host = hostHeader.replace(/:\d+$/, "");
      const portSuffix = config.PORT === 443 ? "" : `:${config.PORT}`;
      const location = `https://${host}${portSuffix}${req.url || "/"}`;
      res.statusCode = 301;
      res.setHeader("Location", location);
      res.end();
    });

    redirectServer.listen(settings.webTls.redirectHttpPort, () => {
      logger.info("HTTP redirect server started", {
        port: settings.webTls.redirectHttpPort,
        targetPort: config.PORT,
      });
    });
  }

  // Graceful shutdown. SIGTERM/SIGINT (docker stop, systemd, Ctrl+C) get a
  // window to drain in-flight requests, close the HTTP listener(s), and let
  // the process exit cleanly. A second signal forces an exit so a stuck
  // request can't keep the container alive forever.
  //
  // Production gets a longer grace because an in-flight LDAP bind against
  // a slow domain controller can take 10-20 s; killing it mid-flight risks
  // a half-completed membership change. Dev keeps the shorter window so
  // tsx-watch reloads feel snappy.
  const SHUTDOWN_GRACE_MS = config.NODE_ENV === "production" ? 30_000 : 10_000;
  let shuttingDown = false;
  function shutdown(signal: NodeJS.Signals): void {
    if (shuttingDown) {
      logger.warn("Shutdown signal repeated; exiting now", { signal });
      process.exit(1);
    }
    shuttingDown = true;
    logger.info("Shutdown signal received; draining", {
      signal,
      graceMs: SHUTDOWN_GRACE_MS,
    });
    const timer = setTimeout(() => {
      logger.warn("Shutdown grace exceeded; forcing exit");
      process.exit(1);
    }, SHUTDOWN_GRACE_MS);
    timer.unref();
    server.close((err) => {
      if (err) {
        logger.warn("HTTP server close errored", { err: (err as Error).message });
      }
      // Drain pooled LDAP connections best-effort so the DC doesn't see
      // a flurry of TLS resets when the process exits. Fire-and-forget;
      // we're about to call process.exit anyway.
      adRepository.closePool().catch(() => undefined);
      releaseSingleInstanceLock(lock.lockPath);
      stopCleanupInterval();
      logger.info("Shutdown complete");
      process.exit(0);
    });
  }
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

void start().catch((error) => {
  logger.error("Failed to start Group Self Service", {
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });
  process.exit(1);
});
