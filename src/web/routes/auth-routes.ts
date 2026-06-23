import { Router } from "express";
import crypto from "node:crypto";
import session from "express-session";
import { z } from "zod";
import { AdDirectoryRepository, EntraDirectoryRepository } from "../../application/contracts";
import { PortalAdminAuthorizationService } from "../../application/portal-admin-authorization-service";
import { PortalSettingsService } from "../../application/portal-settings-service";
import { checkAccountLockout, clearAccountLockout, recordLoginFailure } from "../../application/login-lockout";
import { LoginHistoryStore } from "../../infrastructure/login-history";
import { config } from "../../config/env";
import { logger } from "../../infrastructure/logger";
import { asyncHandler } from "../async-handler";
import { getDirectoryCredentials, setDirectoryCredentials, getEntraAccessToken, setEntraAccessToken } from "../session-directory-credentials";

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

// Regenerate the session ID after a successful authentication to defeat
// session fixation attacks. Resolves once the new (empty) session is ready
// to receive identity data.
function regenerateSession(req: import("express").Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });
}

function saveSession(req: import("express").Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });
}

export function createAuthRoutes(
  adRepository: AdDirectoryRepository,
  entraRepository: EntraDirectoryRepository,
  settingsService: PortalSettingsService,
  adminAuthorizationService: PortalAdminAuthorizationService,
  loginHistory: LoginHistoryStore,
  sessionStore: session.Store
): Router {
  const router = Router();

  router.get("/login", asyncHandler(async (req, res) => {
    const flash = typeof req.query.flash === "string" ? req.query.flash : undefined;
    // Regenerate the session on the login page when nobody is signed in. This
    // recovers from stale CSRF/session cookies left over from a previous
    // process (e.g. dev-server restart wiped the in-memory session store) so
    // the issued CSRF token is always bound to a live session id.
    if (!req.session.user) {
      try {
        await regenerateSession(req);
      } catch (err) {
        logger.warn("login session regenerate failed", { err: (err as Error).message });
      }
    }
    const settings = await settingsService.getSettings();
    const setupMode = !settings.ad.enabled && !settings.entra.enabled;
        res.render("login", {
      title: "Sign in",
      csrfToken: req.csrfToken!(),
      error: flash,
      setupMode,
    });
  }));

  router.post("/login", asyncHandler(async (req, res) => {
    const settingsAtPost = await settingsService.getSettings();
    const setupMode = !settingsAtPost.ad.enabled && !settingsAtPost.entra.enabled;
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).render("login", {
        title: "Sign in",
        csrfToken: req.csrfToken!(),
        error: "Username is required.",
        setupMode,
      });
      return;
    }

    // Per-account lockout. Complements the IP-based rate limiter on this
    // route: stops anyone (regardless of IP) from grinding through guesses
    // against a single account.
    const lockoutBefore = checkAccountLockout(parsed.data.username);
    if (lockoutBefore.locked) {
      logger.warn("Login attempt against locked account", {
        username: parsed.data.username,
        retryAfterSeconds: lockoutBefore.retryAfterSeconds,
        ip: req.ip,
      });
      const minutes = Math.max(1, Math.ceil((lockoutBefore.retryAfterSeconds ?? 0) / 60));
      res.status(429).render("login", {
        title: "Sign in",
        csrfToken: req.csrfToken!(),
        error: `Too many failed sign-in attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
        setupMode,
      });
      return;
    }

    const isBreakGlass = await settingsService.authenticateBreakGlass(parsed.data.username, parsed.data.password);
    if (isBreakGlass) {
      clearAccountLockout(parsed.data.username);
      await regenerateSession(req);
      req.session.user = {
        upn: `${parsed.data.username}@local.breakglass`,
        samAccountName: parsed.data.username,
        displayName: `Break Glass ${parsed.data.username}`,
      };
      req.session.isBreakGlass = true;
      req.session.isPortalAdmin = true;
      setDirectoryCredentials(req.session, undefined);
      setEntraAccessToken(req.session, undefined);
      logger.warn("Break-glass admin login", { username: parsed.data.username, ip: req.ip });
      await saveSession(req);
      // First-run wizard: if neither AD nor Entra is configured yet, send
      // the break-glass admin to the guided /admin/setup page instead of
      // dropping them on the raw settings tabs. Once either integration is
      // enabled the next login lands on /admin/settings as usual.
      const destination = setupMode
        ? "/admin/setup"
        : "/admin/settings?flash=Break-glass+admin+login+successful";
      res.redirect(destination);
      return;
    }

    const user = await adRepository.authenticateUser(parsed.data.username, parsed.data.password).catch((err) => {
      const e = err as Error & { code?: number | string };
      logger.error("AD authenticate threw", {
        username: parsed.data.username,
        code: e.code,
        message: e.message,
        stack: e.stack,
      });
      return null;
    });
    if (!user) {
      const status = recordLoginFailure(parsed.data.username);
      logger.info("Login rejected", {
        username: parsed.data.username,
        consecutiveFailures: status.consecutiveFailures,
        nowLocked: status.locked,
      });
      res.status(401).render("login", {
        title: "Sign in",
        csrfToken: req.csrfToken!(),
        error: "Invalid credentials.",
        setupMode,
      });
      return;
    }

    clearAccountLockout(parsed.data.username);

    await regenerateSession(req);
    req.session.isBreakGlass = false;
    setDirectoryCredentials(req.session, {
      username: parsed.data.username,
      password: parsed.data.password,
      poolToken: crypto.randomUUID(),
    });
    setEntraAccessToken(req.session, undefined);
    req.session.user = user;
    const directoryCredentials = getDirectoryCredentials(req.session);
    req.session.isPortalAdmin = await adminAuthorizationService.isPortalAdmin(
      user,
      false,
      directoryCredentials,
      undefined
    );
    logger.info("Login success", { username: user.samAccountName, upn: user.upn, ip: req.ip });
    await saveSession(req);

    // Record "previous login" data + register this session as active. The
    // login-history store handles persistence to disk; failures are non-
    // fatal so a write hiccup never blocks the user from signing in.
    try {
      await loginHistory.recordLogin(user.samAccountName, {
        timestamp: new Date().toISOString(),
        ip: req.ip,
        userAgent: req.headers["user-agent"] as string | undefined,
      });
      if (req.sessionID) {
        loginHistory.registerSession(user.samAccountName, req.sessionID, {
          ip: req.ip,
          userAgent: req.headers["user-agent"] as string | undefined,
        });
      }
    } catch (err) {
      logger.warn("login-history record failed", { err: (err as Error).message });
    }

    // Complete primary sign-in immediately. Entra connection is opt-in via
    // the "Connect Entra ID" action on /groups so users without a current
    // Microsoft session are never blocked from reaching the app.
        req.session.entraSilentAttempted = false;
    res.redirect("/groups");
  }));

  router.get("/entra/start", asyncHandler(async (req, res) => {
    if (!req.session.user) {
      res.redirect("/auth/login");
      return;
    }
    // Any explicit visit to /entra/start (banner click, admin-page CTA) clears
    // the banner-dismissed flag so subsequent silent failures can re-surface
    // the prompt later in the session if needed.
    req.session.entraBannerDismissed = false;

    const state = crypto.randomBytes(24).toString("base64url");
    const codeVerifier = crypto.randomBytes(64).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    req.session.entraAuthState = state;
    req.session.entraPkceVerifier = codeVerifier;

    const settings = await settingsService.getSettings();
    const silent = String(req.query.silent || "") === "1";
    req.session.entraSilentAttempted = silent;
    // Pass the AD-authenticated UPN as login_hint so Microsoft pre-fills the
    // email field and skips the account-picker / home-realm-discovery hops
    // when the browser has no existing Microsoft session. domain_hint speeds
    // that up further on federated tenants. Both are best-effort \u2014 if the AD
    // identity has no UPN we just send the request without hints.
    const upn = req.session.user.upn || "";
    const atIndex = upn.indexOf("@");
    const loginHint = upn.includes("@") ? upn : undefined;
    const domainHint = atIndex > 0 ? upn.slice(atIndex + 1) : undefined;
    const authUrl = await entraRepository.getAuthorizationUrl(
      state,
      codeChallenge,
      settings.entra.redirectUri,
      {
        loginHint,
        domainHint,
        prompt: silent ? "none" : undefined,
      }
    );
        res.redirect(authUrl);
  }));

  router.get("/entra/callback", asyncHandler(async (req, res) => {
    const state = String(req.query.state || "");
    const code = String(req.query.code || "");
    const errorParam = String(req.query.error || "");

    // Silent SSO attempted but the browser has no Microsoft session (or
    // consent/account picker is required). Do not escalate automatically to
    // an interactive Microsoft prompt; return to groups and let the user
    // choose to click "Connect Entra ID" when they want to sign in.
    const silentRetryable = new Set([
      "login_required",
      "interaction_required",
      "consent_required",
      "account_selection_required",
    ]);
    if (errorParam && silentRetryable.has(errorParam) && req.session.entraSilentAttempted) {
      req.session.entraSilentAttempted = false;
      req.session.entraAuthState = undefined;
      req.session.entraPkceVerifier = undefined;
      setEntraAccessToken(req.session, undefined);
      res.redirect("/groups?flash=Sign+in+to+Entra+ID+to+view+and+manage+Entra-owned+groups");
      return;
    }

    if (
      !state ||
      !code ||
      !req.session.entraAuthState ||
      !req.session.entraPkceVerifier ||
      state !== req.session.entraAuthState
    ) {
      setEntraAccessToken(req.session, undefined);
      req.session.entraSilentAttempted = false;
      res.redirect("/groups?flash=Entra+sign-in+was+not+completed");
      return;
    }

    const settings = await settingsService.getSettings();
    const accessToken = await entraRepository.exchangeAuthorizationCode(code, req.session.entraPkceVerifier, settings.entra.redirectUri);

    req.session.entraAuthState = undefined;
    req.session.entraPkceVerifier = undefined;

    if (!accessToken) {
      setEntraAccessToken(req.session, undefined);
      res.redirect("/groups?flash=Unable+to+connect+to+Entra+ID");
      return;
    }

    // Defeat session fixation across the Entra step: snapshot the identity
    // values we want to carry forward, regenerate to issue a new session id,
    // then re-attach them on the fresh session. Without this an attacker who
    // pre-shared a session id with the victim could end up holding the
    // victim's Entra access token.
    const carriedUser = req.session.user;
    const carriedIsBreakGlass = req.session.isBreakGlass === true;
    const carriedDirectoryCreds = req.session.encryptedDirectoryCredentials;
    try {
      await regenerateSession(req);
    } catch (err) {
      logger.warn("Entra callback session regenerate failed", { err: (err as Error).message });
    }
    req.session.user = carriedUser;
    req.session.isBreakGlass = carriedIsBreakGlass;
    req.session.encryptedDirectoryCredentials = carriedDirectoryCreds;
    setEntraAccessToken(req.session, accessToken);
    req.session.isPortalAdmin = await adminAuthorizationService.isPortalAdmin(
      req.session.user!,
      req.session.isBreakGlass === true,
      getDirectoryCredentials(req.session),
      accessToken
    );
    // Rotate the CSRF cookie so it is bound to the new session id. Without
    // this the browser still carries a token tied to the pre-regenerate
    // session and the next non-GET request would be rejected as "Session
    // expired".
    try {
      req.csrfToken!();
    } catch {
      /* best-effort */
    }
    // Persist the new session before sending the redirect so the next request
    // is guaranteed to load it.
        await saveSession(req);
    res.redirect("/groups?flash=Connected+to+Entra+ID");
  }));

  // Local-only stand-in for the real Microsoft callback. Used by
  // MockEntraDirectoryRepository so dev/test runs don't need a real tenant.
  // Refused outright in production: even though the wired-up repo is the
  // real Graph client, leaving this route mounted means a future
  // mis-configuration that swaps in the mock repo would silently turn the
  // route into an authenticated front door (any user could obtain
  // entraAccessToken="mock-entra-token" and bypass Entra-backed admin
  // checks). Registering it conditionally removes the surface entirely.
  if (config.NODE_ENV !== "production") {
    router.get("/entra/mock-callback", asyncHandler(async (req, res) => {
      const state = String(req.query.state || "");
      const code = String(req.query.code || "");

      if (!state || !code || state !== req.session.entraAuthState || !req.session.entraPkceVerifier) {
        setEntraAccessToken(req.session, undefined);
        res.redirect("/groups?flash=Mock+Entra+sign-in+failed");
        return;
      }

      req.session.entraAuthState = undefined;
      req.session.entraPkceVerifier = undefined;
      // Same session-fixation guard as the real callback.
      const carriedUser = req.session.user;
      const carriedIsBreakGlass = req.session.isBreakGlass === true;
      const carriedDirectoryCreds = req.session.encryptedDirectoryCredentials;
      try {
        await regenerateSession(req);
      } catch (err) {
        logger.warn("Mock Entra callback session regenerate failed", { err: (err as Error).message });
      }
      req.session.user = carriedUser;
      req.session.isBreakGlass = carriedIsBreakGlass;
      req.session.encryptedDirectoryCredentials = carriedDirectoryCreds;
      setEntraAccessToken(req.session, "mock-entra-token");
      req.session.isPortalAdmin = req.session.isBreakGlass === true;
      try {
        req.csrfToken!();
      } catch {
        /* best-effort */
      }
            await saveSession(req);
      res.redirect("/groups?flash=Connected+to+mock+Entra+ID");
    }));
  } else {
    // Belt-and-braces: explicitly refuse the path in production so a stray
    // bookmark or scanner never even reaches a routing fall-through.
    router.get("/entra/mock-callback", (_req, res) => {
      res.status(404).type("text/plain").send("Not found");
    });
  }

  // Persistently hide the "Connect to Entra ID" banner for the rest of this
  // session. The user can still trigger the OAuth flow on demand via the
  // Connect link / button.
  router.post("/entra/dismiss-banner", (req, res) => {
    req.session.entraBannerDismissed = true;
    res.redirect("/groups");
  });

  router.post("/logout", (req, res) => {
    const username = req.session.user?.samAccountName;
    const sid = req.sessionID;
    req.session.destroy((err) => {
      if (err) {
        logger.warn("Logout session destroy failed", { err: (err as Error).message });
      }
      if (username && sid) {
        loginHistory.unregisterSession(username, sid);
      }
      res.clearCookie("connect.sid", { path: "/" });
      if (username) {
        logger.info("Logout", { username });
      }
      res.redirect("/auth/login");
    });
  });

  // Sign out every session for the current user except the one calling this
  // endpoint. Useful when a user spots an unfamiliar entry on their
  // "Last sign-in" line and wants to evict the imposter without changing
  // their own password.
  router.post("/sign-out-others", asyncHandler(async (req, res) => {
    if (!req.session.user) {
      res.redirect("/auth/login");
      return;
    }
    const username = req.session.user.samAccountName;
    const currentSid = req.sessionID;
    const sids = loginHistory.listOtherSessionIds(username, currentSid);
    loginHistory.forgetOtherSessions(username, currentSid);
    let destroyed = 0;
    for (const sid of sids) {
      await new Promise<void>((resolve) => {
        sessionStore.destroy(sid, (err) => {
          if (err) {
            logger.warn("sign-out-others: failed to destroy session", { err: (err as Error).message, sid });
          } else {
            destroyed += 1;
          }
          resolve();
        });
      });
    }
    logger.info("Other sessions signed out", { username, destroyed });
    const message = destroyed === 0
      ? "No other active sessions found."
      : `Signed out ${destroyed} other session${destroyed === 1 ? "" : "s"}.`;
        res.redirect(`/groups?flash=${encodeURIComponent(message)}`);
  }));

  return router;
}
