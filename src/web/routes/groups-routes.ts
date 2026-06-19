import { Router } from "express";
import session from "express-session";
import { z } from "zod";
import { GroupManagementService } from "../../application/group-management-service";
import { PortalSettingsService } from "../../application/portal-settings-service";
import { asyncHandler } from "../async-handler";
import { requireAuth } from "../auth-middleware";
import { getDirectoryCredentials, getEntraAccessToken } from "../session-directory-credentials";
import { groupListLatency } from "../../infrastructure/metrics";
import { LoginHistoryStore } from "../../infrastructure/login-history";

// Loose distinguished-name validator. Accepts standard RFC 4514 forms like
// "CN=Foo,OU=Bar,DC=example,DC=com" while rejecting newlines, NUL bytes, or
// strings without an "attr=value" component. The downstream LDAP client
// performs final canonicalisation; this is only a boundary sanity check.
const DN_REGEX = /^[A-Za-z][\w-]*=[^,\r\n\0]+(?:,[A-Za-z][\w-]*=[^,\r\n\0]+)*$/;
// Entra group/user references travel as "entra:{guid}" or "entra-user:{guid}".
const ENTRA_GROUP_REF_REGEX = /^entra:[0-9a-f-]{32,40}$/i;
const ENTRA_USER_REF_REGEX = /^entra-user:[0-9a-f-]{32,40}$/i;

const groupRefString = z
  .string()
  .min(1)
  .max(2048)
  .refine((v) => {
    const trimmed = v.trim();
    return DN_REGEX.test(trimmed) || ENTRA_GROUP_REF_REGEX.test(trimmed);
  }, { message: "Invalid group reference" });

const memberRefString = z
  .string()
  .min(1)
  .max(2048)
  .refine((v) => {
    const trimmed = v.trim();
    return DN_REGEX.test(trimmed) || ENTRA_USER_REF_REGEX.test(trimmed);
  }, { message: "Invalid member reference" });

const groupRefSchema = z.object({ groupDn: groupRefString });
const memberSchema = z.object({ groupDn: groupRefString, memberDn: memberRefString });

// Allowed flash message prefixes. Flash values must contain only alphanumeric,
// spaces, commas, and "+" characters to prevent XSS via the EJS template.
// This prevents injection of HTML/script content into the flash parameter.
function sanitizeFlash(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  // Allow alphanumeric, spaces, commas, plus signs, and hyphens (covers common flash messages).
  if (!/^[a-zA-Z0-9 ,+\-]*$/.test(value)) return undefined;
  return value;
}

export function createGroupRoutes(
  service: GroupManagementService,
  settingsService: PortalSettingsService,
  loginHistory: LoginHistoryStore,
  sessionStore: session.Store
): Router {
  const router = Router();
  router.use(requireAuth);

  router.get("/", asyncHandler(async (req, res) => {
    // Record wall-clock time for the initial groups list render. Used by the
    // admin Health tab as a coarse user-experience metric.
    const startedAt = Date.now();
    const directoryCredentials = getDirectoryCredentials(req.session);
    const groups = await service.getManagedGroupsForUser(
      req.user!,
      req.correlationId,
      getEntraAccessToken(req.session),
      directoryCredentials
    );
    const settings = await settingsService.getSettings();
    // Banner shown to AD-authenticated users who haven't yet completed an
    // Entra round-trip. We don't auto-redirect to OAuth: the silent attempt
    // already ran after login (see auth-routes), and forcing an interactive
    // prompt would defeat the point of "Entra only when needed". The user
    // can connect on demand or dismiss the banner for the session.
    const entraConnectBannerVisible =
      settings.entra.enabled &&
      !req.session.isBreakGlass &&
      !getEntraAccessToken(req.session) &&
      !req.session.entraBannerDismissed;
    // Previous-login + active-sessions widget. Break-glass account is
    // hidden from the widget — no AD identity, no useful history.
    const username = req.user?.samAccountName;
    const previousLogin = username && !req.session.isBreakGlass
      ? loginHistory.getLastLogin(username)
      : undefined;
    if (username && !req.session.isBreakGlass) {
      // Drop tracked sids whose session is no longer in the store. A
      // browser-tab close doesn't hit /auth/logout, so without this the
      // "N other active sessions" count climbs over time. Best-effort;
      // a reconciliation failure must never block the page render.
      try {
        await loginHistory.reconcileWithStore(username, sessionStore);
      } catch {
        /* non-fatal */
      }
    }
    const otherSessionsCount = username && !req.session.isBreakGlass
      ? loginHistory.listOtherSessionIds(username, req.sessionID || "").length
      : 0;
    res.render("groups", {
      title: "Managed Groups",
      groups,
      csrfToken: req.csrfToken!(),
      user: req.user,
      flash: sanitizeFlash(req.query.flash),
      entraWritesEnabled: !!(settings.entra.enabled && settings.entra.allowMemberWrites && getEntraAccessToken(req.session)),
      entraConnectBannerVisible,
      previousLogin,
      otherSessionsCount,
    });
        groupListLatency.record(Date.now() - startedAt);
  }));

  router.get("/members", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = groupRefSchema.parse(req.query);
      const members = await service.getGroupMembersForUser(
        req.user!,
        parsed.groupDn,
        req.correlationId,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      res.render("members", {
        title: "Group Members",
        groupDn: parsed.groupDn,
        members,
        csrfToken: req.csrfToken!(),
        flash: sanitizeFlash(req.query.flash),
      });
    } catch (error) {
      next(error);
    }
  });

  router.get("/members/list", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = groupRefSchema.parse(req.query);
      const members = await service.getGroupMembersForUser(
        req.user!,
        parsed.groupDn,
        req.correlationId,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      res.json({ ok: true, members });
    } catch (error) {
      next(error);
    }
  });

  // Inline member-count endpoint used by the groups-list page to populate the
  // small "N members" hint per visible row. Cached per group for 60s in
  // process memory so a refresh / scroll burst doesn't translate to one LDAP
  // query per group per second. Authorisation is enforced inside the
  // service; an unauthorised caller gets a 4xx via the error handler.
    const memberCountCache = new Map<string, { count: number; expires: number }>();
  const MEMBER_COUNT_TTL_MS = 60_000;
  // Upper bound on cached entries to prevent unbounded memory growth.
  // Each entry is tiny (key string + number + timestamp), so 2 000 is
  // generous for any realistic user × group matrix while capping heap
  // at a few hundred KB.
  const MEMBER_COUNT_CACHE_MAX = 2_000;
  // Hard cap on a single batched request so a malicious client can't spike
  // the LDAP server with hundreds of queries in one round-trip. The
  // groups-list page only ever asks for what's currently visible (≤ a
  // typical page size of 50–100), so this is generous.
  const MEMBER_COUNT_BATCH_MAX = 100;

  async function resolveMemberCount(
    user: import("../../domain/models").UserIdentity,
    groupDn: string,
    entraAccessToken: string | undefined,
    directoryCredentials: import("../../application/contracts").DirectorySessionCredentials | undefined
  ): Promise<{ count: number; cached: boolean }> {
    const cacheKey = `${user.samAccountName}::${groupDn}`;
    const now = Date.now();
    const cached = memberCountCache.get(cacheKey);
    if (cached && cached.expires > now) {
      return { count: cached.count, cached: true };
    }
        const count = await service.getGroupMemberCount(user, groupDn, entraAccessToken, directoryCredentials);
    // Evict expired entries before inserting so the cache doesn't grow
    // without bound over long-running processes with many users/groups.
    if (memberCountCache.size >= MEMBER_COUNT_CACHE_MAX) {
      for (const [k, v] of memberCountCache) {
        if (v.expires <= now) memberCountCache.delete(k);
      }
      // If still at capacity after sweeping expired entries, drop the
      // entry with the earliest expiry (approximating LRU).
      if (memberCountCache.size >= MEMBER_COUNT_CACHE_MAX) {
        let oldestKey: string | undefined;
        let oldestExp = Infinity;
        for (const [k, v] of memberCountCache) {
          if (v.expires < oldestExp) { oldestExp = v.expires; oldestKey = k; }
        }
        if (oldestKey) memberCountCache.delete(oldestKey);
      }
    }
    memberCountCache.set(cacheKey, { count, expires: now + MEMBER_COUNT_TTL_MS });
    return { count, cached: false };
  }

  router.get("/members/count", async (req, res, _next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = groupRefSchema.parse(req.query);
      const result = await resolveMemberCount(
        req.user!,
        parsed.groupDn,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      res.json({ ok: true, count: result.count, cached: result.cached });
    } catch (error) {
      // Render as JSON 4xx so the page-side JS can fail quietly instead of
      // bubbling to the global error template.
      const message = error instanceof Error ? error.message : "Failed to count members";
      res.status(400).json({ ok: false, message });
    }
  });

  // Batched member-count endpoint. Accepts a JSON body
  //   { groupDns: ["CN=..,DC=..", "entra:GUID", ...] }
  // and returns
  //   { ok: true, results: [{groupDn, count?, cached?, error?}, ...] }
  // The page-side JS prefers this over per-row GETs so a freshly opened
  // groups page costs one HTTP round-trip instead of N.
  const batchSchema = z.object({
    groupDns: z.array(groupRefString).min(1).max(MEMBER_COUNT_BATCH_MAX),
  });
  router.post("/members/counts", async (req, res, _next) => {
    let parsed: z.infer<typeof batchSchema>;
    try {
      parsed = batchSchema.parse(req.body);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid request";
      res.status(400).json({ ok: false, message });
      return;
    }
    const directoryCredentials = getDirectoryCredentials(req.session);
    // Resolve in parallel but bounded — Promise.all is fine here because
    // each call shares the same cache and the upper bound is already
    // enforced by the schema. The service layer enforces per-group
    // authorisation, so a forged DN in the array fails for that DN only.
    const results = await Promise.all(
      parsed.groupDns.map(async (dn) => {
        try {
          const { count, cached } = await resolveMemberCount(
            req.user!,
            dn,
            getEntraAccessToken(req.session),
            directoryCredentials
          );
          return { groupDn: dn, count, cached };
        } catch (err) {
          return {
            groupDn: dn,
            error: err instanceof Error ? err.message : "Failed to count members",
          };
        }
      })
    );
    res.json({ ok: true, results });
  });

  router.post("/members/add", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = memberSchema.parse(req.body);
      await service.addMember(
        req.user!,
        parsed.groupDn,
        parsed.memberDn,
        req.correlationId,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      if (req.xhr || (req.headers.accept || "").includes("application/json")) {
        res.json({ ok: true });
        return;
      }
      res.redirect(`/groups/members?groupDn=${encodeURIComponent(parsed.groupDn)}&flash=Added+member`);
    } catch (error) {
      if (req.xhr || (req.headers.accept || "").includes("application/json")) {
        res.status(400).json({ ok: false, message: error instanceof Error ? error.message : String(error) });
        return;
      }
      next(error);
    }
  });

  router.post("/members/remove", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = memberSchema.parse(req.body);
      await service.removeMember(
        req.user!,
        parsed.groupDn,
        parsed.memberDn,
        req.correlationId,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      if (req.xhr || (req.headers.accept || "").includes("application/json")) {
        res.json({ ok: true });
        return;
      }
      res.redirect(`/groups/members?groupDn=${encodeURIComponent(parsed.groupDn)}&flash=Removed+member`);
    } catch (error) {
      if (req.xhr || (req.headers.accept || "").includes("application/json")) {
        res.status(400).json({ ok: false, message: error instanceof Error ? error.message : String(error) });
        return;
      }
      next(error);
    }
  });

  router.post("/members/bulk-add", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const groupDn = groupRefString.parse(String(req.body.groupDn || ""));
      const memberDns = String(req.body.memberDns || "")
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      const invalid = memberDns.filter((ref) => !DN_REGEX.test(ref) && !ENTRA_USER_REF_REGEX.test(ref));
      if (invalid.length > 0) {
        res.status(400).render("error", {
          title: "Invalid input",
          message: `Invalid member entries: ${invalid.slice(0, 3).join(", ")}${invalid.length > 3 ? "\u2026" : ""}`,
          correlationId: req.correlationId,
        });
        return;
      }
            const result = await service.bulkAdd(req.user!, groupDn, memberDns, req.correlationId, getEntraAccessToken(req.session), directoryCredentials);
      const parts = [`Added ${result.added}`];
      if (result.skipped > 0) parts.push(`skipped ${result.skipped}`);
      if (result.failed > 0) parts.push(`${result.failed} failed`);
      res.redirect(`/groups/members?groupDn=${encodeURIComponent(groupDn)}&flash=${encodeURIComponent(parts.join(", "))}`);
    } catch (error) {
      next(error);
    }
  });

  router.post("/members/bulk-remove", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const groupDn = groupRefString.parse(String(req.body.groupDn || ""));
      const memberDns = String(req.body.memberDns || "")
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      const invalid = memberDns.filter((ref) => !DN_REGEX.test(ref) && !ENTRA_USER_REF_REGEX.test(ref));
      if (invalid.length > 0) {
        res.status(400).render("error", {
          title: "Invalid input",
          message: `Invalid member entries: ${invalid.slice(0, 3).join(", ")}${invalid.length > 3 ? "\u2026" : ""}`,
          correlationId: req.correlationId,
        });
        return;
      }
            const result = await service.bulkRemove(req.user!, groupDn, memberDns, req.correlationId, getEntraAccessToken(req.session), directoryCredentials);
      const parts = [`Removed ${result.removed}`];
      if (result.skipped > 0) parts.push(`skipped ${result.skipped}`);
      if (result.failed > 0) parts.push(`${result.failed} failed`);
      res.redirect(`/groups/members?groupDn=${encodeURIComponent(groupDn)}&flash=${encodeURIComponent(parts.join(", "))}`);
    } catch (error) {
      next(error);
    }
  });

  router.get("/members/export", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const parsed = groupRefSchema.parse(req.query);
      const csv = await service.exportMembersCsv(
        req.user!,
        parsed.groupDn,
        req.correlationId,
        getEntraAccessToken(req.session),
        directoryCredentials
      );
      res.header("Content-Type", "text/csv");
      res.attachment("group-members.csv");
      res.send(csv);
    } catch (error) {
      next(error);
    }
  });

  router.get("/search", async (req, res, next) => {
    try {
      const directoryCredentials = getDirectoryCredentials(req.session);
      const q = String(req.query.q || "");
      if (!q) {
        res.json([]);
        return;
      }
      const sourceParam = String(req.query.source || "").toLowerCase();
      const groupDnParam = String(req.query.groupDn || "");
      const source: "ad" | "entra" | undefined =
        sourceParam === "entra" ? "entra" : sourceParam === "ad" ? "ad" : undefined;
      const results = await service.searchPrincipals(
        req.user!,
        q,
        25,
        req.correlationId,
        {
          source,
          groupRef: groupDnParam || undefined,
          entraAccessToken: getEntraAccessToken(req.session),
          directoryCredentials,
        }
      );
      res.json(results);
    } catch (error) {
      next(error);
    }
  });

  return router;
}
