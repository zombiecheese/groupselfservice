# Technical Reference

This document explains how the **Group Self Service Portal** is constructed: the request-handling pipeline, the layering of services and repositories, the data model, and — at length — the security boundaries that protect user data, query results, and credentials.

For features, configuration, and operations notes see [README.md](README.md).

---

## 1. Architecture overview

The application is a single-process **Node.js 20 + TypeScript** Express server that renders server-side **EJS** templates with a thin layer of unbundled vanilla-JS for interactive admin and group-management widgets. There is no SPA, no client-side router, and no runtime build step — `tsc` compiles to `dist/`, static assets ship as-is from `public/`.

The codebase is layered. Cross-layer access flows top-down only:

```
src/web/            HTTP boundary: Express routes, middleware, EJS views
  └── routes/       request validation (zod), session/csrf, calls services
  └── auth-middleware, session-directory-credentials

src/application/    business logic, contracts (interfaces), audit emission
  └── group-management-service, portal-settings-service,
       portal-admin-authorization-service, mail-service

src/infrastructure/ outbound adapters
  ├── ad/           ldapts client + caching/configurable wrappers + mock
  ├── entra/        Microsoft Graph repository + configurable/mock/noop
  ├── audit/        NDJSON file writer + optional syslog forwarder
  ├── settings/     encrypted JSON settings repository
  ├── security/     AES-256-GCM ciphers (secrets at rest, session creds)
  ├── jobs/         retention sweeper
  ├── logger.ts     winston JSON logger
  └── metrics.ts    in-process latency histogram

src/domain/         pure types / models (no I/O)

src/config/         zod-validated env parsing + production preflight checks
```

The application object is wired up in [src/server.ts](src/server.ts) with constructor injection. Repositories are wrapped: a real `LdapAdRepository` (with a bounded per-credential connection pool, see §6.11) is wrapped by `ConfigurableAdRepository` (delegates to a mock when AD is disabled in settings, caches the resolved instance keyed by relevant settings so the pool persists across calls) wrapped by `CachedAdRepository` (60-second TTL + LRU-bounded cache for `findManagedGroups`, invalidating the target user's entries on member add/remove).

A PID lockfile under `data/.portal.pid` ([src/infrastructure/single-instance-lock.ts](src/infrastructure/single-instance-lock.ts)) refuses to start a second process against the same data directory: this is intentional — the per-account login-lockout map, the active-sessions map for *Sign out other sessions*, the LDAP pool, and the AD ownership cache all live in process memory and are correct only when there is exactly one process.

---

## 2. Request lifecycle

Every HTTP request flows through a fixed middleware chain configured in [src/server.ts](src/server.ts):

1. **`helmet()`** sets baseline security response headers.
2. **Structured JSON access logger** (`requestLogger`) emits one winston `http`-level entry per request at response-finish with method, path, status, duration, content length, correlation id, IP, actor sAM, and user-agent.
3. **`express.urlencoded`** / **`express.json`** parse the body. Limit is 4 MB, sized for the branding logo upload (capped at 2 MB encoded). A 413 from this layer is intercepted by the global error handler and rendered as a friendly red flash on the General settings tab when it originates from `/admin/settings`.
4. **`cookieParser()`** parses request cookies. Only one application cookie carries identity; the CSRF cookie is managed by `csrf-csrf`.
5. **`express-session`** issues the session cookie, stamped `httpOnly`, `sameSite=lax`, `secure` in production, with a configurable TTL (`SESSION_TTL_SECONDS`, default 28 800 s = 8 h). The store is `session-file-store` writing one JSON-per-sid into `data/sessions/`, reaped every 15 minutes. Sessions therefore survive process restart and rolling deploys — see §6.5.
6. **`csrf-csrf` double-submit cookie** issues `__Host-psifi.x-csrf-token` (in production) or `x-csrf-token` (dev) and binds the token to the current `session.id`. A custom getter accepts the matching token from either the `_csrf` form field or the `x-csrf-token` request header.
7. **Static asset middleware** serves `public/`.
8. **Correlation-id middleware** assigns `req.correlationId = req.header('x-correlation-id') ?? crypto.randomUUID()`; this id flows into both winston logs and audit records.
9. **`attachUserFromSession`** populates `req.user` from `req.session.user` if present; absent for anonymous routes.
10. **Locals propagation** copies `req.user` and `req.session.isPortalAdmin` to `res.locals` so EJS partials can render the right header without re-fetching.
11. **Route handlers** (mounted under `/auth`, `/groups`, `/admin`).
12. **Global error handler** — last in the chain — converts `csrf-csrf` `EBADCSRFTOKEN` errors into a friendly "Session expired" page (or a redirect for the login form), maps `413` from the body parser to a settings-tab flash, maps typed `HttpError` ([src/domain/http-error.ts](src/domain/http-error.ts)) thrown by service / route code to the right 4xx with JSON-or-HTML negotiation based on `Accept`, and otherwise renders the generic error template.

A single startup path then chooses between an HTTP and HTTPS listener depending on `webTls.enabled` in portal settings; if HTTPS is on and `webTls.redirectHttpEnabled` is also on, a second `http` server is started just to issue 301s.

---

## 3. Data flow examples

### 3.1 Loading the groups list (`GET /groups`)

1. `requireAuth` rejects anonymous requests.
2. `getDirectoryCredentials(req.session)` decrypts the per-session AD credential payload (see §6.4).
3. `GroupManagementService.getManagedGroupsForUser` calls **both** repositories:
   - AD: `findManagedGroups(user, includeNested, 500, credentials)` — reads `managedBy` and (optionally) walks one nesting level.
   - Entra: `findManagedGroups(accessToken, 500)` — `GET /v1.0/me/ownedObjects/microsoft.graph.group`. Skipped if the user has no Graph token.
4. Results are concatenated (`[...adGroups, ...entraGroups]`) and a `GROUP_LIST` audit event is emitted.
5. The view renders, then `groupListLatency.record(Date.now() - startedAt)` pushes the wall-clock duration into a 200-sample ring buffer used by the Health tab.

### 3.2 Adding a member (`POST /groups/members/add`)

1. CSRF token validated by `csrf-csrf`.
2. zod validates the request body. `groupDn` and `memberDn` must each match either an AD distinguished-name regex or one of the prefixed Entra references (`entra:{guid}` for groups, `entra-user:{guid}` for members).
3. `GroupManagementService.addMember` dispatches by prefix:
   - **AD path** — `assertCanManage` calls `adRepository.canUserManageGroup` to confirm the requesting user is on the group's `managedBy` (directly or one level nested) before issuing the `addGroupMember` LDAP modify.
   - **Entra path** — checks (a) integration enabled, (b) `allowMemberWrites` toggle on, (c) the request carries a Graph token, then calls `isUserOwnerOfGroup` against `/me/ownedObjects` before issuing `POST /v1.0/groups/{id}/members/$ref`.
4. Audit record (`GROUP_ADD_MEMBER`, with `source` = `ad` or `entra`) is written to the daily NDJSON file and optionally forwarded over syslog.
5. Notification email is sent to the affected user *if* mail is enabled and the relevant `notifications.memberAddedEnabled` flag is on.

### 3.3 Login (`POST /auth/login`)

1. `express-rate-limit` applies a 10-attempts-per-15-minute window keyed by IP. Successful logins are not counted toward the limit.
2. The handler tries `adRepository.authenticateUser(upnOrSam, password)` first (LDAP simple bind under the user's own credentials). Failing that, it falls back to `portalSettingsService.authenticateBreakGlass(username, password)`, which performs a constant-time PBKDF2-SHA256 comparison against the salted hash stored in `portal-settings.json`.
3. On success the session is **regenerated** (`req.session.regenerate(...)`), then `req.session.user`, `req.session.isBreakGlass`, and the AES-GCM-encrypted `req.session.directoryCredentialsPayload` are set.
4. Portal-admin status is computed by `PortalAdminAuthorizationService` and stamped into the session.
5. If Entra is enabled the user is redirected to `/auth/entra/start`; otherwise to `/groups`.

---

## 4. Domain model

Located in [src/domain/models.ts](src/domain/models.ts) — pure types, no behavior. Highlights:

| Type | Purpose |
| --- | --- |
| `UserIdentity` | Authenticated principal (UPN, sAMAccountName, displayName, optional DN). |
| `AdGroup` / `AdUser` | Distinguished-name-keyed AD records. |
| `EntraUser` | GUID-keyed Entra user (added with cloud member-write feature). |
| `ManagedGroup` | View model: `{ group, source: "ad" \| "entra", ownerType: "direct" \| "nested" \| "entra-owned", ownerPath? }`. |
| `GroupMembershipChange` | LDAP-flavored `{ groupDn, memberDn }`. |
| `AuditAction` | Closed enum: `GROUP_LIST`, `GROUP_VIEW_MEMBERS`, `GROUP_ADD_MEMBER`, `GROUP_REMOVE_MEMBER`, `GROUP_BULK_ADD`, `GROUP_BULK_REMOVE`, `GROUP_EXPORT_MEMBERS`. |
| `AuditRecord` | NDJSON row including `source` discriminator, correlation id, and free-text `details`. |

Service interfaces (`AdDirectoryRepository`, `EntraDirectoryRepository`, `PortalSettingsRepository`, `AuditRepository`) live alongside the configuration types in [src/application/contracts.ts](src/application/contracts.ts).

---

## 5. Persistence model

The portal owns several pieces of mutable state, all under `./data/`:

1. **`./data/portal-settings.json`** — single JSON document holding *all* admin settings. Read on every request via [`FilePortalSettingsRepository`](src/infrastructure/settings/file-portal-settings-repository.ts), which deep-merges defaults so older files transparently inherit any newly-introduced fields. Fields flagged as secrets (Entra client secret, mail-Entra client secret, SMTP password, web-TLS private key, web-TLS passphrase) are encrypted in place with the `enc:v1:` marker; the file is rewritten **atomically** (tmp file + fsync + rename) on every save via [`writeFileAtomic`](src/infrastructure/atomic-write.ts), so a crash between truncate and final flush never leaves a zero-byte file. The reader refuses to overwrite an empty or invalid file with defaults — the operator is told the exact path and asked to restore. See §6.2.
2. **`./data/audit/audit-YYYY-MM-DD.ndjson`** — append-only daily log produced by `HostedAuditRepository`. Each record carries a `seq` and an `hmac` so the chain can be replayed by the `npm run verify-audit` CLI. A retention sweeper removes files older than `audit.retentionDays` on a schedule plus opportunistically every 20 writes. See §6.13.
3. **`./data/sessions/<sid>.json`** — one JSON file per active browser session, written by `session-file-store`. Persists sessions across restart and rolling deploys; reaped every 15 minutes when the TTL elapses. The session payload holds the session id, `user`, `isBreakGlass`, `isPortalAdmin` (+ a TTL cache on the admin-check), encrypted `encryptedDirectoryCredentials` (AD credentials — `{ username, password, poolToken }`), encrypted `encryptedEntraAccessToken` (Microsoft Graph token), Entra OAuth `state`/`pkceVerifier`, the `entraSilentAttempted` and `entraBannerDismissed` flags, and a CSRF anchor flag. Both credential payloads are AES-256-GCM-encrypted with a fresh random IV per encryption. Never touched directly; only manipulated through the typed `req.session` extensions in [src/web/auth-middleware.ts](src/web/auth-middleware.ts) and helpers in [src/web/session-directory-credentials.ts](src/web/session-directory-credentials.ts).
4. **`./data/login-history.json`** — per-user *last sign-in* + active-sessions index used by the security-visibility widget on `/groups`. Single-flight writer; atomic write via the same helper.
5. **`./data/.portal.pid`** — single-instance lockfile (see §1).
6. **In-process caches** — AD ownership cache, inline member-count cache, per-account login-lockout map, LDAP connection pool, latency ring buffer. All correct only on a single instance; all reset on restart by design.

There is **no relational database**. There is **no shared cache**. The portal is intentionally single-instance per data directory (enforced by the PID lockfile); multi-instance is *not* on the roadmap. See the README *Deployment topology* section.

---

## 6. Security architecture

Security is the dominant non-functional concern in this code base. This section enumerates the controls that protect user data, search results, and credentials.

### 6.1 Trust boundaries

| Boundary | Trust level | Defenses applied |
| --- | --- | --- |
| Browser ↔ portal | Untrusted | TLS termination, CSRF, helmet headers, secure/httpOnly/sameSite cookies, body-size cap, rate limiting, regex input validation, EJS auto-escaping, helmet-set CSP defaults. |
| Portal ↔ Active Directory | Trusted infra; mutual auth via TLS + per-user bind | LDAPS (preferred), custom CA bundle, server-name override, signed-in user's credentials only (no service account), TLS validation defaults to strict. |
| Portal ↔ Microsoft Graph | TLS-protected public endpoint | OAuth 2.0 Authorization Code + PKCE, per-user delegated access tokens, no refresh tokens (re-auth on expiry). |
| Portal ↔ SMTP relay | Configurable | STARTTLS by default, opt-in cleartext for relay-only loopback, optional auth, optional relaxed TLS validation with explicit insecure banner. |
| Portal ↔ disk | Trusted host filesystem | AES-256-GCM-encrypted secrets, ciphertext-rewrite on save, 0o600 not enforced (relies on host posture). |

### 6.2 Secrets at rest — `secrets-cipher.ts`

[`encryptSecret` / `decryptSecret`](src/infrastructure/security/secrets-cipher.ts) implement an AES-256-GCM cipher that prefixes ciphertext with the literal marker `enc:v1:`. The marker lets the codebase round-trip mixed-state files: legacy plaintext or hand-edited values pass through `decryptSecret` unchanged because the marker check fails, and the next save re-encrypts them.

Key handling:

```text
deriveKey(CREDENTIAL_ENCRYPTION_KEY)
  if base64-decoded length === 32  → use those 32 bytes directly
  else                              → SHA-256 the raw string → 32 bytes
```

This means an operator can supply either a 32-byte base64 string (preferred, generated by `openssl rand -base64 32`) or a long passphrase; the latter is hashed to a deterministic 32-byte key.

Encryption layout (`enc:v1:` prefix omitted):

```text
base64( IV(12) || GCM_TAG(16) || CIPHERTEXT(N) )
```

Each save uses a fresh 12-byte random IV. GCM authenticates the ciphertext, so tampering returns an empty string from `decryptSecret` (defensive default — failure surfaces as a missing secret, not as forged data).

Fields encrypted via this cipher: Entra `clientSecret`, mail-Entra `clientSecret`, SMTP `password`, web-TLS `keyPem`, web-TLS `passphrase`.

The same key material drives session-credential encryption (§6.4) but with a separate, JSON-wrapped payload format so the two paths can evolve independently.

**File mode.** After every settings save the repository attempts `fs.chmod(path, 0o600)` so on POSIX hosts only the owner (the portal's service account) can read the encrypted blob. The call is wrapped in a try/catch because it's a no-op on Windows and on filesystems that don't honor POSIX modes. The same protection is applied to newly-created audit NDJSON files.

### 6.3 Production preflight

[`src/config/env.ts`](src/config/env.ts) parses `process.env` through a `zod` schema (typed config object) and then runs `validateProductionSecurity()`. In `NODE_ENV=production` the process **exits non-zero on startup** if either:

- `SESSION_SECRET` is still the default placeholder or shorter than 32 characters; or
- `CREDENTIAL_ENCRYPTION_KEY` is still the default placeholder; or
- in production, `CREDENTIAL_ENCRYPTION_KEY` does not decode as exactly 32 bytes of base64 (a true AES-256 key). The error message includes the exact one-liner to generate a compliant key: `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`. In development a short passphrase still works (it's hashed to 32 bytes by `secrets-cipher.ts`); production refuses to start.

In development the same conditions emit a `[security] Non-production warnings:` message but allow startup. This is the single mechanism that prevents accidentally running with weak secrets in production.

### 6.4 Per-session AD credentials — `session-crypto.ts`

LDAP simple bind requires the user's password on every operation that mutates AD. Storing that password in a session store creates two risks: a session-store dump leaks plaintext, and a developer mistake (e.g. a `console.log(req.session)`) leaks it into logs.

[`encryptDirectoryCredentials`](src/infrastructure/security/session-crypto.ts) addresses both:

1. On login the helper serializes `{ username, password, poolToken }` to JSON, AES-256-GCM-encrypts the result with a fresh IV, and wraps `{ iv, tag, data }` in a single base64 string stored as `req.session.directoryCredentialsPayload`. `poolToken` is a `randomUUID()` generated at login; it is the sole key used to look up the user's LDAP connection-pool bucket (see §6.11) and contains no password material.
2. On every read (`getDirectoryCredentials(req.session)`) the helper decrypts the payload into a transient object — never written back to the session — and the AD repository methods accept it as their `credentials` argument.
3. If the key has rotated or the payload is malformed, decryption returns `null` and the consuming code treats the user as having no LDAP credentials (mock repo behavior, or 412/401 depending on operation).

Net effect: a memory dump or session-store leak yields ciphertext only. The plaintext password lives on the call stack of a single LDAP operation and is GC'd immediately after.

### 6.5 Session lifecycle

- `express-session` cookie attributes: `httpOnly`, `sameSite=lax`, `secure` in production, server-controlled `maxAge`. The cookie is the only client-bearing identifier.
- **Login regenerates the session** to defeat session fixation: the previous `req.session.id` is destroyed and a new one issued before user data is attached.
- **Entra OAuth callback also regenerates the session**, snapshotting identity fields (user, isBreakGlass, encrypted directory credentials, encrypted access token) before regeneration and re-attaching them on the fresh session. This closes a session-fixation window where an attacker could pre-share a session id with the victim, wait for them to complete Microsoft sign-in, and then ride the resulting Entra token.
- **Logout regenerates the session** as well, then redirects to login, ensuring no residual encrypted token payload survives.
- **`GET /auth/login` self-heals stale CSRF cookies**: when the request lands without a `req.session.user`, the session is regenerated before the CSRF token is issued. This recovers from the common scenario where the in-memory store was wiped (dev restart) but the user's browser still holds the old session/CSRF cookie pair.
- The session store is `session-file-store` writing one JSON-per-sid into `data/sessions/`, with the session TTL applied and expired files reaped every 15 minutes. Sessions survive process restart and rolling deploys, and the *Sign out other sessions* feature works for any sid the store still knows about. Both `encryptedDirectoryCredentials` and `encryptedEntraAccessToken` are stored encrypted with AES-256-GCM, so a session-store dump never yields plaintext credentials or tokens. The CSRF token-binding mechanism (`getSessionIdentifier(req) => req.session.id`) cooperates with this (and with any other store that produces a stable id). The portal is intentionally single-instance per data directory — enforced by the PID lockfile (§1) — so a shared session store is not required and not on the roadmap.
- **Active-sessions reconciliation.** Closing a browser tab does not hit `/auth/logout`, so [`LoginHistoryStore.reconcileWithStore`](src/infrastructure/login-history.ts) is called best-effort on every `/groups` render: each tracked sid is checked against the session store and any that no longer exist are dropped so the *N other active sessions* widget converges back to truth.

### 6.6 CSRF

`csrf-csrf` provides the double-submit cookie variant. The token is bound to the session id rather than to the cookie value alone, so a stolen cookie without the matching session is useless. The middleware applies to **every** state-changing request; safe methods (`GET`, `HEAD`, `OPTIONS`) are exempt from token requirement but still trigger token issuance via `req.csrfToken()`.

The token is exposed to forms via `<%= csrfToken %>` and to AJAX clients via either the `_csrf` form field or the `x-csrf-token` header, matching whatever the front-end finds easier.

### 6.7 Authentication

Three modes can authenticate a user; only one is active per session:

1. **AD forms login** — primary path. `LdapAdRepository.authenticateUser` performs a single bind against the configured LDAPS endpoint. The bound credentials are then encrypted into the session for downstream LDAP operations.
2. **Break-glass admin** — a static username + PBKDF2-SHA256-hashed password stored in `portal-settings.json`. Hash parameters: **600 000** iterations (OWASP 2023 password-storage guidance for SHA-256), 32-byte derived key, 16-byte random salt per credential. Comparison uses `crypto.timingSafeEqual` to defeat early-exit timing attacks. Hashes written by older builds (120 000 iterations) remain valid and are **transparently re-hashed on the next successful sign-in** — the new salt + hash + iteration count are persisted via the settings service. Break-glass holders never get LDAP credentials, so AD-write operations fail with explicit messaging.
3. **Entra OAuth (delegated)** — layered on top of the AD/break-glass session for SSO-flavored UX. PKCE-protected (S256 challenge, 64-byte verifier), `state` validated on callback. The portal stores only the access token and never requests a refresh token: when the access token expires, the user re-runs `/auth/entra/start` rather than the portal silently renewing.

### 6.8 Authorization

Two distinct authorization domains exist:

- **End-user domain** — can the signed-in user manage *this* group?
  - AD: `canUserManageGroup` walks `managedBy` directly and (when nested-managedBy is enabled) one level into a member-of check. Either match returns true.
  - Entra: `isUserOwnerOfGroup` queries `/me/ownedObjects` and filters for the target id.
- **Admin domain** — can the signed-in user edit portal settings?
  - `PortalAdminAuthorizationService.isPortalAdmin` evaluates, in order: `req.session.isBreakGlass`, then runs AD-group and Entra-group membership lookups in parallel (`Promise.any` short-circuits on the first match). AD groups come from `delegatedAdmin.adGroupDns`; Entra groups from `delegatedAdmin.entraGroupIds` (via `/me/checkMemberGroups`). The result is cached in the session for 60 s and re-checked whenever the Entra access token presence/identity changes — so a removed delegated admin loses access promptly without each `/admin/*` request triggering N AD + M Entra lookups.

Both paths fail closed: a missing repository, a network timeout, or a Graph 403 yields `false` rather than `true`.

### 6.9 Input validation

- `zod` schemas guard every state-changing route. Schemas are colocated with the handler that consumes them, e.g. [groups-routes.ts](src/web/routes/groups-routes.ts) defines `groupRefString`, `memberRefString`, `groupRefSchema`, `memberSchema`.
- AD identifiers must match a strict DN regex (`^[A-Za-z][\w-]*=[^,\r\n\0]+(?:,[A-Za-z][\w-]*=[^,\r\n\0]+)*$`) — no newlines, no NULs, no missing `attr=value` segments.
- Entra references are restricted to `entra:{guid}` (groups) and `entra-user:{guid}` (members) by separate regexes.
- Theme color fields are restricted to `^#[0-9a-fA-F]{6}$` and silently fall back to the previous value on mismatch.
- The branding logo data URL is checked against an allow-list of MIME prefixes (`png|jpeg|jpg|gif|webp|svg+xml`) plus a 2 MB length cap before being accepted.
- The **LDAP URL** field is parsed with `new URL(...)` and the scheme is restricted to `ldap://` or `ldaps://`. Empty values are tolerated (settings can be saved progressively); non-empty values without a hostname are rejected with a red flash on the Directory tab.
- The **Entra redirect URI** must parse as a URL and must use `https://`, with `http://` accepted only when the hostname is `localhost`, `127.0.0.1`, or `::1` for local development.
- The **audit file path** rejects empty strings, control characters, and any segment equal to `..` (split on either `\` or `/` so both Windows and POSIX traversal attempts are caught). Absolute paths are allowed because they're legitimate for centralised log directories.

### 6.10 Rate limiting

Four routes are explicitly rate-limited via `express-rate-limit`:

| Route | Window | Limit | Notes |
| --- | --- | --- | --- |
| `POST /auth/login` | 15 minutes | 10 per IP | Successful logins are excluded from the count via `skipSuccessfulRequests: true`. Layered on top of the per-account lockout in §7. |
| `GET /groups/search` | 1 minute | 30 per IP | Mitigates wildcard-search abuse against AD. |
| `GET/POST /groups/members/count[s]` | 1 minute | 60 per IP | Caps the inline member-count fan-out from a freshly opened groups page. |
| `GET /admin/audit`, `GET /admin/audit.csv` | 1 minute | 30 per IP | Bounds disk-bound scans of the audit NDJSON files. |

The limits are deliberately permissive enough to avoid breaking interactive use while throttling automated brute force / enumeration. Behind a reverse proxy, set the `TRUST_PROXY` environment variable (see [.env.example](.env.example)) so the limiter and `req.ip` honor `X-Forwarded-For` and the limiter keys on the real client IP. Express receives this via `app.set('trust proxy', ...)` at startup; without it, every request appears to come from the proxy and the per-IP limits become per-portal limits.

### 6.11 LDAP transport security

`LdapAdRepository` uses [ldapts](https://www.npmjs.com/package/ldapts) and exposes:

- **Protocol selection** via the URL scheme (`ldap://` vs `ldaps://`).
- **`tlsRejectUnauthorized`** — defaults to true. The Admin Settings UI exposes an *allow untrusted TLS* toggle that flips this to false; whenever it does, an alert banner appears at the top of every settings page until it is re-enabled.
- **Custom CA PEM** — operators can paste an enterprise CA into a textarea; the bundle is passed as `ca` to the underlying `tls.connect` call so private CAs work without modifying the host trust store.
- **Server-name override** — for SNI corner cases when the LDAPS endpoint cert SAN doesn't match the URL hostname.
- **Family hint** — an `IPv4-only` toggle when the host has both A and AAAA records but only one path is reachable.
- **Pre-flight reachability** — before binding, `pickReachableHost` does DNS + raw TCP checks against every resolved address, picks the first reachable one, then performs the bind. Multi-A records with one dead DC therefore don't surface as cryptic timeouts.
- **Bounded per-credential connection pool** — ldapts maintains a TCP+TLS connection per `Client` instance and the bind step is the expensive part (per-connect TLS handshake on LDAPS). The repository keeps up to 4 bound clients per credential idle for up to 5 minutes; subsequent operations on the same call path reuse them. Pool buckets are keyed by an opaque `poolToken` (a `randomUUID()` generated at login and encrypted inside the session alongside the user's AD credentials — see §6.4). The key contains no password material: a memory snapshot of the pool map reveals nothing about user credentials. Failed operations discard the client instead of returning it to the pool. The pool is drained on graceful shutdown via a `closePool()` pass-through that bubbles up through `CachedAdRepository` and `ConfigurableAdRepository`. Anonymous (un-bound) clients are not pooled.

### 6.12 Graph / OAuth token handling

- **Authorization request** carries `state` (24 random bytes, base64url) and a SHA-256-derived PKCE challenge.
- **`login_hint` and `domain_hint`** are populated from the AD-authenticated user's UPN so Microsoft pre-fills the email field and skips home-realm discovery on federated tenants.
- **Silent SSO attempt, no auto-retry.** The first authorize request after AD login carries `prompt=none`. If the browser has an existing Microsoft session the OAuth round trip completes without UI and the user lands on `/groups` with cloud groups merged in. If AAD returns `error=login_required` (or `interaction_required` / `consent_required` / `account_selection_required`), the callback **redirects to `/groups` instead of restarting interactively** — the user still gets a working AD-side portal, and a non-blocking *Connect Entra ID* banner offers an opt-in interactive flow. A session flag (`entraSilentAttempted`) ensures the silent variant runs only on the first post-AD-login attempt; explicit visits to `/auth/entra/start` (banner click, admin-page CTA) always do an interactive request. Net effect: zero clicks when SSO is available, zero blocked users when Microsoft is unreachable or uncooperative, and the user only sees a Microsoft prompt when they explicitly opt in.
- **Banner dismissal** is per-session (`POST /auth/entra/dismiss-banner` sets `entraBannerDismissed=true`). Cleared on the next interactive `/auth/entra/start`.
- **Callback** validates `state` by exact-match against `req.session.entraAuthState`; mismatches raise an explicit error rather than silently failing.
- **Session regeneration on callback** — see §6.5. Pre-shared session ids cannot survive the OAuth round trip.
- **Token storage** is session-bound and encrypted: the bearer token is AES-256-GCM-encrypted into `req.session.encryptedEntraAccessToken` with a fresh random IV per encryption. The session is persisted to `data/sessions/<sid>.json` by `session-file-store`, so the encrypted token does land on disk, but ciphertext-only (plaintext never touches disk). Filesystem permissions should protect the data directory (the portal does not chmod session files; it relies on the data-directory's POSIX mode). The cookie carrying the sid is `httpOnly`+`secure`+`sameSite=lax` so the encrypted token is never reachable from page JS even if XSS were somehow achieved. On every outbound Graph call, the token is decrypted from the session for the duration of that single request and then garbage-collected.
- **No refresh tokens.** When Graph returns 401, the calling repository surfaces the error and the user is asked to re-authenticate. This trades convenience for a smaller breach-recovery surface — there is no long-lived credential the portal must invalidate when an account is compromised.
- **All admin-initiated test requests** (`/admin/settings/test-entra`, `/admin/settings/test-mail`, `/admin/health`) carry `AbortSignal.timeout(5000)` on every outbound `fetch` so a slow or hostile remote can't pin a request handler indefinitely.
- **Scope cross-check** — the Health tab and runtime guards read `entra.allowMemberWrites` together with the configured `scope` and report a Warning when writes are allowed but the scope lacks `GroupMember.ReadWrite.All`.

### 6.13 AD cache credential awareness

[`CachedAdRepository`](src/infrastructure/ad/cached-ad-repository.ts) implements a 60-second TTL + LRU-bounded (default 500 entries) cache for `findManagedGroups`. The cache key is now `(userDn|userUpn|samAccountName || includeNested || limit || credentialHash)` where `credentialHash` is the first 8 bytes of SHA-256(`credentials.username`). This prevents cross-user cache poisoning: if two users query with the same `(user, includeNested, limit)` but different credentials (e.g., after credential rotation), each gets the correct result without stale data contamination. Cache invalidation fires on `addGroupMember` / `removeGroupMember` so the target user's ownership listing reflects the change immediately.

### 6.14 Entra repository instance caching

[`ConfigurableEntraDirectoryRepository`](src/infrastructure/entra/configurable-entra-directory-repository.ts) now caches the resolved `EntraDirectoryGraphRepository` instance keyed by the settings tuple it cares about (tenantId, clientId, scope, redirectUri, clientSecret). When settings are changed via the admin UI, the old instance is discarded and a fresh one is created on the next call. This mirrors the [`ConfigurableAdRepository`](src/infrastructure/ad/configurable-ad-repository.ts) pattern: avoiding per-call repository creation lets the LDAP connection pool (and soon, HTTP/2 connection reuse for Graph) actually persist across method calls instead of being reset every request.

### 6.15 OData filter injection prevention

[`EntraDirectoryGraphRepository.searchUsers`](src/infrastructure/entra/entra-directory-repository.ts) validates the search query against the allowlist pattern `/^[a-zA-Z0-9.@_ -]*$/` before embedding it in a `$filter` string. Queries containing injection characters (parentheses, keywords like `or`) are silently rejected with an empty result set rather than passed to Graph, preventing OData injection attacks.

### 6.16 Login lockout cleanup

[`LoginLockoutStore`](src/application/login-lockout.ts) now includes periodic cleanup via `startCleanupInterval()` / `stopCleanupInterval()`. The interval (every 5 minutes) removes entries whose 15-minute lockout window has elapsed. This is wired into the server lifecycle: `startCleanupInterval()` is called after `server.listen()` succeeds, and `stopCleanupInterval()` is called during graceful shutdown. Prevents unbounded memory growth during username enumeration attacks on a long-running instance.

### 6.17 Flash parameter sanitization

[`groups-routes.ts`](src/web/routes/groups-routes.ts) now validates flash messages against the pattern `/^[a-zA-Z0-9 ,+\-]*$/` before rendering them in EJS templates. This prevents HTML/script injection via the flash query parameter. Flash values are sanitized via a `sanitizeFlash()` helper and any non-matching values are silently discarded.

### 6.18 Audit logging

[`HostedAuditRepository`](src/infrastructure/audit/hosted-audit-repository.ts) writes `JSON.stringify(record) + "\n"` to a daily-rolled NDJSON file under the configured audit directory, serialised through a single-flight write queue so concurrent membership changes never race on the chain. Records carry:

- `id` (UUIDv4), `timestampUtc` (ISO-8601), `correlationId`.
- `actorUpn` and `actorSamAccountName` — extracted from the authenticated user.
- `action`, `status`, `source` (`ad` | `entra`), and `targetGroupDn`/`targetMemberDn` where applicable.
- `details` — short free-text suffix.
- **`seq`** — 1-based sequence number within the daily file.
- **`hmac`** — HMAC-SHA256(`prevHmac || "\n" || canonicalJson(recordWithoutHmac)`), hex-encoded. The HMAC key is derived from `CREDENTIAL_ENCRYPTION_KEY` via HKDF with a fixed audit label (no extra secret to manage).

**Integrity verifier.** Running `npm run verify-audit [--quiet] [<directory>]` (entry point: [src/cli/verify-audit.ts](src/cli/verify-audit.ts)) replays each daily file's chain and exits non-zero on any gap in `seq`, missing or mismatched `hmac`, modification, or write under a rotated key. Designed for cron / CI integrity checks.

When `audit.syslogEnabled` is on, the same record is forwarded to the configured syslog endpoint over UDP4 or UDP6 in RFC 3164 format. Failures of the network forwarder do not block the file write.

**Admin viewer.** `GET /admin/audit` renders a filterable table (date range default last 7 days, actor, action, source, group, status, limit). `GET /admin/audit.csv` streams the same query as CSV. Both routes are admin-only, rate-limited (see §6.10), and are surfaced in the header nav only when `audit.enabled` is on so deep-links return 404 otherwise.

The generic `error` view never renders stack traces. In **production** (`NODE_ENV=production`) it shows a static "An unexpected error occurred." string with the `correlationId` so an operator can correlate a UI complaint with a log entry; the original `err.message` is logged server-side but never reaches the browser. In development the original message is rendered to keep the inner loop fast. Service / route code can throw `HttpError` ([src/domain/http-error.ts](src/domain/http-error.ts)) for known 4xx outcomes — the `publicMessage` is intentionally exposed to the user, in JSON or HTML depending on `Accept`.

### 6.19 HTTP response headers

`helmet()` ships sensible defaults (X-Content-Type-Options nosniff, X-Frame-Options SAMEORIGIN, Referrer-Policy no-referrer, etc.). Two directives are explicitly tuned for this app:

- **`form-action`** is set to `'self' https://login.microsoftonline.com https://login.live.com` so the Entra OAuth redirect chain validates. `form-action` is enforced across the entire redirect chain, not just the immediate POST target — without the explicit Microsoft entries, posting the login form would fail CSP when it later 302'd to `login.microsoftonline.com`.
- **HSTS** (`Strict-Transport-Security`, one-year `max-age`, `includeSubDomains`) and **`upgrade-insecure-requests`** are sent only in production. A cached HSTS entry on `localhost` would otherwise silently upgrade dev HTTP traffic to HTTPS and cause spurious CSP `form-action` violations even after the cache was cleared by re-issuing the headers.

Two additional response-header rules are applied as small custom middleware:

- **`Permissions-Policy`** denies every browser feature the portal doesn't use (camera, microphone, geolocation, USB, payment, accelerometer, fullscreen-from-non-self, etc.). Belt-and-braces with CSP `script-src 'self'` against a content-injected script trying to access sensitive hardware APIs.
- **`Cache-Control: no-store`** (plus `Pragma: no-cache`) on every `/auth/*`, `/groups`, `/groups/*`, and `/admin/*` HTML response. Stops authenticated content from sitting in browser, proxy, or CDN caches; static assets under `public/` are unaffected.

Cookies set by the app are `httpOnly`+`secure` (production) and `sameSite=lax`.

The `__Host-` cookie name prefix used for the CSRF token in production enforces that the cookie was set with `Secure`, no `Domain`, and `Path=/` — browsers reject cookies that fail those constraints, so a man-in-the-middle CDN can't downgrade or scope-broaden the token.

### 6.20 Branding logo

User-supplied images touch two surfaces:

1. **Client side (browser)** validates MIME type and **raw file size ≤ 1.5 MB** before the file is read; oversize/unsupported files trigger an inline red error and the `<input type="file">` is reset so the user can compress and retry.
2. **Server side** validates the resulting data URL against the same MIME allow-list (`png|jpeg|jpg|gif|webp|svg+xml`) and rejects anything over **2 MB encoded**. On rejection the user is redirected back with `flashKind=error`, which the EJS layer renders in the red `.alert.error` style rather than the green success style.

The body parser limit is 4 MB, so a 2 MB encoded payload always reaches the route — there is no path where the parser silently 413s before validation runs.

### 6.21 Insecure-option visibility

When an admin enables any of:

- AD `tlsRejectUnauthorized = false`,
- SMTP `ignoreTls = true`,
- SMTP `allowUntrustedTls = true`,
- SMTP `requireAuth = false` while mail is enabled,

a yellow warning banner appears at the top of every Admin Settings page listing the active risks. The toggles still work — this is a visibility control, not a hard block, because lab/QA scenarios sometimes legitimately need them.

### 6.20 Defense-in-depth summary

If an attacker controls one of the following, what's the worst case?

| Compromised asset | Exposure | Mitigation |
| --- | --- | --- |
| Browser cookie jar | Active session until logout/expiry. | `httpOnly` + `secure` + `sameSite=lax`; CSRF binds tokens to session id; logout regenerates. |
| `portal-settings.json` (read-only) | Configuration is visible; secrets remain ciphertext. | AES-256-GCM with `enc:v1:` marker; no plaintext on disk after first save. |
| `portal-settings.json` (read-write) | Attacker can disable AD/Entra, swap delegated-admin lists, etc. | Admin-only writes via `/admin/settings/*`; production preflight refuses default keys. Audit log captures admin actions. |
| `audit/*.ndjson` | Past membership-change history is visible. | Records intentionally avoid storing passwords/tokens; UPNs only. |
| Memory dump of running process | Active session creds (decrypted briefly during LDAP ops) and Entra tokens. | Per-session encryption defeats raw store dumps; access tokens not persisted. |
| `CREDENTIAL_ENCRYPTION_KEY` only | Cannot decrypt without the file too. | Key required for *all* secret/session decryption. |
| Both the file and the key | Full secret recovery for stored secrets. | This is by design — the key is the trust anchor; rotate it via the operator workflow described below. |

### 6.21 Key rotation

Both kinds of ciphertext (settings secrets and session credentials) embed a 12-byte random IV per encryption, so re-saving the settings file after rotating `CREDENTIAL_ENCRYPTION_KEY` rewrites everything with the new key. Recommended rotation procedure:

1. Bring the portal down.
2. Decrypt secrets manually (or programmatically) with the *old* key, replace the env var with the new key, restart.
3. Open Admin Settings, re-enter Entra/SMTP/web-TLS secrets, save. The settings file is rewritten with new ciphertext.
4. Existing user sessions become unreadable (the encrypted credential payload no longer decrypts) and users will be prompted to re-authenticate — this is intentional and matches the security posture of "sessions tied to the encryption epoch".

---

## 7. Observability

- **`/healthz`** is a public, unauthenticated liveness probe (`{ ok: true, uptimeSeconds }`) for load balancers, Docker `HEALTHCHECK`, Kubernetes readiness probes, and uptime monitors. Returns no internal detail.
- **Structured logs** via `winston` (JSON to stdout). The `requestLogger` middleware emits one `http` event per request at response-finish containing method, path, status, duration, content length, correlation id, client IP, actor sAM, and user-agent. Every other log line carries the correlation id when it originates from a request. Set `LOG_DIR` to also write a daily-rotated file transport (20 MB / 14 days / gzipped, via `winston-daily-rotate-file`) alongside stdout — use this for bare-metal installs; containerised deployments should leave it unset and let the platform handle rotation.
- **Startup log** includes `nodeEnv`, `adProvider`, `entraProvider`, and `mockEntraCallbackEnabled` so an operator can confirm wiring at a glance.
- **Audit log** as described above; integrity verifier via `npm run verify-audit`; long-term retention via syslog forwarding to a SIEM.
- **In-process metrics** in [`src/infrastructure/metrics.ts`](src/infrastructure/metrics.ts): a 200-sample latency tracker for the `/groups` initial render. Exposed at `GET /admin/health` and rendered in the Health Status tab as count / avg / p50 / p95 / min / max / last-sample timestamp.
- **`GET /admin/health`** (admin-only) runs five probes — application self-check, AD DNS+TCP, Entra metadata + Graph `/me`, mail config completeness, latency stats — and returns a JSON snapshot. All probes are best-effort with 4–5 s timeouts and capture failure messages instead of throwing.
- **Graceful shutdown.** SIGTERM / SIGINT trigger a drain window (30 s in production, 10 s in dev): new connections are refused, in-flight requests finish, the pooled LDAP connections drain, the HTTP listener closes, and the process exits cleanly. A second signal short-circuits to immediate exit (so a stuck request can never block a container restart). `docker-compose.yml` sets `stop_grace_period: 35s` to match.
- **Per-account login lockout** ([`src/application/login-lockout.ts`](src/application/login-lockout.ts)) tracks consecutive failures in memory and locks an account for 15 minutes after 5 attempts, independent of source IP. The IP-based rate limiter stops one machine grinding through guesses; the lockout stops anyone grinding through guesses against a single account. Restart clears all lockout state (intentional) — a process crash should not permanently lock out users.

---

## 8. Testing

- **Unit tests** ([tests/unit](tests/unit)) target service boundaries with the mock AD/Entra repositories. They exercise mixed AD+Entra group listings, the Entra dispatcher (`allowMemberWrites` off, no token, owner check, idempotency, mismatched references) and basic settings-service shape. `MockAdRepository` ships under `src/` because it is also the production AD-disabled fallback; `MockEntraDirectoryRepository` lives under [tests/fixtures](tests/fixtures) so it can never accidentally be wired into the composition root.
- **Integration tests** ([tests/integration](tests/integration)) spin up a minimal Express app and verify routing surfaces. LDAP and Graph are not exercised end-to-end in CI — those rely on the mock repos because real directories are environment-specific.
- Run `npm.cmd test` to execute the suite via `vitest`. `npm.cmd run build` verifies the TypeScript compiles cleanly. `npm.cmd run lint` runs ESLint (flat config v9) over `src/` and `tests/`; the `.githooks/pre-commit` hook (enable per-clone with `git config core.hooksPath .githooks`) runs Prettier + ESLint on staged files.
- **Deferred**: a Playwright end-to-end smoke test is the only outstanding productionisation item (browser binaries are heavy, so it's scoped as a standalone follow-up).

---

## 9. Where to look for what

| Concern | Primary file(s) |
| --- | --- |
| Express wiring, middleware order, TLS bootstrap, shutdown | [src/server.ts](src/server.ts) |
| Single-instance enforcement (PID lockfile) | [src/infrastructure/single-instance-lock.ts](src/infrastructure/single-instance-lock.ts) |
| Atomic file writes (tmp + fsync + rename) | [src/infrastructure/atomic-write.ts](src/infrastructure/atomic-write.ts) |
| Typed HTTP error class for 4xx mapping | [src/domain/http-error.ts](src/domain/http-error.ts) |
| Auth + session pinning + login/logout + sign-out-others | [src/web/routes/auth-routes.ts](src/web/routes/auth-routes.ts), [src/web/auth-middleware.ts](src/web/auth-middleware.ts) |
| Group list / member CRUD HTTP surface + batched member-count | [src/web/routes/groups-routes.ts](src/web/routes/groups-routes.ts) |
| Admin settings + audit viewer + setup wizard + health probe | [src/web/routes/admin-routes.ts](src/web/routes/admin-routes.ts) |
| Group dispatcher (AD vs Entra), audit emission | [src/application/group-management-service.ts](src/application/group-management-service.ts) |
| LDAP client / TLS config / pre-flight / connection pool | [src/infrastructure/ad/ldap-ad-repository.ts](src/infrastructure/ad/ldap-ad-repository.ts) |
| Microsoft Graph adapter | [src/infrastructure/entra/entra-directory-repository.ts](src/infrastructure/entra/entra-directory-repository.ts) |
| Settings file + secret encryption | [src/infrastructure/settings/file-portal-settings-repository.ts](src/infrastructure/settings/file-portal-settings-repository.ts), [src/infrastructure/security/secrets-cipher.ts](src/infrastructure/security/secrets-cipher.ts) |
| Per-session credential cipher | [src/infrastructure/security/session-crypto.ts](src/infrastructure/security/session-crypto.ts), [src/web/session-directory-credentials.ts](src/web/session-directory-credentials.ts) |
| Audit writer + syslog forwarder + HMAC chain | [src/infrastructure/audit/hosted-audit-repository.ts](src/infrastructure/audit/hosted-audit-repository.ts), [src/infrastructure/audit/audit-chain.ts](src/infrastructure/audit/audit-chain.ts) |
| Audit verifier CLI | [src/cli/verify-audit.ts](src/cli/verify-audit.ts) (`npm run verify-audit`) |
| Login history + active-sessions reconciliation | [src/infrastructure/login-history.ts](src/infrastructure/login-history.ts) |
| Per-account login lockout | [src/application/login-lockout.ts](src/application/login-lockout.ts) |
| Portal-admin authorisation (cached + parallel) | [src/application/portal-admin-authorization-service.ts](src/application/portal-admin-authorization-service.ts) |
| Logger (stdout + optional LOG_DIR rotation) | [src/infrastructure/logger.ts](src/infrastructure/logger.ts) |
| Health metrics | [src/infrastructure/metrics.ts](src/infrastructure/metrics.ts) |
| Production preflight | [src/config/env.ts](src/config/env.ts) |
