# Changelog

All notable changes to the Group Self Service Portal are recorded here.
Dates use `YYYY-MM-DD`. This project follows the spirit of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) but does not yet
guarantee a strict version scheme.

## [Unreleased]

### Performance and operations updates
- **Settings reads no longer perform PBKDF2 in normal request paths.**
  `PortalSettingsService` now separates first-run credential initialization
  from merge-default reads, so routine settings access avoids expensive
  password-hash work.
- **Settings repository now has a short in-memory cache.**
  `FilePortalSettingsRepository` keeps a defensive-cloned 5-second TTL cache,
  refreshes on save, and emits hit/miss telemetry for `/admin/health`.
- **Request-scoped settings reuse.**
  Shared settings are now stored on `res.locals.settings` so downstream route
  handlers can reuse one read per request instead of repeating repository I/O.
- **Batched member-count endpoint now uses bounded concurrency.**
  `/groups/members/counts` runs with a fixed worker pool to prevent bursty
  directory fan-out from saturating the event loop on constrained CPU.
- **Static assets now ship with long-lived immutable caching headers.**
  Versioned asset URLs (`?v=<stamp>`) plus `Cache-Control: max-age=1y,
  immutable` remove repeat-download overhead across navigations.
- **Session-store reap cadence reduced from 15 minutes to 60 minutes.**
  Reduces metadata churn on network filesystems (for example EFS/NFS) while
  retaining TTL enforcement on read.
- **Single-instance lock acquisition is now atomic.**
  Startup lock uses `O_EXCL` semantics (`wx`) to avoid dual-claim races on
  network storage during concurrent starts.
- **`/healthz` moved to an early fast path and returns 204.**
  Liveness probes now bypass session/CSRF/settings middleware and return
  `204 No Content` with no body, minimizing probe overhead.

### Security — LDAP pool key no longer derived from password
- **Pool identity decoupled from credentials.** `LdapAdRepository` now identifies connection-pool buckets via an opaque `poolToken` — a `randomUUID()` generated at login and stored inside the AES-256-GCM-encrypted `encryptedDirectoryCredentials` session payload. The previous HMAC-SHA256 / scrypt derivation from the user's password has been removed entirely: pool-map keys contain no password material and can reveal nothing about credentials if a process memory snapshot is captured. `poolToken` is a new field on `DirectorySessionCredentials` in [src/application/contracts.ts](src/application/contracts.ts) and travels through the same encrypted session path as `username` and `password`; no extra secrets, storage, or configuration are required. `poolKey()` in [src/infrastructure/ad/ldap-ad-repository.ts](src/infrastructure/ad/ldap-ad-repository.ts) is now a synchronous O(1) string concatenation.

### Security — medium-severity hardening pass (M1-M6 findings)
- **M1: Entra access tokens encrypted at rest.** Access tokens (short-lived, ~1-hour expiry) are now AES-256-GCM-encrypted into `req.session.encryptedEntraAccessToken` using the same cipher as session AD credentials. Tokens are decrypted only for the duration of the Graph API call and immediately garbage-collected. A session-store dump yields ciphertext only. New helpers `encryptEntraAccessToken()` / `decryptEntraAccessToken()` in [src/infrastructure/security/session-crypto.ts](src/infrastructure/security/session-crypto.ts); accessor functions in [src/web/session-directory-credentials.ts](src/web/session-directory-credentials.ts).
- **M2: Login lockout cleanup prevents unbounded growth.** New `startCleanupInterval()` / `stopCleanupInterval()` functions in [src/application/login-lockout.ts](src/application/login-lockout.ts) sweep expired lockout entries every 5 minutes. Integrated into server startup and graceful shutdown in [src/server.ts](src/server.ts). Stops the per-account lockout map from growing unbounded during username enumeration attacks.
- **M3: AD cache includes credential hash in key.** [CachedAdRepository.keyForUser()](src/infrastructure/ad/cached-ad-repository.ts) now includes a SHA-256 hash of `credentials.username` in the cache key. Prevents cross-user cache poisoning if different users query with the same `(userDn, includeNested, limit)` but different credentials.
- **M4: OData filter injection prevention.** [EntraDirectoryGraphRepository.searchUsers()](src/infrastructure/entra/entra-directory-repository.ts) validates the search query against `/^[a-zA-Z0-9.@_ -]*$/` before embedding in `$filter`. Queries with injection characters (parentheses, keywords) are silently rejected with an empty result.
- **M5: Entra repository instance caching.** [ConfigurableEntraDirectoryRepository](src/infrastructure/entra/configurable-entra-directory-repository.ts) now caches the resolved `EntraDirectoryGraphRepository` instance keyed by settings (tenantId, clientId, scope, redirectUri, clientSecret). Mirrors the ConfigurableAdRepository pattern; prevents per-call instance creation that would reset any connection reuse optimizations.
- **M6: Flash parameter whitelist.** [groups-routes.ts](src/web/routes/groups-routes.ts) now validates flash query parameters against `/^[a-zA-Z0-9 ,+\\-]*$/` before rendering in EJS. Prevents HTML/script injection via the flash parameter. A `sanitizeFlash()` helper is applied to all flash values passed to view context.

### Changed - Entra sign-in flow is now strictly opt-in
- **Primary login no longer depends on Entra session state.** After a
  successful AD (or break-glass) sign-in, users are redirected directly
  to `/groups` every time.
- **Removed automatic post-login Entra redirect.** The previous
  `/auth/entra/start?silent=1` hop after AD login could feel like login
  did not progress when no Microsoft session existed. That automatic hop
  is now removed.
- **Entra connection remains available on demand.** Users connect only by
  explicitly clicking **Connect Entra ID** from the `/groups` banner (or
  admin connect CTA), then complete Microsoft sign-in interactively.
- **Updated user-facing copy** to clarify outcome and capability: users
  are prompted to sign in to Entra ID to **view and manage Entra-owned
  groups**.
- **Capability impact:** AD-only users always land in the app without an
  Entra round-trip; Entra-backed group visibility/management and
  Entra-group-based delegated admin checks activate once the user chooses
  to connect Entra in that session.

### Productionisation pass — closed 2026-06-06
21 of 22 tracker items closed (every 🔴, every 🟡, 7 of 8 🟢).
Deferred to a separate stand-alone task:

- **#18 Playwright e2e smoke test** — wants new test infra (~75 MB browser binaries via `@playwright/test`), a `playwright.config.ts`, a separate `test:e2e` npm script, and a docker-compose-based fixture; large enough to track on its own.

Final verification on close: `npm run build` clean, `npm test` 14/14, `npm run lint` 0 problems.

### Polish — fifth batch (final 🟢 cleanup minus #18 Playwright)
- **Test-only mock relocated.** `MockEntraDirectoryRepository` moved
  from `src/infrastructure/entra/` to `tests/fixtures/` so it cannot
  accidentally be wired into the production composition root. The
  AD-disabled fallback `MockAdRepository` stays under `src/` (it's a
  genuine runtime path, not a test fixture) and now carries a header
  comment making that distinction explicit.
- **Login-history active-sessions reconciliation.** Closing a browser
  tab does not hit `/auth/logout`, so the per-user active-sessions map
  could only grow. New `LoginHistoryStore.reconcileWithStore()` asks
  the session store whether each tracked sid still exists and drops
  the ones that are gone. Called best-effort on every render of
  `/groups` for non-break-glass users so the *"N other active
  sessions"* widget converges back to truth instead of climbing
  forever.
- **Opt-in log rotation.** New `LOG_DIR` env var: when set, the
  structured JSON logs are also written to a daily-rotated file
  (20 MB / 14 days / gzipped) via `winston-daily-rotate-file`. Leave
  it unset for containerised deployments — docker/k8s/journal-d
  already rotate stdout. Documented in the README env-vars table.

### Polish — fourth batch (cleanup of remaining 🟢 items)
- **LRU cap on `CachedAdRepository`.** The ownership cache now uses a
  bounded LRU (default 500 entries, configurable via the constructor
  third arg) with insertion-order touch on hit. Stops the rare scenario
  of unbounded growth in a long-running process — practical impact is
  modest given each entry is one user × a couple of variants, but it's
  free defence-in-depth.
- **`CachedAdRepository.invalidateUser` is now wired** to fire on
  `addGroupMember` / `removeGroupMember`, using the affected
  member's DN. Because `includeNested=true` ownership listings include
  groups owned via the user's group membership, changing membership
  invalidates the target user's `findManagedGroups` cache so their
  next page render reflects the change immediately rather than waiting
  for the 60 s TTL. Added a sibling `invalidateUserDn(dn)` helper for
  callers that only have the DN.
- **Magic `500` / `999` list caps replaced with env-configurable
  values.** New `MAX_GROUPS_PER_LIST` (default 500) and
  `MAX_MEMBERS_PER_GROUP` (default 999) env vars. Both passed through
  the `GroupManagementService` constructor; defaults preserve previous
  behaviour. Documented in README env-vars table.
- **Production graceful-shutdown grace extended to 30 s.** A SIGTERM
  in production now gives in-flight LDAP binds (which can take
  10-20 s against a slow DC) time to finish before the forced exit.
  Dev keeps the 10 s window for snappy tsx-watch reloads. Compose
  `stop_grace_period` bumped to 35 s to match.

### Security — productionisation hardening (third batch — all 🟡 closed)
- **Atomic settings + login-history writes.** New
  `infrastructure/atomic-write.ts` helper writes to a sibling tmp file in
  the same directory, fsyncs, then renames over the destination. Used by
  `FilePortalSettingsRepository.save()` and `LoginHistoryStore.persist()`.
  A crash, container kill, or power-cut between truncate and final flush
  can no longer leave the file zero-length. As a paired fix, the settings
  reader now **refuses to silently overwrite a present-but-empty or
  present-but-invalid file with defaults**; the operator is logged the
  exact path and asked to restore from backup. The previous behaviour
  silently rotated the break-glass admin password whenever the file was
  unreadable for any reason.
- **Stricter `CREDENTIAL_ENCRYPTION_KEY` validator in production.** The
  startup check now requires the key to decode as exactly 32 bytes of
  base64 (a true AES-256 key) when `NODE_ENV === "production"`. A short
  passphrase still works in dev (it's hashed to 32 bytes), but production
  refuses to start. Error message includes the exact one-liner to
  generate a compliant key with `crypto.randomBytes(32).toString('base64')`.
- **Rate limits on audit + member-count endpoints.** `GET/POST
  /groups/members/count[s]` are capped at 60 req/min/IP, `GET
  /admin/audit` and `/admin/audit.csv` at 30 req/min/IP. Stops an
  authenticated misbehaving client (or a curious browser tab) from
  hammering disk-bound or directory-bound endpoints.
- **Portal-admin check is now cached + parallel.** Per-session 60-second
  TTL cache invalidates when the Entra access token changes; AD and
  Entra group lookups now run in parallel via `Promise.any` and
  short-circuit on the first match. Removes the N×M sequential lookup
  every /admin/* page used to incur.
- **Typed `HttpError` class** at `src/domain/http-error.ts`. Service /
  route code can throw `HttpError.notFound("…")`,
  `HttpError.forbidden("…")`, `HttpError.badRequest("…")` etc. The
  global error handler now maps these to the right status with the
  `publicMessage` intentionally exposed to the user. JSON-preferred
  clients receive `{ok:false, message, code}` instead of an HTML error
  page. Plain `Error` still surfaces as a sanitised 500 in production.
- **Batched member-count endpoint.** New `POST /groups/members/counts`
  takes `{groupDns: string[]}` (max 100) and returns
  `{results: [{groupDn, count?, cached?, error?}]}`. The groups-list
  page now fetches every visible row's count in **one** round-trip
  instead of one-per-row. Server-side cache and per-DN authorisation
  are unchanged; the existing single-DN `GET /count` is still wired up
  for backward compatibility and admin pages.
- **LDAP connection pool.** `LdapAdRepository` now keeps a bounded
  per-credential pool of bound clients (4 idle per key, 5-minute idle
  TTL, periodic sweeper). Pool keys are HMAC'd against a per-process
  random salt so a memory dump can't reverse them offline. `withClient`
  acquires and releases through the pool; an operation that throws
  discards the client instead of returning it. Drained on graceful
  shutdown via a new `closePool()` pass-through that bubbles up through
  `ConfigurableAdRepository` and `CachedAdRepository`.
  `ConfigurableAdRepository` also now caches the resolved
  `LdapAdRepository` instance keyed by the settings tuple it cares
  about, so the pool actually persists across calls instead of being
  reset every request; closes the old pool when admin-changed settings
  invalidate the cached instance.
- **Audit log HMAC chain + verifier CLI.** Every audit record now
  carries `seq` (1-based, per daily file) and `hmac`
  (HMAC-SHA256 of `prevHmac || canonicalJson(record)`, key derived from
  `CREDENTIAL_ENCRYPTION_KEY` via HKDF with a fixed label). A new
  `npm run verify-audit [--quiet] [<directory>]` script replays each
  daily file's chain and exits non-zero on any gap, missing seq/hmac,
  modification, or write under a rotated key. Designed for cron /
  CI integrity checks. The single-flight write queue is now also used
  to serialise audit writes within the process so concurrent
  membership changes never produce a broken chain. **Note:** audit
  files written before this batch will not verify (they predate the
  chain fields); the verifier reports this exactly so an operator can
  decide whether to archive and start fresh.

### Security — productionisation hardening
- **`/auth/entra/mock-callback` is now gated by `NODE_ENV`.** The route is
  only registered when `NODE_ENV !== "production"`. In production a stub
  handler returns `404 Not Found` so a stray bookmark or scanner never even
  reaches a routing fall-through. The route exists so
  `MockEntraDirectoryRepository` can complete a fake OAuth round-trip during
  dev/test; leaving it mounted in production turned a misconfigured wiring
  swap (real → mock repo) into an authenticated front door because anyone
  could obtain `entraAccessToken="mock-entra-token"` and bypass any
  Entra-backed admin checks. Startup log now includes
  `mockEntraCallbackEnabled` so an operator can confirm the route's status
  at a glance.
- **Sessions persist across restart.** Replaced the in-memory
  `express-session` store with `session-file-store` (pure-JS, no native
  modules). One JSON file per session id is written to `data/sessions/`
  with the session TTL applied; expired files are reaped every 15 minutes.
  Result: a tsx-watch reload, a docker restart, or a planned deploy no
  longer signs every active user out, and the "Sign out other sessions"
  feature now works for sessions that outlived a previous process. The
  store directory is already covered by `.gitignore` / `.dockerignore` via
  the existing `data/` rule.
- **Single-instance enforcement (PID lockfile).** A new
  `single-instance-lock.ts` writes `data/.portal.pid` with the running
  process's PID at startup and refuses to boot when another live process
  already owns the file. Stale locks (whose PID is no longer running) are
  silently reclaimed. The lock is released on graceful shutdown. Stops
  the silent failure mode where someone accidentally starts a second
  process against the same data directory and halves the per-account
  login lockout threshold.
- **Documented single-instance constraint** in `README.md` (new
  *Deployment topology* section) and `docker-compose.yml` (comment in the
  service block reminding operators not to scale the service past one
  replica).
- **CSP `script-src 'self'` + `script-src-attr 'none'`** are now pinned
  explicitly. Audit confirmed there are zero inline `<script>` blocks and
  zero inline event handlers in the EJS views — the one remaining
  `onsubmit="return confirm(...)"` on the *Sign out other sessions* form
  was rewritten as a `data-confirm` attribute consumed by a delegated
  listener in `public/groups.js`. New inline scripts must NOT be added;
  convert to data attributes consumed by the existing public bundles.
  `style-src` keeps `'unsafe-inline'` for the per-request theme variables
  and admin theme-preset swatches, which use validated hex values, not
  user content.
- Code comments referring to "multi-instance" replacements have been
  rewritten to make the single-instance contract explicit
  (`login-history.ts`).

### Added — UX polish
- Toast notification system (`/public/toast.js`). All `?flash=…&flashKind=…`
  query-param messages become auto-dismissing toasts; the params are stripped
  from the URL on load so refresh/copy-paste does not re-trigger them.
  Reachable from any client-side script via `window.Portal.toast(message, kind)`.
- Confirm dialog on member removal. The remove button now passes the
  member's display label into a `window.confirm()` prompt.
- Loading spinner + disabled state on every admin **Test Connection** button
  while the probe runs, plus a member-list spinner while the modal loads.
- In-modal **member filter** for the "Current members" list — case-insensitive
  match across name / UPN / sAMAccountName / mail. Hidden until at least one
  member exists.
- Match-highlight (`<mark>`) in the modal search results and member-filter
  list.
- Sort / source / text-filter selections on the groups list persist per
  browser via `localStorage`.

### Added — security polish
- Per-account login lockout. Five consecutive failed sign-ins lock an
  account (case-insensitive UPN/sAM) for 15 minutes regardless of source IP.
  Complements the existing IP-based rate limiter on `/auth/login`. Cleared on
  any successful sign-in. Unit-tested.
- `Permissions-Policy` response header disables every browser feature the
  portal does not use (camera, microphone, geolocation, payment, USB, etc.).
- `Cache-Control: no-store` on every `/auth/*`, `/groups`, `/groups/*`, and
  `/admin/*` HTML response so authenticated pages never sit in a browser or
  proxy cache.

### Added — operational polish
- **Public `/healthz`** liveness probe. Unauthenticated, returns
  `{ ok: true, uptimeSeconds }`. Dockerfile `HEALTHCHECK` now hits this
  instead of `/auth/login`.
- **Graceful shutdown** on SIGTERM / SIGINT. 10-second drain window for
  in-flight requests, then forced exit. A second signal short-circuits the
  drain.
- **Structured JSON request log** (replaces morgan's "combined" format).
  Includes method, path, status, duration, content length, correlation id,
  client IP, actor sAM, and user-agent. Logged at the response-finish event.

### Added — functional polish
- Better authorization error message on AD groups: instead of "You are not
  authorized to manage this group", the portal now resolves the group's
  `managedBy` and tells the user who owns it.

### Added — accessibility polish
- Skip-link at the top of every page ("Skip to main content").
- Visible focus rings via `:focus-visible` for buttons, links, inputs,
  selects, and textareas.
- Tab key trapped inside the member-management modal while open; focus
  returns to the element that opened it when the modal closes.

### Changed
- Removed the legacy in-page `<div class="alert success">` flash blocks from
  `groups.ejs`, `members.ejs`, `admin-settings.ejs`,
  `wizard-entra-directory.ejs`, and `wizard-entra-mail.ejs`. The toast layer
  renders these now.
- Static toast/skip-link/spinner CSS lives in `public/styles.css`; modal
  filter + match highlight + spinner styles live in `public/groups.css`;
  busy-button style in `public/admin-settings.css`.

### Added — code quality
- `npm run test:coverage` shortcut.
- Unit tests for the login-lockout module.

### Added — quick-wins batch (items 1–4 of the outstanding-suggestions list)
- **Backup and restore** operator section in the README: file-level snapshot
  procedure for Docker and bare-metal, restore checklist, DR-test prompt,
  and an explicit "what is *not* in `data/`" callout for
  `CREDENTIAL_ENCRYPTION_KEY` and `SESSION_SECRET`.
- **Cache-busting** on every `<link>`/`<script>` URL: server stamps an
  `ASSET_VERSION` (process start time + random suffix) at startup and
  appends it as `?v=…`. Browsers and shared proxies treat each deploy as a
  fresh URL, eliminating the "I see old CSS after deploy" class of bug.
- **docker-compose healthcheck** mirrors the Dockerfile `HEALTHCHECK` and
  hits `/healthz`; downstream services can now wait on
  `condition: service_healthy`. Also added `stop_grace_period: 15s` so the
  graceful-shutdown drain fits within the orchestrator's stop window.
- **Group favorites + recently-viewed** on the groups list. A per-row star
  pins a group to the top of every sort; clicking *Manage* updates a
  10-deep most-recently-used queue whose top five sit just below favorites.
  Both lists persist per browser via `localStorage`; nothing leaves the
  client.

### Added — second batch (items 5, 7, 9, 13, 14 of outstanding suggestions)
- **Inline member count** on each row of the groups list. The page fires a
  lazy `/groups/members/count` request per visible row, throttled to 4
  concurrent and skipping any DN already counted. The server caches each
  count for 60s per `(user, group)` pair so a burst of renders translates to
  one LDAP/Graph query per group per minute.
- **ESLint v9 (flat config) + Prettier** wired in.
  - `npm run lint` / `npm run lint:fix` / `npm run format` /
    `npm run format:check` scripts.
  - Repo-wide config under `eslint.config.mjs` and `.prettierrc.json`.
  - Pre-commit hook at `.githooks/pre-commit` (enable per clone with
    `git config core.hooksPath .githooks`).
- **Last sign-in display + active sessions + sign-out-other-sessions.**
  - Per-user previous-login record (timestamp + IP + UA) persisted to
    `data/login-history.json` so it survives restarts. Per-user active
    sessions tracked in memory (single-instance only).
  - A subtle strip above the groups table shows "Last sign-in: …" and
    "N other active sessions" with a "Sign them out" form button.
  - `POST /auth/sign-out-others` enumerates the user's sessions, asks the
    session store to destroy every sid except the current one, removes them
    from the active-session index, and bounces back to `/groups` with a
    toast.
  - Break-glass account is intentionally hidden from this widget.
- **Audit log viewer + CSV export** at `/admin/audit`.
  - Filters: date range (defaults to last 7 days), actor substring, action,
    source, group DN substring, status, page-size cap (UI 1k, CSV 10k).
  - Reads daily NDJSON files in reverse so newest records surface first.
  - "Audit Log" link surfaced in the global header when the user is a
    portal admin.
- **First-run wizard** at `/admin/setup`.
  - Break-glass admin login while both AD and Entra are disabled now lands
    on this page instead of the raw settings tabs.
  - Three guided steps: rotate break-glass password, connect a directory,
    delegate ongoing admin rights. Each step links straight to the relevant
    settings tab or wizard.
  - Once either integration is enabled the page redirects to
    `/admin/settings` automatically.

## Earlier history

Earlier work (initial AD + Entra integration, Health Status tab, Entra member
self-service, silent SSO with Connect-banner fallback, group display filter,
group-type column, security batch fixes, etc.) is captured in the README
*Feature coverage* section and in commit history.
