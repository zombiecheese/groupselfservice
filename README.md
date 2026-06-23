# Group Self Service Portal

Web-based self-service group management portal that combines ownership visibility from on-prem Active Directory and Microsoft Entra ID. Owners (`managedBy` in AD, group owners in Entra) can view membership and add/remove members for the groups they own — and only those — without giving them broad directory rights.

## Documentation

- **[INSTALLATION.md](INSTALLATION.md)** — production-secret generation, environment variables, local dev, build/test, deployment (Docker, reverse proxy, systemd), security checklist, and backup/restore.
- **[TECHNICAL.md](TECHNICAL.md)** — architectural and security deep-dive.
- **[CHANGELOG.md](CHANGELOG.md)** — release history.

## Feature coverage
 
### Authentication & access control
- Forms login with username + password against Active Directory (per-user LDAP bind — no shared service account).
- Login form copy adapts to deployment state: a *"No directory integration is configured yet"* hint appears only when both AD and Entra are disabled (first-run / fresh install).
- Optional Entra ID sign-in via OAuth2 Authorization Code + PKCE (supports MFA / Conditional Access). AD login always completes directly to `/groups`; Entra sign-in is user-initiated from the non-blocking *Connect Entra ID* banner (or admin connect CTA) when users want Entra-backed visibility and management.
- Break-glass admin account provisioned on first start; rotate password from Admin Settings &rarr; **Security**. The PBKDF2 hash uses 600 000 SHA-256 iterations (OWASP 2023); legacy 120 000-iteration hashes are transparently re-hashed on next successful sign-in.
- Delegated portal-admin rights granted via configured AD groups (DN list) and/or Entra group IDs (Security tab).
- Session regeneration on AD login, Entra callback, and logout to defeat session fixation; login GET self-heals stale CSRF cookies.
- Rate limiting on `/auth/login` (10 attempts / 15 min, successful logins not counted) and `/groups/search` (30 / min). Honors the `TRUST_PROXY` environment variable when running behind a reverse proxy.
- **Per-account lockout**: five consecutive failed sign-ins lock the account (case-insensitive, source-IP-independent) for 15 minutes regardless of the IP rate limit. Cleared on the next successful sign-in.

### Group ownership & membership
- Lists AD groups where the signed-in user is `managedBy` directly.
- Resolves nested AD ownership: when `managedBy` references an owner group and the user is a member of that group, the owned groups are listed too.
- Lists Entra groups the user owns (via Microsoft Graph).
- View members of an owned group (AD or Entra).
- Add or remove a single member by DN or `sAMAccountName`/UPN search (AD), or by name/UPN/email search against the tenant directory (Entra, opt-in).
- Bulk add / remove by reference list with per-line validation (`CN=...,DC=...` for AD; `entra-user:{guid}` for Entra).
- Sortable, filterable groups list with text filter, source filter (AD/Entra), and sort by name/source/type/ownership.
- **Type column** decodes each group's classification: AD shows `Security (Global)`, `Distribution (Universal)`, etc.; Entra shows `Microsoft 365`, `Security`, `Mail-enabled Security`, `Distribution`, optionally suffixed with `· Dynamic` for dynamic-membership groups.
- **Group display filter** (admin-configurable) hides selected group types from end users so, e.g., distribution lists managed elsewhere stay out of view. Audit records still capture the full count plus how many were hidden.
- Export current membership as CSV (DN for AD members, opaque ref for Entra).
- Search principals (users) in AD with rate-limited wildcard support; per-group source-aware search switches automatically when managing an Entra group.

### Admin settings (UI-driven, persisted to disk)
- AD integration: LDAP URL, base DN, nested-managedBy resolution toggle, custom CA PEM, server-name override, allow-untrusted TLS toggle (with explicit insecure banner), IPv4-only toggle.
- Entra integration: tenant ID, client ID/secret, scopes, redirect URI, **opt-in member-write toggle** for cloud groups; an in-page wizard helps populate it.
- Mail integration: SMTP (port 25 / 465 / 587, optional auth, STARTTLS toggles, allow-untrusted-TLS toggle) **or** Entra Graph send-as; in-page wizard for both.
- Notifications: opt-in member-added / member-removed emails to the affected user, with editable subject + body templates and `%groupname%`, `%targetuser%`, `%performedby%`, `%domain%` placeholders.
- Auditing: NDJSON file path, retention days, optional syslog forwarding (UDP4/UDP6, host, port, app name).
- Delegated-admin group pickers: search-as-you-type for AD and Entra groups, click to add, × to remove — no DN copy-pasting. Break-glass admins (no LDAP credentials) get a manual-DN input instead of the live picker.
- Branding: site name, header title, and an optional header logo (PNG, JPG, GIF, WebP, or SVG; max 1.5 MB raw / 2 MB encoded). Oversized or unsupported uploads surface an inline error before the form is even submitted; the server enforces the same limit and reports it via a red flash on the General tab.
- Native web TLS: optional HTTPS listener with admin-imported PEM certificate, private key, and optional passphrase under General settings, plus an optional plain-HTTP redirect listener.
- Theme: light / dark / auto color mode plus a two-color palette (primary + secondary) with eight presets and color pickers. Dark mode is neutral grey; accents follow the chosen palette.
- "Test connection" buttons for AD, Entra and mail before saving each section.
- **Health Status tab**: live status cards for the application (uptime, Node version, heap, RSS), Active Directory (DNS + TCP probe), Entra ID (tenant metadata + delegated-token Graph `/me` check + scope/write-flag cross-check), mail configuration completeness, and a performance card with min / avg / median / p95 / max latency for the initial groups-list render. Probes are best-effort with short timeouts and never throw.
- **About tab**: tool description, version, author, license, and links to the source repository and issue tracker.

### Security baseline
- CSRF protection via the double-submit cookie pattern (`csrf-csrf`); token is bound to the session id.
- Helmet HTTP headers. CSP `form-action` is restricted to `'self'` plus `https://login.microsoftonline.com` and `https://login.live.com` to support the Entra OAuth round trip without weakening other directives. HSTS (one-year `max-age`) is sent only in production; `upgrade-insecure-requests` is also production-only so plain-HTTP dev doesn't get caught in a forced-HTTPS loop.
- `Permissions-Policy` response header denies camera, microphone, geolocation, payment, USB, and every other browser feature the portal does not use.
- `Cache-Control: no-store` on every `/auth/*`, `/groups`, `/groups/*`, and `/admin/*` HTML response so authenticated pages never sit in a browser or proxy cache.
- HTTPS-only cookies in production (`httpOnly`, `sameSite=lax`, `Secure`).
- Native web-server TLS material can be stored in portal settings; the private key and optional passphrase are encrypted on disk.
- Per-session LDAP credentials encrypted at rest (AES-256-GCM) using `CREDENTIAL_ENCRYPTION_KEY` so a session-store dump never leaks plaintext passwords.
- Settings-file secrets (Entra client secret, SMTP password, mail-Entra client secret, web-TLS key + passphrase) encrypted on disk with the same key (marker `enc:v1:`). Settings and audit files are chmod'd to `0o600` on POSIX after each write; no-op on Windows.
- **Atomic settings + login-history writes** (tmp file + fsync + rename) so a crash or power-cut between truncate and final flush never produces a zero-byte file; the reader refuses to overwrite an empty or invalid file with defaults.
- Production startup refuses placeholder `SESSION_SECRET` / `CREDENTIAL_ENCRYPTION_KEY`, and in production `CREDENTIAL_ENCRYPTION_KEY` must decode as exactly 32 bytes of base64 (a true AES-256 key).
- **Strict CSP**: `script-src 'self'`, `script-src-attr 'none'` (no inline `<script>` or `onclick=` allowed); `form-action` scoped to `'self'` plus the Microsoft OAuth endpoints; HSTS + `upgrade-insecure-requests` in production only.
- **Per-account login lockout** (5 fails / 15 min, source-IP-independent) complements the IP-based `/auth/login` rate limit. **Rate limits** on `/groups/search` (30/min/IP), `/groups/members/count[s]` (60/min/IP), and `/admin/audit*` (30/min/IP).
- **Single-instance enforcement**: PID lockfile at `data/.portal.pid` refuses to start a second process against the same data directory.
- **Dev-only `/auth/entra/mock-callback`** route is removed in production (404 stub returned for any caller); the wired Entra repo is the real Graph client.
- DN regex validation on every group/member input; LDAP URL must parse as `ldap://`/`ldaps://`; Entra redirect URI must be `https://` (or `http://localhost` for dev); audit `filePath` rejects control characters and `..` traversal.
- **Typed `HttpError`** lets service code throw `HttpError.forbidden(...)` / `notFound(...)` etc. with an explicitly user-safe message; the global handler maps these to the right 4xx with JSON-or-HTML negotiation.
- Insecure-transport warning banner shown when AD or SMTP TLS is relaxed.
- Generic 500 errors in production never echo `err.message` to the browser — only the correlation id is shown; full message stays in the server log.

### Auditing
- Every membership change is written as NDJSON under the configured audit path.
- Each event includes: `Id`, `TimestampUtc`, `ActorUpn`, `ActorSam`, `CorrelationId`, `Action`, `Source` (`ad` or `entra`), `TargetGroupDn`, `TargetMemberDn`, `Status`, `Details`.
- **Hash-chained integrity**: each record also carries `seq` (1-based per daily file) and `hmac` = HMAC-SHA256(prevHmac || canonicalJson). The HMAC key is derived from `CREDENTIAL_ENCRYPTION_KEY` via HKDF, so no extra secret to manage. `npm run verify-audit` replays every chain and exits non-zero on any insertion, deletion, modification, or key-rotation break.
- **Admin Audit Log viewer** at `/admin/audit` with filter form (date range, actor, action, source, group, status, limit). Same filters drive a CSV export.
- Retention is enforced by the configured retention-days value.
- Optional syslog forwarding (RFC 3164) for SIEM ingestion.

### Observability
- `/healthz` is a **public** liveness probe that returns HTTP `204 No Content` on success. It is mounted as an early fast path, so probes bypass session, CSRF, and settings-loading middleware. The Dockerfile `HEALTHCHECK` uses it.
- `/admin/health` returns a JSON snapshot used by the Health Status tab. Same probes can be hit directly for monitoring (admin-authenticated).
- Initial-groups-list latency is sampled in process (most recent 200 renders); resets on restart.
- All HTTP requests are logged as JSON via winston (method, path, status, duration, content length, correlation id, IP, actor, user-agent) so a SIEM can ingest without per-line parsing. Logs go to stdout by default; set `LOG_DIR` to also write daily-rotated files (20 MB / 14 days / gzipped) for bare-metal installs.
- Per-request `correlationId` flows into both access logs and audit records.
- Startup log includes `nodeEnv` and `mockEntraCallbackEnabled` so an operator can confirm both at a glance.
- `SIGTERM` / `SIGINT` trigger a graceful-drain window (30 s in production, 10 s in dev); in-flight requests finish, the pooled LDAP connections drain, the listener closes, and the process exits cleanly. A second signal forces immediate exit. `docker-compose.yml` sets `stop_grace_period: 35s` to match.

## Tech stack

- Node.js 20+ / TypeScript
- Express 5 + EJS server-rendered views
- LDAP via `ldapts`
- Microsoft Graph via the built-in `fetch`
- Sessions via `express-session` backed by `session-file-store` (one JSON-per-sid under `data/sessions/`, single-instance only; see [Deployment topology](INSTALLATION.md#deployment-topology--single-instance-by-design))
- CSRF via `csrf-csrf` (double-submit cookie)
- `helmet`, `express-rate-limit`
- Mail via `nodemailer` (SMTP) or Microsoft Graph send-as (Entra)
- Hosted NDJSON audit store + optional syslog forwarding
- Logging via `winston`
- Tests via `vitest`

## Prerequisites

- Runs on **Windows**, **Linux/macOS**, or as a **Linux-based container** (Docker / Kubernetes).
- Node.js 20+ (or Docker)
- Network reachability to your domain controllers (LDAP/LDAPS)
- End-user accounts must have the directory rights appropriate for the group operations they perform (delegated control on the target groups)
- (Optional) Microsoft Entra app registration with delegated `Group.Read.All`, `User.Read`, plus any scopes needed for member writes
- (Optional) SMTP relay or Entra mail-enabled identity for notification emails
- (Optional) Syslog endpoint for centralized audit forwarding

## Quick start

> **Platform note:** use `npm.cmd` on **Windows** and plain `npm` on **Linux/macOS**
> (and inside the Linux container). The `npm` scripts themselves are identical everywhere.

### Windows (PowerShell)

```powershell
# 1. Install dependencies
npm.cmd install

# 2. Create a .env with strong secrets (see INSTALLATION.md for details)
$session = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($session)
"SESSION_SECRET=$([Convert]::ToBase64String($session))" | Out-File -Encoding ascii .env

$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
"CREDENTIAL_ENCRYPTION_KEY=$([Convert]::ToBase64String($key))" | Add-Content -Encoding ascii .env

# 3. Start the dev server
npm.cmd run dev
```

### Linux / macOS (bash)

```bash
# 1. Install dependencies
npm install

# 2. Create a .env with strong secrets (requires OpenSSL)
{
  echo "SESSION_SECRET=$(openssl rand -base64 48)"
  echo "CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -base64 32)"
} >> .env

# 3. Start the dev server
npm run dev
```

### Docker (Linux container)

```bash
# 1. Create a .env with strong secrets (see above), then build + run.
docker compose up --build -d
```

Open <http://localhost:3000> and sign in with the break-glass credentials (`breakglass` / `ChangeMeNow!123`), then rotate the password from Admin Settings &rarr; **Security**.

For production secret generation, environment variables, deployment options (Docker, reverse proxy, systemd, native Windows service), the pre-production security checklist, and backup/restore, see **[INSTALLATION.md](INSTALLATION.md)**.

