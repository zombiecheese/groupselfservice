# Installation & Deployment

Detailed setup, configuration, and deployment guide for the Group Self Service Portal.

- For a high-level feature list, prerequisites, and a quick start, see [README.md](README.md).
- For an architectural and security deep-dive, see [TECHNICAL.md](TECHNICAL.md).

## Contents

- [Generating production secrets](#generating-production-secrets)
- [Environment variables](#environment-variables)
- [Local development](#local-development)
- [Build and test](#build-and-test)
- [Admin settings model](#admin-settings-model)
- [Active Directory notes](#active-directory-notes)
- [Entra ID notes](#entra-id-notes)
- [Deployment](#deployment)
- [Security checklist before production](#security-checklist-before-production)
- [Backup and restore](#backup-and-restore)
- [Project structure](#project-structure)

## Generating production secrets

The portal requires two secrets in production. Both are read from the environment
(via `.env` or the orchestrator), **never** stored in `data/`, and must be backed up
separately and securely (a password vault is appropriate).

| Secret | Purpose | Production requirement |
| --- | --- | --- |
| `SESSION_SECRET` | Signs the session cookie and is reused as the CSRF secret. | At least 32 characters of high-entropy random data. The startup preflight refuses the placeholder value. |
| `CREDENTIAL_ENCRYPTION_KEY` | AES-256-GCM key that encrypts per-session LDAP credentials and the secret fields inside `portal-settings.json`. Also derives the audit HMAC key via HKDF. | Exactly **32 bytes**, base64-encoded (a true AES-256 key). The startup preflight refuses anything that does not decode to 32 bytes. |

> **Important:** Once `CREDENTIAL_ENCRYPTION_KEY` has encrypted on-disk secrets, changing it
> makes those secrets unreadable (the portal treats them as empty) and breaks audit-chain
> verification. Generate it **once** per environment and store it durably before first run.

### Linux / macOS (OpenSSL)

```bash
# SESSION_SECRET — 48 random bytes, base64 (>= 32 chars)
openssl rand -base64 48

# CREDENTIAL_ENCRYPTION_KEY — exactly 32 random bytes, base64
openssl rand -base64 32
```

### Any platform with Node.js

```bash
# SESSION_SECRET
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64'))"

# CREDENTIAL_ENCRYPTION_KEY — exactly 32 bytes (required in production)
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

### Windows (PowerShell)

Use the cryptographic RNG rather than `Get-Random`:

```powershell
# SESSION_SECRET — 48 random bytes, base64
$bytes = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)

# CREDENTIAL_ENCRYPTION_KEY — exactly 32 random bytes, base64
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[Convert]::ToBase64String($bytes)
```

### Writing both straight into a `.env` file (PowerShell)

```powershell
$session = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($session)
"SESSION_SECRET=$([Convert]::ToBase64String($session))" | Out-File -Encoding ascii .env

$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
"CREDENTIAL_ENCRYPTION_KEY=$([Convert]::ToBase64String($key))" | Add-Content -Encoding ascii .env
```

### Writing both straight into a `.env` file (bash)

```bash
{
  echo "SESSION_SECRET=$(openssl rand -base64 48)"
  echo "CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -base64 32)"
} >> .env
```

After generating, set `NODE_ENV=production` so the startup preflight enforces the strict
checks described above.

## Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `NODE_ENV` | `development` | `production` enables strict security checks. |
| `PORT` | `3000` | HTTP listen port. |
| `SESSION_SECRET` | placeholder | Required in production; min 32 chars recommended. Reused as the CSRF secret. |
| `SESSION_TTL_SECONDS` | `28800` | 8 hours. |
| `CREDENTIAL_ENCRYPTION_KEY` | placeholder | Required in production. Encrypts session credentials and settings-file secrets at rest. |
| `AUTH_MODE` | `forms` | Forms-based AD password login. |
| `SETTINGS_FILE_PATH` | `./data/portal-settings.json` | |
| `DEFAULT_PAGE_SIZE` | `100` | |
| `MAX_BATCH_SIZE` | `200` | Max members per bulk add/remove. |
| `MAX_GROUPS_PER_LIST` | `500` | Hard cap on the number of groups returned per `/groups` render. |
| `MAX_MEMBERS_PER_GROUP` | `999` | Hard cap on the number of members returned per group-members read. |
| `LOG_DIR` | _(unset)_ | When set, the structured JSON access + app log is also written to a daily-rotated file in this directory (20 MB / 14 days, gzipped). Leave unset for containerised deployments — docker / k8s / journal-d handle rotation and capture from stdout. |
| `TRUST_PROXY` | `false` | Pass through to `app.set('trust proxy', ...)`. Set to `1` (or a CSV of trusted subnets) when running behind a reverse proxy so rate limiting and `req.ip` honour `X-Forwarded-For`. |

## Local development

> **Cross-platform note:** the commands below use `npm.cmd`, which is the executable
> name on **Windows**. On **Linux/macOS** (and inside the Linux container) use plain
> `npm` instead — e.g. `npm install`, `npm run dev`.

1. Copy `.env.example` to `.env` and update values (at minimum `SESSION_SECRET` and `CREDENTIAL_ENCRYPTION_KEY`).
2. Install dependencies: `npm.cmd install` (`npm install` on Linux/macOS).
3. Start the dev server: `npm.cmd run dev` (`npm run dev` on Linux/macOS).
4. Open <http://localhost:3000> and sign in with the break-glass credentials.

The dev server uses `session-file-store` writing one JSON-per-sid into `data/sessions/`, so restarting it (or `tsx watch` auto-reloading) no longer signs users out. The login page still self-heals stale CSRF cookies via a session regeneration. This deployment model is intended for a single running app instance — a PID lockfile (`data/.portal.pid`) refuses to start a second process against the same data directory.

## Build and test

The `npm` scripts are identical on every platform; only the executable name differs
(`npm.cmd` on Windows, `npm` on Linux/macOS and in the container).

| Task | Windows | Linux / macOS / container |
| --- | --- | --- |
| Build | `npm.cmd run build` | `npm run build` |
| Test | `npm.cmd test` | `npm test` |
| Run compiled app | `npm.cmd start` | `npm start` |

## Admin settings model

- All AD/Entra/mail/audit configuration lives in `./data/portal-settings.json` (override with `SETTINGS_FILE_PATH`).
- Secrets in that file are encrypted at rest using `CREDENTIAL_ENCRYPTION_KEY`.
- Native web TLS is also configured in that file; enabling it requires a restart because the certificate is loaded at process startup. The optional redirect listener is configured there too.
- Branding logo uploads are also stored in that file as an image data URL so they can be rendered directly in the shared site header.
- On first start, a default break-glass user is provisioned:
  - username: `breakglass`
  - password: `ChangeMeNow!123`
- Rotate break-glass credentials immediately from Admin Settings.

## Active Directory notes

- LDAP operations use the signed-in user's credentials for that session; there is no dedicated LDAP bind account.
- Ensure `managedBy` is populated on every group end users will manage.
- For nested ownership, set `managedBy` to an owner group whose members are the actual managers.
- LDAPS with a trusted CA is the supported configuration. The "allow untrusted TLS" toggle exists for lab use only and shows a banner while enabled.

## Entra ID notes

- Register an app with delegated permissions and add the redirect URI you set in Admin Settings to the registration.
- The portal uses Authorization Code + PKCE; MFA / Conditional Access prompts are honored interactively.
- The same Entra access token also drives the delegated-admin Entra group picker in Admin Settings.
- **Member self-service for Entra groups** is opt-in. To enable it:
  1. Tick **Allow users to add/remove members of their Entra-owned groups** in Admin Settings &rarr; Directory.
  2. Add `GroupMember.ReadWrite.All` to the configured scope (existing default keeps `Group.Read.All User.Read openid profile` for read-only).
  3. Grant tenant admin consent for the new permission.
  4. Existing users must sign out and sign back in so the new scope is consented in their token.
- Mutations are still gated server-side by Graph: only group **owners** can add or remove members. Non-owners receive a 403.

### Entra sign-in behavior (opt-in)

AD authentication is the only required sign-in step to enter the portal. Entra sign-in is optional and user-driven.

- **Login always progresses to `/groups`.** A successful AD (or break-glass) sign-in never depends on an existing Microsoft browser session.
- **Entra is connected only when the user chooses.** Users click **Connect Entra ID** from the `/groups` banner (or the admin connect CTA) to start the OAuth flow.
- **Capabilities unlocked after connect.** Once Entra is connected in-session, users can view/manage Entra-owned groups (subject to owner/write settings), and Entra-group-based delegated admin checks can be evaluated.
- **Banner dismissal is per-session** (`POST /auth/entra/dismiss-banner`). Once dismissed it does not reappear until the next sign-in.
- **Tailored admin 403.** A user who lands on `/admin/settings` without a token but whose tenant has delegated-admin Entra group IDs configured sees a *"Connect to Microsoft Entra ID"* page with a direct Connect button instead of a flat "access denied".

The browser still has to obey Conditional Access and MFA policies; those are tenant-side and not something the portal can or should bypass.

## Deployment

The portal is a plain Node.js process, so it runs the same way on every supported target.
Pick the one that matches your environment:

- **[Docker / docker-compose](#docker--docker-compose-linux)** — Linux container image (also the way to run on Windows via Docker Desktop's Linux VM). Recommended for most deployments.
- **[Reverse proxy](#reverse-proxy-optional)** — front any of the below with Nginx/Caddy/Traefik/HAProxy (or IIS on Windows) for TLS termination.
- **[systemd](#systemd-bare-metal-linux)** — native Linux host, no container.
- **[Native Windows (Windows Service)](#native-windows-windows-service)** — Windows Server host, no container.

All targets honor the same single-instance rule below.

### Deployment topology — single-instance by design

The portal is intentionally **one Node.js process per data directory**. Several pieces of state live in process memory and are correct only when there is exactly one process:

- Per-account login lockout counter (a second process would see only its own failures, effectively halving the threshold).
- Active-sessions map used by *Sign out other sessions*.
- Short-lived AD ownership cache and inline member-count cache.
- Single-writer assumption for `data/portal-settings.json` and `data/login-history.json`.

To enforce this, the process writes a PID lockfile (`data/.portal.pid`) at startup and refuses to boot when another live process already owns the data directory. Stale locks (whose PID is no longer running) are reclaimed automatically.

Do **not** set replicas/scale > 1 in your orchestrator. For HA, run an active/standby pair on shared storage with only one process active at a time, or accept the deploy-window outage. Sessions are persisted to disk so a restart no longer signs every user out.

### Docker / docker-compose (Linux)

A multi-stage Linux `Dockerfile` and a `docker-compose.yml` are included.

```powershell
# Create a .env file with strong values for both secrets (see "Generating
# production secrets" above for cross-platform commands).
$session = [byte[]]::new(48)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($session)
"SESSION_SECRET=$([Convert]::ToBase64String($session))" | Out-File -Encoding ascii .env

$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
"CREDENTIAL_ENCRYPTION_KEY=$([Convert]::ToBase64String($key))" | Add-Content -Encoding ascii .env

docker compose up --build -d
```

The compose file:
- Builds the app from this repo and runs it as the non-root `node` user.
- Persists portal settings + audit data + on-disk sessions on the `gss-data` named volume mounted at `/app/data`.

The portal is single-instance by design (see *Deployment topology* above). Sessions are now persisted to `data/sessions/`, so a `docker compose up -d --force-recreate` no longer signs every user out, but you must still run only one container against the same `gss-data` volume.

> **Linux / macOS shell** equivalent of the `.env` bootstrap above:
>
> ```bash
> {
>   echo "SESSION_SECRET=$(openssl rand -base64 48)"
>   echo "CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -base64 32)"
> } >> .env
> docker compose up --build -d
> ```
>
> Docker Desktop on Windows runs the same Linux image inside its Linux VM, so the
> container itself is identical on either host; only the shell used to author `.env`
> and invoke `docker compose` differs.

If you want the application itself to terminate HTTPS, import the PEM certificate and private key under General settings, save, and restart the container. You can also enable a second HTTP listener that issues `301` redirects to the HTTPS port; configure its bind port in the same section. Otherwise you can continue to terminate TLS upstream.

Mount your enterprise CA bundle into the container and reference it via the AD "Custom CA PEM" field in Admin Settings if your domain controllers use a private CA.

### Reverse proxy (optional)

Run the container behind an open-source reverse proxy (Nginx, Caddy, Traefik, HAProxy) if you prefer terminating TLS upstream and forwarding traffic to the app on port 3000. The Node process identity never binds to LDAP — every operation uses the signed-in user's credentials.

When using the built-in HTTP redirect listener, make sure the chosen redirect port is reachable and that the process has permission to bind it. Port 80 is standard, but containers and unprivileged Linux users often need a higher port unless you grant that capability explicitly.

### systemd (bare metal Linux)

If you prefer running directly on a Linux host, build with `npm ci && npm run build`, copy `dist/`, `node_modules/`, `views/`, `public/` and `package.json` to the target, and run `node dist/server.js` under a dedicated unprivileged service user via a `systemd` unit. Place the same reverse proxy in front for TLS termination.

Example `/etc/systemd/system/groupselfservice.service`:

```ini
[Unit]
Description=Group Self Service Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gss
WorkingDirectory=/opt/groupselfservice
EnvironmentFile=/opt/groupselfservice/.env
Environment=NODE_ENV=production
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
# Match the in-app graceful-drain window (30 s in production).
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now groupselfservice
sudo systemctl status groupselfservice
```

### Native Windows (Windows Service)

To run directly on a Windows Server host (no container), install Node.js 20+, then build
and stage the app:

```powershell
npm ci
npm run build
# Copy dist\, node_modules\, views\, public\ and package.json to the target, e.g. C:\GroupSelfService
```

Set the two production secrets and `NODE_ENV` as **machine** environment variables (so the
service account sees them) and start the app:

```powershell
[Environment]::SetEnvironmentVariable('NODE_ENV', 'production', 'Machine')
[Environment]::SetEnvironmentVariable('SESSION_SECRET', '<generated value>', 'Machine')
[Environment]::SetEnvironmentVariable('CREDENTIAL_ENCRYPTION_KEY', '<generated value>', 'Machine')

cd C:\GroupSelfService
node dist\server.js
```

For an always-on service, wrap `node dist\server.js` with a supervisor such as
[NSSM](https://nssm.cc/) or [WinSW](https://github.com/winsw/winsw) so it starts at boot,
restarts on failure, and runs under a dedicated low-privilege service account:

```powershell
# Example using NSSM.
nssm install GroupSelfService "C:\Program Files\nodejs\node.exe" "C:\GroupSelfService\dist\server.js"
nssm set GroupSelfService AppDirectory "C:\GroupSelfService"
nssm set GroupSelfService AppEnvironmentExtra "NODE_ENV=production"
nssm start GroupSelfService
```

Place IIS (with Application Request Routing / URL Rewrite) or the same open-source reverse
proxy in front for TLS termination, or enable native HTTPS in General settings. POSIX file
modes (`0o600`) do not apply on Windows — secure the `data\` directory with NTFS ACLs so
only the service account (and administrators) can read it.

## Security checklist before production

- Set strong, unique values for `SESSION_SECRET` and `CREDENTIAL_ENCRYPTION_KEY` (see [Generating production secrets](#generating-production-secrets)).
- Run a single application instance per data directory. The portal enforces this with a PID lockfile (`data/.portal.pid`); see *Deployment topology — single-instance by design* above.
- In production set `CREDENTIAL_ENCRYPTION_KEY` to a true 32-byte base64 value (generate with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`). The startup preflight refuses to start with anything less in production.
- Enforce LDAPS with a trusted CA; leave the "allow untrusted TLS" toggle off.
- Use least-privilege AD delegation on the groups end users will manage.
- Rotate the break-glass password from Admin Settings on first login.
- Either enable native HTTPS in General settings or place the portal behind TLS at the load balancer / reverse proxy (`secure` cookies are auto-enabled in production).
- Forward audit events to syslog for retention beyond the local NDJSON window.

## Backup and restore

The portal's entire state lives in two places, both under the `./data` directory by default:

- `data/portal-settings.json` — all admin configuration (AD, Entra, mail, audit, branding, web TLS, break-glass hash, delegated admins, group-display filter, theme). Secrets inside are AES-256-GCM-encrypted with `CREDENTIAL_ENCRYPTION_KEY`. Written atomically (tmp + fsync + rename) so a crash between truncate and final flush never leaves a zero-byte file.
- `data/audit/audit-YYYY-MM-DD.ndjson` — daily-rolled append-only audit log files. Each record carries a `seq` and an `hmac` so the chain can be replayed by the verifier CLI (`npm run verify-audit`) to detect any insertion, deletion, or modification.

Three smaller files complete the on-disk surface:

- `data/sessions/<sid>.json` — one file per active browser session, written by `session-file-store`. Reaped automatically when the session TTL expires.
- `data/login-history.json` — per-user *last sign-in* timestamp + IP + UA for the security-visibility widget.
- `data/.portal.pid` — single-instance lockfile holding the PID of the running process. Refuses startup if another live process already owns it.

There is no database, no schema, no migration step.

### Hot backup (recommended)

Settings and audit files are written atomically (append for audit; rewrite for settings) and read on every request, so a snapshot taken while the portal is running is safe — you just need to copy the directory.

**Docker named volume (Windows PowerShell or Linux/macOS shell — `docker` syntax is identical):**

```powershell
# Stop accepting new writes momentarily (optional but cleanest).
docker compose stop app

# Copy the volume contents to a timestamped backup.
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
docker run --rm -v gss-data:/data -v ${PWD}:/backup alpine `
  tar -czf "/backup/gss-backup-$stamp.tar.gz" -C / data

docker compose start app
```

```bash
# Linux / macOS shell equivalent.
docker compose stop app
docker run --rm -v gss-data:/data -v "$PWD":/backup alpine \
  tar -czf "/backup/gss-backup-$(date +%Y%m%d-%H%M%S).tar.gz" -C / data
docker compose start app
```

**Bare-metal Linux (systemd):**

```bash
sudo systemctl stop groupselfservice
sudo tar -czf "/var/backups/gss-backup-$(date +%Y%m%d-%H%M%S).tar.gz" -C /var/lib/groupselfservice data
sudo systemctl start groupselfservice
```

**Native Windows (Windows Service):**

```powershell
# Stop the service (use your supervisor's name, e.g. NSSM 'GroupSelfService').
Stop-Service GroupSelfService

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Compress-Archive -Path "C:\GroupSelfService\data\*" -DestinationPath "C:\Backups\gss-backup-$stamp.zip"

Start-Service GroupSelfService
```

### Restore

1. Stop the portal.
2. Replace `data/` with the backup contents (on **Linux**, preserve file ownership and POSIX mode `0o600` on the settings + audit files, otherwise the portal will re-`chmod` them on the next write anyway; on **Windows**, restore into the same folder and confirm the NTFS ACLs still restrict it to the service account). Inside a **container**, extract the archive back into the `gss-data` volume (e.g. `docker run --rm -v gss-data:/data -v <backup-dir>:/backup alpine tar -xzf /backup/<file>.tar.gz -C /`).
3. Set the same `CREDENTIAL_ENCRYPTION_KEY` the backup was taken with — without it the encrypted secrets in `portal-settings.json` are unreadable and the portal will treat them as empty.
4. Start the portal.

### What is *not* in `data/`

- Per-account login lockout state, in-process metrics (groups-list latency samples), the LDAP connection pool, and the short-lived AD ownership / inline member-count caches. All reset on restart by design.
- `CREDENTIAL_ENCRYPTION_KEY` and `SESSION_SECRET` — these live in environment variables; back them up separately and securely (a password vault is appropriate).
- `LOG_DIR` rotated log files — if you enable file logging, those are operational telemetry, not state; treat them like any other log directory.

### Disaster-recovery sanity test

Once a quarter, restore a backup into a throwaway environment and verify:

- Admin **Health Status** tab loads with the expected AD/Entra/mail status.
- Settings tabs show the previously-configured values (encrypted fields will be re-decrypted with the same key).
- A test sign-in succeeds.
- The audit directory contains the daily NDJSON files from the backup window.

## Project structure

- `src/domain` — core models
- `src/application` — services, contracts, business logic
- `src/infrastructure` — LDAP, Entra Graph, settings repository, audit store, mail, secrets cipher
- `src/web` — Express middleware and routes
- `views` — server-rendered EJS templates
- `public` — static CSS/JS for the admin and group pages
- `tests` — unit and integration specs
