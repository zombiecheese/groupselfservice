import { Attribute, Change, Client } from "ldapts";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import type { ConnectionOptions } from "node:tls";
import { AdDirectoryRepository, DirectorySessionCredentials } from "../../application/contracts";
import { AdGroup, AdUser, GroupMembershipChange, ManagedGroup, UserIdentity } from "../../domain/models";
import { logger } from "../logger";

// ldapts can return single-value attributes as either a plain string or a
// one-element array depending on the server response encoding. Normalise both
// to a single string so downstream code never encounters an array where it
// expects a scalar (e.g. description passed to EJS toLowerCase()).
function coerceString(value: string | string[] | undefined): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value)) return value.length > 0 ? String(value[0]) : undefined;
  return String(value);
}

function escapeLdapFilter(input: string): string {
  return input
    .replace(/\\/g, "\\5c")
    .replace(/\*/g, "\\2a")
    .replace(/\(/g, "\\28")
    .replace(/\)/g, "\\29")
    .replace(/\u0000/g, "\\00");
}

// AD `groupType` is a signed 32-bit bitmask. The high bit (0x80000000) marks a
// security group; absence means distribution. The low bits encode the scope
// (Global / Domain Local / Universal). Returns a friendly label such as
// "Security (Global)" or null when the attribute isn't present/parseable.
function decodeAdGroupType(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value)) return undefined;
  // Convert the (possibly negative) signed 32-bit representation into an
  // unsigned bitmask before testing the security-enabled flag.
  const unsigned = value >>> 0;
  const isSecurity = (unsigned & 0x80000000) !== 0;
  let scope = "";
  if ((unsigned & 0x00000002) !== 0) scope = "Global";
  else if ((unsigned & 0x00000004) !== 0) scope = "Domain Local";
  else if ((unsigned & 0x00000008) !== 0) scope = "Universal";
  const kind = isSecurity ? "Security" : "Distribution";
  return scope ? `${kind} (${scope})` : kind;
}

export interface LdapTlsConfig {
  caPem?: string;
  rejectUnauthorized?: boolean;
  serverName?: string;
}

export function buildLdapTlsOptions(config: LdapTlsConfig | undefined): ConnectionOptions | undefined {
  if (!config) {
    return undefined;
  }
  const opts: ConnectionOptions = {};
  if (config.caPem && config.caPem.trim().length > 0) {
    opts.ca = config.caPem;
  }
  if (config.rejectUnauthorized === false) {
    opts.rejectUnauthorized = false;
  }
  if (config.serverName && config.serverName.trim().length > 0) {
    opts.servername = config.serverName.trim();
  }
  return Object.keys(opts).length > 0 ? opts : undefined;
}

async function probeTcp(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const sock = net.connect({ host, port, timeout: timeoutMs });
    const done = (ok: boolean) => {
      sock.removeAllListeners();
      sock.destroy();
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

// Short-lived cache for resolved hostname -> reachable IP. Avoids re-running DNS
// + per-IP TCP probes (each up to 3s) on every LDAP call within a request burst.
const REACHABLE_TTL_MS = 60_000;
const reachableCache = new Map<string, { ip: string; family: number; expires: number }>();

function cacheKey(host: string, port: number): string {
  return `${host.toLowerCase()}|${port}`;
}

// Resolve a hostname to a reachable IP (IPv4 preferred). Returns null if none.
export async function pickReachableHost(host: string, port: number, ipv4Only = false): Promise<string | null> {
  if (net.isIP(host)) {
    return (await probeTcp(host, port, 3000)) ? host : null;
  }
  const key = cacheKey(host, port);
  const cached = reachableCache.get(key);
  if (cached && cached.expires > Date.now()) {
    if (!ipv4Only || cached.family === 4) {
      return cached.ip;
    }
  }
  let addrs: Array<{ address: string; family: number }> = [];
  try {
    addrs = await dns.lookup(host, { all: true, family: ipv4Only ? 4 : 0 });
  } catch (err) {
    logger.warn("DNS lookup failed", { host, err: (err as Error).message, ipv4Only });
    return null;
  }
  const filtered = ipv4Only ? addrs.filter((a) => a.family === 4) : addrs;
  const sorted = [...filtered].sort((a, b) => (a.family === 4 ? -1 : 1) - (b.family === 4 ? -1 : 1));
  for (const a of sorted) {
    if (await probeTcp(a.address, port, 3000)) {
      reachableCache.set(key, { ip: a.address, family: a.family, expires: Date.now() + REACHABLE_TTL_MS });
      return a.address;
    }
  }
  return null;
}

// Resolve the LDAP URL hostname, find the first reachable IP, and return a URL
// that targets that IP. Cert hostname verification continues to use the original
// hostname via tlsOptions.servername.
async function resolveReachableLdapUrl(
  ldapUrl: string,
  tlsServerName: string | undefined,
  ipv4Only: boolean
): Promise<{ url: string; servername: string } | null> {
  let parsed: URL;
  try {
    parsed = new URL(ldapUrl);
  } catch {
    return null;
  }
  const originalHost = parsed.hostname;
  const isTls = parsed.protocol === "ldaps:";
  const port = Number(parsed.port) || (isTls ? 636 : 389);
  const servername = (tlsServerName && tlsServerName.trim()) || originalHost;

  // If hostname is already an IP, no DNS happy-eyeballs needed.
  if (net.isIP(originalHost)) {
    return { url: ldapUrl, servername };
  }

  // Reuse cached reachable IP within TTL to avoid DNS+probe stalls per call.
  const key = cacheKey(originalHost, port);
  const cached = reachableCache.get(key);
  if (cached && cached.expires > Date.now() && (!ipv4Only || cached.family === 4)) {
    const ipHost = cached.family === 6 ? `[${cached.ip}]` : cached.ip;
    const rebuilt = `${parsed.protocol}//${ipHost}:${port}${parsed.pathname || ""}${parsed.search || ""}`;
    return { url: rebuilt, servername };
  }

  let addrs: Array<{ address: string; family: number }> = [];
  try {
    // Get all addresses (A + AAAA). On Windows, Node often prefers IPv6 when present,
    // which can stall if AAAA is not actually routable in this environment.
    addrs = await dns.lookup(originalHost, { all: true, family: ipv4Only ? 4 : 0 });
  } catch (err) {
    logger.warn("LDAP DNS lookup failed", { host: originalHost, err: (err as Error).message, ipv4Only });
    return null;
  }
  if (addrs.length === 0) {
    return null;
  }

  const filtered = ipv4Only ? addrs.filter((a) => a.family === 4) : addrs;
  if (filtered.length === 0) {
    logger.warn("LDAP no IPv4 addresses for host (ipv4Only)", { host: originalHost });
    return null;
  }

  // Prefer IPv4 first (matches typical AD/LDAP deployments), then IPv6.
  const sorted = [...filtered].sort((a, b) => (a.family === 4 ? -1 : 1) - (b.family === 4 ? -1 : 1));

  logger.info("LDAP resolving host", {
    host: originalHost,
    port,
    addrs: sorted.map((a) => `${a.address}/v${a.family}`),
  });

  for (const a of sorted) {
    const ok = await probeTcp(a.address, port, 3000);
    if (ok) {
      const ipHost = a.family === 6 ? `[${a.address}]` : a.address;
      const rebuilt = `${parsed.protocol}//${ipHost}:${port}${parsed.pathname || ""}${parsed.search || ""}`;
      logger.info("LDAP using reachable IP", { host: originalHost, ip: a.address, port });
      reachableCache.set(cacheKey(originalHost, port), {
        ip: a.address,
        family: a.family,
        expires: Date.now() + REACHABLE_TTL_MS,
      });
      return { url: rebuilt, servername };
    } else {
      logger.warn("LDAP IP unreachable", { host: originalHost, ip: a.address, port });
    }
  }
  logger.warn("LDAP no reachable IPs", {
    host: originalHost,
    port,
    addrs: sorted.map((a) => a.address),
  });
  return null;
}

export class LdapAdRepository implements AdDirectoryRepository {
  // Bounded idle-client pool keyed by `(resolved url, bind username)`.
  // ldapts maintains a TCP+TLS connection per Client instance; the bind
  // step is the expensive part, especially over LDAPS where the TLS
  // handshake is per-connect. With per-call create+bind+unbind a single
  // /admin/* render fired 5+ TLS handshakes against the DC. The pool
  // keeps recently-used bound clients open so subsequent calls in the
  // same request reuse them. Two sane bounds: idle TTL (auto-close
  // anything idle longer than this; covers credentials being changed
  // while a session is logged in) and max idle clients per key
  // (bound memory + open sockets when many users hit the portal at once).
  //
  // Anonymous (un-bound) clients are not pooled — they are short-lived,
  // and the cost difference is small.
  //
  // The pool is per-repository instance. Because the repo is composed
  // around a CachedAdRepository in server.ts and lives for the lifetime
  // of the process, this is effectively a process-wide pool. Single-
  // instance deployment makes this safe.
  private readonly pool = new Map<string, { client: Client; idleSince: number }[]>();
  private readonly POOL_MAX_PER_KEY = 4;
  private readonly POOL_IDLE_TTL_MS = 5 * 60_000; // 5 minutes
  private poolSweeper?: NodeJS.Timeout;

  constructor(
    private readonly ldapUrl: string,
    private readonly baseDn: string,
    private readonly tlsConfig?: LdapTlsConfig,
    private readonly ipv4Only: boolean = false
  ) {
    // Periodic sweep of expired idle clients so they don't sit on the DC
    // long after the user logged out.
    this.poolSweeper = setInterval(() => this.sweepPool(), 60_000);
    this.poolSweeper.unref();
  }

  // The pool key is built from the session's opaque poolToken — a random UUID
  // assigned at login and stored in the encrypted session. It contains no
  // password material, so no KDF is needed and a memory snapshot of the pool
  // map reveals nothing about user credentials.
  private poolKey(credentials?: DirectorySessionCredentials): string {
    if (!credentials?.username || !credentials.poolToken) {
      return `${this.ldapUrl}|anon`;
    }
    return `${this.ldapUrl}|u:${credentials.username.toLowerCase()}|t:${credentials.poolToken}`;
  }

  private async createClient(): Promise<Client> {
    const resolved = await resolveReachableLdapUrl(this.ldapUrl, this.tlsConfig?.serverName, this.ipv4Only);
    const baseTls = buildLdapTlsOptions(this.tlsConfig);
    let tlsOptions = baseTls;
    let url = this.ldapUrl;
    if (resolved) {
      url = resolved.url;
      // Always pin SNI/hostname check to the original hostname so the cert validates
      // even when we connect by IP.
      tlsOptions = { ...(baseTls || {}), servername: resolved.servername } as ConnectionOptions;
    }
    return new Client({
      url,
      timeout: 10000,
      connectTimeout: 10000,
      ...(tlsOptions ? { tlsOptions } : {}),
    });
  }

  // Acquire a bound (or anonymous) client, preferring an idle one in the
  // pool. Caller is expected to call `releaseClient` on success or
  // `discardClient` if the operation threw — never `unbind()` directly.
  private async acquireClient(credentials?: DirectorySessionCredentials): Promise<{ client: Client; key: string }> {
    if (!credentials?.username || !credentials.password) {
      // Anonymous: don't bother pooling. ldapts is cheap to construct
      // and we never need a long-lived anonymous handle.
      const client = await this.createClient();
      return { client, key: this.poolKey(undefined) };
    }
    const key = this.poolKey(credentials);
    const bucket = this.pool.get(key);
    if (bucket && bucket.length > 0) {
      const slot = bucket.pop()!;
      // Drop expired entries silently and fall through to a fresh bind.
      if (Date.now() - slot.idleSince > this.POOL_IDLE_TTL_MS) {
        try { await slot.client.unbind(); } catch { /* best-effort */ }
      } else {
        return { client: slot.client, key };
      }
    }
    const client = await this.createClient();
    await client.bind(credentials.username, credentials.password);
    return { client, key };
  }

  private releaseClient(client: Client, key: string): void {
    if (key.endsWith("|anon")) {
      // Anonymous clients aren't pooled — close immediately.
      client.unbind().catch(() => undefined);
      return;
    }
    let bucket = this.pool.get(key);
    if (!bucket) {
      bucket = [];
      this.pool.set(key, bucket);
    }
    if (bucket.length >= this.POOL_MAX_PER_KEY) {
      // Pool full for this key: close the surplus client.
      client.unbind().catch(() => undefined);
      return;
    }
    bucket.push({ client, idleSince: Date.now() });
  }

  private discardClient(client: Client): void {
    // Failed operation: never return the client to the pool, the
    // connection state may be unusable. Best-effort unbind.
    client.unbind().catch(() => undefined);
  }

  private sweepPool(): void {
    const now = Date.now();
    for (const [key, bucket] of this.pool) {
      const fresh: { client: Client; idleSince: number }[] = [];
      for (const slot of bucket) {
        if (now - slot.idleSince > this.POOL_IDLE_TTL_MS) {
          slot.client.unbind().catch(() => undefined);
        } else {
          fresh.push(slot);
        }
      }
      if (fresh.length === 0) {
        this.pool.delete(key);
      } else {
        this.pool.set(key, fresh);
      }
    }
  }

  // Close the pool and the sweeper timer. Wired into graceful shutdown
  // by `server.ts`.
  async closePool(): Promise<void> {
    if (this.poolSweeper) {
      clearInterval(this.poolSweeper);
      this.poolSweeper = undefined;
    }
    const tasks: Promise<unknown>[] = [];
    for (const bucket of this.pool.values()) {
      for (const slot of bucket) {
        tasks.push(slot.client.unbind().catch(() => undefined));
      }
    }
    this.pool.clear();
    await Promise.all(tasks);
  }

  private async withClient<T>(
    action: (client: Client) => Promise<T>,
    credentials?: DirectorySessionCredentials
  ): Promise<T> {
    const { client, key } = await this.acquireClient(credentials);
    try {
      const result = await action(client);
      this.releaseClient(client, key);
      return result;
    } catch (err) {
      this.discardClient(client);
      throw err;
    }
  }

  async getCurrentUser(upnOrSam: string, credentials?: DirectorySessionCredentials): Promise<UserIdentity | null> {
    const escaped = escapeLdapFilter(upnOrSam);
    return this.withClient(async (client) => {
      const result = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(|(userPrincipalName=${escaped})(sAMAccountName=${escaped}))`,
        attributes: ["userPrincipalName", "sAMAccountName", "displayName", "distinguishedName"],
        sizeLimit: 1,
      });

      const first = result.searchEntries[0] as Record<string, string | string[] | undefined> | undefined;
      if (!first) {
        return null;
      }

      return {
        upn: (first.userPrincipalName as string) || `${(first.sAMAccountName as string) || upnOrSam}@unknown.local`,
        samAccountName: (first.sAMAccountName as string) || upnOrSam,
        displayName: (first.displayName as string) || (first.sAMAccountName as string) || upnOrSam,
        dn: (first.distinguishedName as string) || undefined,
      };
    }, credentials);
  }

  async authenticateUser(upnOrSam: string, password: string): Promise<UserIdentity | null> {
    if (!password) {
      return null;
    }

    // Step 1: bind. A successful bind means credentials are valid.
    const client = await this.createClient();
    try {
      try {
        await client.bind(upnOrSam, password);
      } catch (err) {
        const e = err as Error & { code?: number | string };
        logger.warn("AD authenticate: bind failed", {
          username: upnOrSam,
          ldapUrl: this.ldapUrl,
          code: e.code,
          message: e.message,
        });
        return null;
      }

      // Step 2: search for the user's record using the same connection (already bound).
      const escaped = escapeLdapFilter(upnOrSam);
      // Strip an @domain suffix so we can match sAMAccountName too.
      const samCandidate = upnOrSam.includes("@") ? upnOrSam.split("@")[0] : upnOrSam;
      const escapedSam = escapeLdapFilter(samCandidate);
      try {
        const result = await client.search(this.baseDn, {
          scope: "sub",
          filter: `(|(userPrincipalName=${escaped})(sAMAccountName=${escaped})(sAMAccountName=${escapedSam}))`,
          attributes: ["userPrincipalName", "sAMAccountName", "displayName", "distinguishedName"],
          sizeLimit: 1,
        });
        const first = result.searchEntries[0] as Record<string, string | string[] | undefined> | undefined;
        if (first) {
          return {
            upn: (first.userPrincipalName as string) || `${(first.sAMAccountName as string) || samCandidate}@unknown.local`,
            samAccountName: (first.sAMAccountName as string) || samCandidate,
            displayName: (first.displayName as string) || (first.sAMAccountName as string) || samCandidate,
            dn: (first.distinguishedName as string) || undefined,
          };
        }
        logger.warn("AD authenticate: bind ok but user lookup returned no entries", {
          username: upnOrSam,
          baseDn: this.baseDn,
        });
      } catch (err) {
        const e = err as Error & { code?: number | string };
        logger.warn("AD authenticate: post-bind lookup errored, accepting bind", {
          username: upnOrSam,
          baseDn: this.baseDn,
          code: e.code,
          message: e.message,
        });
      }

      // Bind succeeded but we couldn't enrich. Return a minimal identity so login still works.
      return {
        upn: upnOrSam.includes("@") ? upnOrSam : `${samCandidate}@unknown.local`,
        samAccountName: samCandidate,
        displayName: samCandidate,
        dn: undefined,
      };
    } finally {
      try {
        await client.unbind();
      } catch {
        /* ignore */
      }
    }
  }

    async findManagedGroups(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    credentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]> {
    // Guard: when the user has no DN (e.g. bind succeeded but the post-bind
    // lookup returned no entries), an empty string inside the managedBy
    // filter becomes a presence test `(managedBy=)` which matches *every*
    // group with any managedBy attribute — potentially the entire directory.
    if (!user.dn) {
      return [];
    }
    return this.withClient(async (client) => {
      const managedResults: ManagedGroup[] = [];
      const direct = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(managedBy=${escapeLdapFilter(user.dn as string)}))`,
        attributes: ["distinguishedName", "cn", "description", "managedBy", "groupType"],
        sizeLimit: limit,
      });

            for (const row of direct.searchEntries as Record<string, string | string[] | undefined>[]) {
        managedResults.push({
          group: {
            dn: coerceString(row.distinguishedName) || "",
            name: coerceString(row.cn) || "",
            description: coerceString(row.description),
            managedByDn: coerceString(row.managedBy),
            groupType: decodeAdGroupType(coerceString(row.groupType)),
          },
          source: "ad",
          ownerType: "direct",
        });
      }

      if (!includeNested || !user.dn) {
        return managedResults;
      }

      const nestedOwnerGroups = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(member=${escapeLdapFilter(user.dn)}))`,
        attributes: ["distinguishedName", "cn"],
        sizeLimit: limit,
      });

      const ownerRows = (nestedOwnerGroups.searchEntries as Record<string, string | undefined>[])
        .filter((row) => !!row.distinguishedName);

      if (ownerRows.length === 0) {
        return managedResults;
      }

      // Collapse N per-owner-group searches into a single OR filter so slow links
      // pay one round-trip instead of one per owner group.
      const ownerFilter = ownerRows
        .map((row) => `(managedBy=${escapeLdapFilter(row.distinguishedName as string)})`)
        .join("");
      const nestedManaged = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(|${ownerFilter}))`,
        attributes: ["distinguishedName", "cn", "description", "managedBy", "groupType"],
        sizeLimit: limit,
      });

            const ownerByDn = new Map<string, string>();
      for (const row of ownerRows) {
        ownerByDn.set(
          (coerceString(row.distinguishedName) as string).toLowerCase(),
          coerceString(row.cn) || (coerceString(row.distinguishedName) as string)
        );
      }

      for (const row of nestedManaged.searchEntries as Record<string, string | string[] | undefined>[]) {
        const rowDn = coerceString(row.distinguishedName);
        const rowManagedBy = coerceString(row.managedBy);
        if (!rowDn) {
          continue;
        }
        if (managedResults.some((x) => x.group.dn === rowDn)) {
          continue;
        }
        const ownerLabel = rowManagedBy
          ? ownerByDn.get(rowManagedBy.toLowerCase())
          : undefined;
                managedResults.push({
          group: {
            dn: row.distinguishedName as string,
            name: coerceString(row.cn) || "",
            description: coerceString(row.description),
            managedByDn: coerceString(row.managedBy),
            groupType: decodeAdGroupType(coerceString(row.groupType)),
          },
          source: "ad",
          ownerType: "nested",
          ownerPath: ownerLabel ? [ownerLabel] : undefined,
        });
      }

      return managedResults.slice(0, limit);
    }, credentials);
  }

  async getGroupMembers(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return this.withClient(async (client) => {
      // Single subtree search using memberOf returns all direct members in one
      // round-trip with the attributes we need, instead of N+1 base searches.
      const result = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(|(objectClass=user)(objectClass=group))(memberOf=${escapeLdapFilter(groupDn)}))`,
        attributes: ["distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "mail"],
      });

            return (result.searchEntries as Record<string, string | string[] | undefined>[])
        .filter((row) => coerceString(row.distinguishedName) && coerceString(row.sAMAccountName))
        .map((row) => ({
          dn: coerceString(row.distinguishedName) as string,
          samAccountName: coerceString(row.sAMAccountName) as string,
          userPrincipalName: coerceString(row.userPrincipalName),
          displayName: coerceString(row.displayName),
          mail: coerceString(row.mail),
        }));
    }, credentials);
  }

  async searchPrincipals(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return this.withClient(async (client) => {
      const escaped = escapeLdapFilter(query);
      const result = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=user)(|(displayName=*${escaped}*)(sAMAccountName=*${escaped}*)(mail=*${escaped}*)))`,
        attributes: ["distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "mail"],
        sizeLimit: limit,
      });

            return (result.searchEntries as Record<string, string | string[] | undefined>[])
        .filter((row) => coerceString(row.distinguishedName) && coerceString(row.sAMAccountName))
        .map((row) => ({
          dn: coerceString(row.distinguishedName) as string,
          samAccountName: coerceString(row.sAMAccountName) as string,
          userPrincipalName: coerceString(row.userPrincipalName),
          displayName: coerceString(row.displayName),
          mail: coerceString(row.mail),
        }));
    }, credentials);
  }

  async searchAdGroups(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdGroup[]> {
    return this.withClient(async (client) => {
      const escaped = escapeLdapFilter(query);
      const result = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(|(cn=*${escaped}*)(sAMAccountName=*${escaped}*)(displayName=*${escaped}*)))`,
        attributes: ["distinguishedName", "cn", "description", "managedBy", "groupType"],
        sizeLimit: limit,
      });
            return (result.searchEntries as Record<string, string | string[] | undefined>[])
        .filter((row) => coerceString(row.distinguishedName) && coerceString(row.cn))
        .map((row) => ({
          dn: coerceString(row.distinguishedName) as string,
          name: coerceString(row.cn) as string,
          description: coerceString(row.description),
          managedByDn: coerceString(row.managedBy),
          groupType: decodeAdGroupType(coerceString(row.groupType)),
        }));
    }, credentials);
  }

  async addGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await this.withClient(async (client) => {
      await client.modify(change.groupDn, [new Change({
        operation: "add",
        modification: new Attribute({
          type: "member",
          values: [change.memberDn],
        }),
      })]);
    }, credentials);
  }

  async removeGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await this.withClient(async (client) => {
      await client.modify(change.groupDn, [new Change({
        operation: "delete",
        modification: new Attribute({
          type: "member",
          values: [change.memberDn],
        }),
      })]);
    }, credentials);
  }

  async canUserManageGroup(
    user: UserIdentity,
    groupDn: string,
    includeNested: boolean,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    if (!user.dn) {
      return false;
    }
    // Direct check against the single group instead of enumerating every group
    // the user manages — collapses thousands of round-trips on slow links.
    return this.withClient(async (client) => {
      const direct = await client.search(groupDn, {
        scope: "base",
        filter: `(&(objectClass=group)(managedBy=${escapeLdapFilter(user.dn as string)}))`,
        attributes: ["distinguishedName"],
        sizeLimit: 1,
      });
      if (direct.searchEntries.length > 0) {
        return true;
      }
      if (!includeNested) {
        return false;
      }
      // Nested ownership: the group's managedBy is itself a group whose members
      // (transitively, via LDAP_MATCHING_RULE_IN_CHAIN) include the user.
      const grp = await client.search(groupDn, {
        scope: "base",
        filter: "(objectClass=group)",
        attributes: ["managedBy"],
        sizeLimit: 1,
      });
      const row = grp.searchEntries[0] as Record<string, string | undefined> | undefined;
      const ownerDn = row?.managedBy;
      if (!ownerDn) {
        return false;
      }
      const memberCheck = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(distinguishedName=${escapeLdapFilter(ownerDn)})(member:1.2.840.113556.1.4.1941:=${escapeLdapFilter(user.dn as string)}))`,
        attributes: ["distinguishedName"],
        sizeLimit: 1,
      });
      return memberCheck.searchEntries.length > 0;
    }, credentials);
  }

  async isUserMemberOfGroup(
    user: UserIdentity,
    groupDn: string,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    if (!user.dn) {
      return false;
    }

    return this.withClient(async (client) => {
      const result = await client.search(this.baseDn, {
        scope: "sub",
        filter: `(&(objectClass=group)(distinguishedName=${escapeLdapFilter(groupDn)})(member:1.2.840.113556.1.4.1941:=${escapeLdapFilter(user.dn as string)}))`,
        attributes: ["distinguishedName"],
        sizeLimit: 1,
      });

      return result.searchEntries.length > 0;
    }, credentials);
  }

  async getGroup(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdGroup | null> {
    return this.withClient(async (client) => {
      const result = await client.search(groupDn, {
        scope: "base",
        filter: "(objectClass=group)",
        attributes: ["distinguishedName", "cn", "description", "managedBy", "groupType"],
        sizeLimit: 1,
      });
            const first = result.searchEntries[0] as Record<string, string | string[] | undefined> | undefined;
      const firstDn = coerceString(first?.distinguishedName);
      const firstName = coerceString(first?.cn);
      if (!first || !firstDn || !firstName) {
        return null;
      }
      return {
        dn: firstDn,
        name: firstName,
        description: coerceString(first.description),
        managedByDn: coerceString(first.managedBy),
        groupType: decodeAdGroupType(coerceString(first.groupType)),
      };
    }, credentials);
  }

  async getUserByDn(dn: string, credentials?: DirectorySessionCredentials): Promise<AdUser | null> {
    return this.withClient(async (client) => {
      const result = await client.search(dn, {
        scope: "base",
        filter: "(objectClass=user)",
        attributes: ["distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "mail"],
        sizeLimit: 1,
      });
            const row = result.searchEntries[0] as Record<string, string | string[] | undefined> | undefined;
      const rowDn = coerceString(row?.distinguishedName);
      const rowSam = coerceString(row?.sAMAccountName);
      if (!row || !rowDn || !rowSam) {
        return null;
      }
      return {
        dn: rowDn,
        samAccountName: rowSam,
        userPrincipalName: coerceString(row.userPrincipalName),
        displayName: coerceString(row.displayName),
        mail: coerceString(row.mail),
      };
    }, credentials);
  }
}
