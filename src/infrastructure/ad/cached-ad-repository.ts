import { AdDirectoryRepository, DirectorySessionCredentials } from "../../application/contracts";
import { AdGroup, AdUser, GroupMembershipChange, ManagedGroup, UserIdentity } from "../../domain/models";
import crypto from "node:crypto";

interface OwnershipEntry {
  expires: number;
  groups: ManagedGroup[];
}

/**
 * Decorator that adds a short TTL + LRU in-memory cache for
 * {@link findManagedGroups}, which is the hot read on the groups page.
 * Other operations are pass-through.
 *
 * The cache is keyed by `(userDn|userUpn)|includeNested|limit`. Entries
 * are evicted when:
 *   - the TTL expires (read path), or
 *   - the LRU capacity is exceeded (write path; oldest entry dropped), or
 *   - a member add/remove targets a user (`invalidateUser`) — because
 *     `includeNested=true` ownership listings include groups owned via
 *     the member's group membership, so changing membership can change
 *     the target user's owned-groups list.
 */
export class CachedAdRepository implements AdDirectoryRepository {
  // Map iteration order is insertion order in JS, so we get LRU semantics
  // for free: on every hit we delete + re-insert the entry (moves it to
  // the end), and on overflow we drop the first entry (oldest).
  private readonly cache = new Map<string, OwnershipEntry>();

  constructor(
    private readonly inner: AdDirectoryRepository,
    private readonly ttlMs: number = 60_000,
    // Hard cap on cached users. 500 covers a single-instance pilot of
    // mid-size orgs comfortably; each entry is one user × the small
    // number of (includeNested, limit) variants the app calls with.
    private readonly maxEntries: number = 500
  ) {}

  private credentialHash(credentials?: DirectorySessionCredentials): string {
    if (!credentials?.username) {
      return "none";
    }
    // Hash the credential username to avoid leaking sensitive info in the cache key.
    // This prevents cross-user cache poisoning if two users query with the same
    // (userDn, includeNested, limit) but different credentials.
    return crypto
      .createHash("sha256")
      .update(credentials.username)
      .digest("hex")
      .substring(0, 8);
  }

  private keyForUser(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    credentials?: DirectorySessionCredentials
  ): string {
    const id = (user.dn || user.upn || user.samAccountName || "").toLowerCase();
    const credHash = this.credentialHash(credentials);
    return `${id}|${includeNested ? 1 : 0}|${limit}|${credHash}`;
  }

  // Invalidate every cache entry that has the given DN as its keying user.
  // Called on add/remove member to keep ownership listings in sync with the
  // change the affected user just lived through.
  invalidateUserDn(dn: string): void {
    const id = (dn || "").toLowerCase();
    if (!id) return;
    for (const key of this.cache.keys()) {
      if (key.startsWith(`${id}|`)) {
        this.cache.delete(key);
      }
    }
  }

  // Forward to the inner repo if it carries an LDAP connection pool;
  // a no-op otherwise. Lets server.ts drain pooled connections during
  // graceful shutdown without knowing the concrete type.
  async closePool(): Promise<void> {
    const inner = this.inner as AdDirectoryRepository & { closePool?: () => Promise<void> };
    if (typeof inner.closePool === "function") {
      await inner.closePool().catch(() => undefined);
    }
  }

  authenticateUser(upnOrSam: string, password: string): Promise<UserIdentity | null> {
    return this.inner.authenticateUser(upnOrSam, password);
  }

  getCurrentUser(upnOrSam: string, credentials?: DirectorySessionCredentials): Promise<UserIdentity | null> {
    return this.inner.getCurrentUser(upnOrSam, credentials);
  }

  async findManagedGroups(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    credentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]> {
    const key = this.keyForUser(user, includeNested, limit, credentials);
    const cached = this.cache.get(key);
    if (cached && cached.expires > Date.now()) {
      // LRU touch: re-insert to move to most-recent.
      this.cache.delete(key);
      this.cache.set(key, cached);
      return cached.groups;
    }
    if (cached) {
      // Expired entry — drop it before fetching to keep the map tidy.
      this.cache.delete(key);
    }
    const groups = await this.inner.findManagedGroups(user, includeNested, limit, credentials);
    // LRU evict: if at capacity, drop the oldest entry (the first one
    // returned by Map's insertion-order iterator).
    if (this.cache.size >= this.maxEntries) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, { groups, expires: Date.now() + this.ttlMs });
    return groups;
  }

  getGroupMembers(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return this.inner.getGroupMembers(groupDn, credentials);
  }

  searchPrincipals(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return this.inner.searchPrincipals(query, limit, credentials);
  }

  searchAdGroups(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdGroup[]> {
    return this.inner.searchAdGroups(query, limit, credentials);
  }

  async addGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await this.inner.addGroupMember(change, credentials);
    // The added user's own `findManagedGroups` result may now include
    // groups owned via the just-joined owner-group (when includeNested
    // is true). Invalidate that user's entries so their next visit to
    // /groups picks up the change immediately instead of after the TTL.
    this.invalidateUserDn(change.memberDn);
  }

  async removeGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await this.inner.removeGroupMember(change, credentials);
    // Symmetric: the removed user may lose nested ownership.
    this.invalidateUserDn(change.memberDn);
  }

  canUserManageGroup(
    user: UserIdentity,
    groupDn: string,
    includeNested: boolean,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    return this.inner.canUserManageGroup(user, groupDn, includeNested, credentials);
  }

  isUserMemberOfGroup(
    user: UserIdentity,
    groupDn: string,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    return this.inner.isUserMemberOfGroup(user, groupDn, credentials);
  }

  getGroup(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdGroup | null> {
    return this.inner.getGroup(groupDn, credentials);
  }

  getUserByDn(dn: string, credentials?: DirectorySessionCredentials): Promise<AdUser | null> {
    return this.inner.getUserByDn(dn, credentials);
  }
}
