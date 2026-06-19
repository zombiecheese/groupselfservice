import { AdDirectoryRepository, DirectorySessionCredentials, PortalSettingsRepository } from "../../application/contracts";
import { AdGroup, AdUser, GroupMembershipChange, ManagedGroup, UserIdentity } from "../../domain/models";
import { LdapAdRepository } from "./ldap-ad-repository";
import { MockAdRepository } from "./mock-ad-repository";

export class ConfigurableAdRepository implements AdDirectoryRepository {
  // Cache the resolved underlying repository so the connection pool inside
  // LdapAdRepository actually pays off — building a new instance per call
  // resets the pool. The cache key is the tuple of settings the LDAP
  // client cares about; if the operator changes any of them via the
  // admin UI, the next call rebuilds the repository (and closes the old
  // pool).
  private cached?: { key: string; repo: AdDirectoryRepository };

  constructor(private readonly settingsRepository: PortalSettingsRepository) {}

  private async resolveRepository(): Promise<AdDirectoryRepository> {
    const settings = await this.settingsRepository.get();
    if (!settings.ad.enabled) {
      // Mock has no expensive resources; rebuild each time is fine.
      return new MockAdRepository();
    }

    const key = JSON.stringify({
      url: settings.ad.ldapUrl,
      baseDn: settings.ad.baseDn,
      caPem: settings.ad.tlsCaPem,
      rejectUnauthorized: settings.ad.tlsRejectUnauthorized,
      serverName: settings.ad.tlsServerName,
      ipv4Only: settings.ad.ipv4Only === true,
    });
    if (this.cached && this.cached.key === key) {
      return this.cached.repo;
    }
    // Close the prior pool before replacing it. Cast because the
    // AdDirectoryRepository interface intentionally doesn't expose
    // pool internals — only LdapAdRepository has them.
    if (this.cached) {
      const prior = this.cached.repo as AdDirectoryRepository & { closePool?: () => Promise<void> };
      if (typeof prior.closePool === "function") {
        prior.closePool().catch(() => undefined);
      }
    }
    const repo = new LdapAdRepository(settings.ad.ldapUrl, settings.ad.baseDn, {
      caPem: settings.ad.tlsCaPem,
      rejectUnauthorized: settings.ad.tlsRejectUnauthorized,
      serverName: settings.ad.tlsServerName,
    }, settings.ad.ipv4Only === true);
    this.cached = { key, repo };
    return repo;
  }

  // For graceful shutdown — server.ts calls this so the pool drains before
  // the process exits.
  async closePool(): Promise<void> {
    if (!this.cached) return;
    const prior = this.cached.repo as AdDirectoryRepository & { closePool?: () => Promise<void> };
    if (typeof prior.closePool === "function") {
      await prior.closePool().catch(() => undefined);
    }
    this.cached = undefined;
  }

  async authenticateUser(upnOrSam: string, password: string): Promise<UserIdentity | null> {
    return (await this.resolveRepository()).authenticateUser(upnOrSam, password);
  }

  async getCurrentUser(upnOrSam: string, credentials?: DirectorySessionCredentials): Promise<UserIdentity | null> {
    return (await this.resolveRepository()).getCurrentUser(upnOrSam, credentials);
  }

  async findManagedGroups(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    credentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]> {
    return (await this.resolveRepository()).findManagedGroups(user, includeNested, limit, credentials);
  }

  async getGroupMembers(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return (await this.resolveRepository()).getGroupMembers(groupDn, credentials);
  }

  async searchPrincipals(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    return (await this.resolveRepository()).searchPrincipals(query, limit, credentials);
  }

  async searchAdGroups(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdGroup[]> {
    return (await this.resolveRepository()).searchAdGroups(query, limit, credentials);
  }

  async addGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await (await this.resolveRepository()).addGroupMember(change, credentials);
  }

  async removeGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void> {
    await (await this.resolveRepository()).removeGroupMember(change, credentials);
  }

  async canUserManageGroup(
    user: UserIdentity,
    groupDn: string,
    includeNested: boolean,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    return (await this.resolveRepository()).canUserManageGroup(user, groupDn, includeNested, credentials);
  }

  async isUserMemberOfGroup(
    user: UserIdentity,
    groupDn: string,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    return (await this.resolveRepository()).isUserMemberOfGroup(user, groupDn, credentials);
  }

  async getGroup(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdGroup | null> {
    return (await this.resolveRepository()).getGroup(groupDn, credentials);
  }

  async getUserByDn(dn: string, credentials?: DirectorySessionCredentials): Promise<AdUser | null> {
    return (await this.resolveRepository()).getUserByDn(dn, credentials);
  }
}
