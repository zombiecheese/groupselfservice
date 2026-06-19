// Production fallback used when AD integration is disabled in portal
// settings. Despite the name, this is NOT a test fixture — the
// `ConfigurableAdRepository` returns this implementation whenever
// `settings.ad.enabled === false` so the portal renders something
// recognisable in the first-run / Entra-only deployment shapes.
//
// The dataset is intentionally tiny (one demo owner, one demo group) so
// the empty-state UI has shape without leaking confidential names.
// Mutations are in-memory only and reset on process restart.
//
// The test-only Entra mock lives under `tests/fixtures/`; this AD one
// stays here precisely because it ships in the production bundle.

import { AdDirectoryRepository, DirectorySessionCredentials } from "../../application/contracts";
import { AdGroup, AdUser, GroupMembershipChange, ManagedGroup, UserIdentity } from "../../domain/models";
import { logger } from "../logger";

export class MockAdRepository implements AdDirectoryRepository {
  private readonly users: AdUser[] = [
    {
      dn: "CN=Alice Admin,OU=Users,DC=contoso,DC=local",
      samAccountName: "alice.admin",
      userPrincipalName: "alice.admin@contoso.local",
      displayName: "Alice Admin",
      mail: "alice.admin@contoso.local",
    },
    {
      dn: "CN=Bob User,OU=Users,DC=contoso,DC=local",
      samAccountName: "bob.user",
      userPrincipalName: "bob.user@contoso.local",
      displayName: "Bob User",
      mail: "bob.user@contoso.local",
    },
  ];

  private readonly groups: AdGroup[] = [
    {
      dn: "CN=HR-App-Users,OU=Groups,DC=contoso,DC=local",
      name: "HR-App-Users",
      description: "Access group for HR application",
      managedByDn: "CN=Alice Admin,OU=Users,DC=contoso,DC=local",
    },
  ];

  private readonly nestedManagerGroupDn = "CN=App-Owners,OU=Groups,DC=contoso,DC=local";

  private readonly groupMembers = new Map<string, Set<string>>([
    ["CN=HR-App-Users,OU=Groups,DC=contoso,DC=local", new Set(["CN=Bob User,OU=Users,DC=contoso,DC=local"])],
  ]);

  private readonly delegatedAdminGroupDn = "CN=Portal-Admins,OU=Groups,DC=contoso,DC=local";

  async getCurrentUser(upnOrSam: string, _credentials?: DirectorySessionCredentials): Promise<UserIdentity | null> {
    const found = this.users.find(
      (x) =>
        x.samAccountName.toLowerCase() === upnOrSam.toLowerCase() ||
        x.userPrincipalName?.toLowerCase() === upnOrSam.toLowerCase()
    );
    if (!found) {
      return null;
    }
    return {
      upn: found.userPrincipalName || `${found.samAccountName}@contoso.local`,
      samAccountName: found.samAccountName,
      displayName: found.displayName || found.samAccountName,
      dn: found.dn,
    };
  }

  async authenticateUser(upnOrSam: string, password: string): Promise<UserIdentity | null> {
    if (process.env.NODE_ENV === "production") {
      logger.warn("MockAdRepository.authenticateUser called in production - verify AD integration is enabled in settings", { upnOrSam });
    }
    if (!password) {
      return null;
    }
    return this.getCurrentUser(upnOrSam);
  }

  async findManagedGroups(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    _credentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]> {
    const managed: ManagedGroup[] = [];

    for (const group of this.groups) {
      if (group.managedByDn?.toLowerCase() === user.dn?.toLowerCase()) {
        managed.push({ group, source: "ad", ownerType: "direct" });
      }
    }

    if (includeNested && user.samAccountName === "alice.admin") {
      managed.push({
        group: {
          dn: "CN=Finance-App-Users,OU=Groups,DC=contoso,DC=local",
          name: "Finance-App-Users",
          description: "Managed via nested owner group",
          managedByDn: this.nestedManagerGroupDn,
        },
        source: "ad",
        ownerType: "nested",
        ownerPath: ["App-Owners"],
      });
    }

    return managed.slice(0, limit);
  }

  async getGroupMembers(groupDn: string, _credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    const members = this.groupMembers.get(groupDn);
    if (!members) {
      return [];
    }
    return this.users.filter((u) => members.has(u.dn));
  }

  async searchPrincipals(query: string, limit: number, _credentials?: DirectorySessionCredentials): Promise<AdUser[]> {
    const q = query.toLowerCase();
    return this.users
      .filter((x) =>
        x.samAccountName.toLowerCase().includes(q) ||
        x.displayName?.toLowerCase().includes(q) ||
        x.mail?.toLowerCase().includes(q)
      )
      .slice(0, limit);
  }

  async searchAdGroups(query: string, limit: number, _credentials?: DirectorySessionCredentials): Promise<AdGroup[]> {
    const q = query.toLowerCase();
    return this.groups
      .filter((g) => g.name.toLowerCase().includes(q) || g.dn.toLowerCase().includes(q))
      .slice(0, limit);
  }

  async addGroupMember(change: GroupMembershipChange, _credentials?: DirectorySessionCredentials): Promise<void> {
    if (!this.groupMembers.has(change.groupDn)) {
      this.groupMembers.set(change.groupDn, new Set<string>());
    }
    this.groupMembers.get(change.groupDn)?.add(change.memberDn);
  }

  async removeGroupMember(change: GroupMembershipChange, _credentials?: DirectorySessionCredentials): Promise<void> {
    this.groupMembers.get(change.groupDn)?.delete(change.memberDn);
  }

  async canUserManageGroup(
    user: UserIdentity,
    groupDn: string,
    includeNested: boolean,
    _credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    const managed = await this.findManagedGroups(user, includeNested, 2000);
    return managed.some((x) => x.group.dn === groupDn);
  }

  async isUserMemberOfGroup(
    user: UserIdentity,
    groupDn: string,
    _credentials?: DirectorySessionCredentials
  ): Promise<boolean> {
    if (groupDn !== this.delegatedAdminGroupDn) {
      return false;
    }
    return user.samAccountName === "alice.admin";
  }

  async getGroup(groupDn: string, _credentials?: DirectorySessionCredentials): Promise<AdGroup | null> {
    return this.groups.find((x) => x.dn === groupDn) || null;
  }

  async getUserByDn(dn: string, _credentials?: DirectorySessionCredentials): Promise<AdUser | null> {
    return this.users.find((x) => x.dn.toLowerCase() === dn.toLowerCase()) || null;
  }
}
