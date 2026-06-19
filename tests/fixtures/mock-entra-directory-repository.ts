// Test-only stand-in for EntraDirectoryRepository. Lives under tests/
// so it can never accidentally be wired into the production composition
// root (`ConfigurableEntraDirectoryRepository` falls back to the no-op
// repo, not this mock, when Entra is disabled in settings).
//
// Used by the GroupManagementService unit tests to exercise the AD+Entra
// merge path without touching the network. The dev-only
// `/auth/entra/mock-callback` route assumes the same return values for
// access tokens but does not import this class directly.

import { EntraDirectoryRepository } from "../../src/application/contracts";
import { EntraUser, ManagedGroup } from "../../src/domain/models";

const MOCK_GROUP_ID = "9abf7bb0-b9d8-4bcb-bec3-3fc5276f0d30";

export class MockEntraDirectoryRepository implements EntraDirectoryRepository {
  // In-memory member roster keyed by group id; mutated by add/remove for tests.
  private readonly members: Map<string, EntraUser[]> = new Map([
    [
      MOCK_GROUP_ID,
      [
        {
          id: "11111111-1111-1111-1111-111111111111",
          displayName: "Mock Cloud User",
          userPrincipalName: "mock.cloud@contoso.onmicrosoft.com",
          mail: "mock.cloud@contoso.onmicrosoft.com",
        },
      ],
    ],
  ]);

  private readonly directory: EntraUser[] = [
    {
      id: "11111111-1111-1111-1111-111111111111",
      displayName: "Mock Cloud User",
      userPrincipalName: "mock.cloud@contoso.onmicrosoft.com",
      mail: "mock.cloud@contoso.onmicrosoft.com",
    },
    {
      id: "22222222-2222-2222-2222-222222222222",
      displayName: "Cloud Bob",
      userPrincipalName: "cloud.bob@contoso.onmicrosoft.com",
      mail: "cloud.bob@contoso.onmicrosoft.com",
    },
  ];

  async getAuthorizationUrl(
    state: string,
    _codeChallenge: string,
    _redirectUri: string,
    _options?: { loginHint?: string; domainHint?: string; prompt?: "none" | "login" | "select_account" | "consent" }
  ): Promise<string> {
    return `/auth/entra/mock-callback?state=${encodeURIComponent(state)}&code=mock-code`;
  }

  async exchangeAuthorizationCode(code: string, _codeVerifier: string, _redirectUri: string): Promise<string | null> {
    if (!code) {
      return null;
    }
    return "mock-entra-token";
  }

  async findManagedGroups(accessToken: string, limit: number): Promise<ManagedGroup[]> {
    if (!accessToken) {
      return [];
    }

    const groups: ManagedGroup[] = [
      {
        group: {
          dn: `entra:${MOCK_GROUP_ID}`,
          externalId: MOCK_GROUP_ID,
          name: "Entra-HR-Cloud-App-Admins",
          description: "Cloud app owners group in Entra ID",
        },
        source: "entra",
        ownerType: "entra-owned",
      },
    ];

    return groups.slice(0, limit);
  }

  async isUserMemberOfGroup(_accessToken: string, groupId: string): Promise<boolean> {
    return groupId.toLowerCase() === MOCK_GROUP_ID;
  }

  async isUserOwnerOfGroup(_accessToken: string, groupId: string): Promise<boolean> {
    return groupId.toLowerCase() === MOCK_GROUP_ID;
  }

  async getGroupMembers(_accessToken: string, groupId: string, limit: number): Promise<EntraUser[]> {
    const list = this.members.get(groupId.toLowerCase()) || [];
    return list.slice(0, limit);
  }

  async searchUsers(_accessToken: string, query: string, limit: number): Promise<EntraUser[]> {
    const q = query.toLowerCase();
    return this.directory
      .filter((u) =>
        (u.displayName || "").toLowerCase().includes(q) ||
        (u.userPrincipalName || "").toLowerCase().includes(q) ||
        (u.mail || "").toLowerCase().includes(q)
      )
      .slice(0, limit);
  }

  async addGroupMember(_accessToken: string, groupId: string, userId: string): Promise<void> {
    const key = groupId.toLowerCase();
    const list = this.members.get(key) || [];
    if (list.some((u) => u.id === userId)) {
      return;
    }
    const directoryEntry = this.directory.find((u) => u.id === userId) || { id: userId };
    this.members.set(key, [...list, directoryEntry]);
  }

  async removeGroupMember(_accessToken: string, groupId: string, userId: string): Promise<void> {
    const key = groupId.toLowerCase();
    const list = this.members.get(key) || [];
    this.members.set(key, list.filter((u) => u.id !== userId));
  }
}
