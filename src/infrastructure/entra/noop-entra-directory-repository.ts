import { EntraDirectoryRepository } from "../../application/contracts";
import { EntraUser, ManagedGroup } from "../../domain/models";

export class NoopEntraDirectoryRepository implements EntraDirectoryRepository {
  async getAuthorizationUrl(
    _state: string,
    _codeChallenge: string,
    _redirectUri: string,
    _options?: { loginHint?: string; domainHint?: string; prompt?: "none" | "login" | "select_account" | "consent" }
  ): Promise<string> {
    return "/groups";
  }

  async exchangeAuthorizationCode(_code: string, _codeVerifier: string, _redirectUri: string): Promise<string | null> {
    return null;
  }

  async findManagedGroups(_accessToken: string, _limit: number): Promise<ManagedGroup[]> {
    return [];
  }

  async isUserMemberOfGroup(_accessToken: string, _groupId: string): Promise<boolean> {
    return false;
  }

  async isUserOwnerOfGroup(_accessToken: string, _groupId: string): Promise<boolean> {
    return false;
  }

  async getGroupMembers(_accessToken: string, _groupId: string, _limit: number): Promise<EntraUser[]> {
    return [];
  }

  async searchUsers(_accessToken: string, _query: string, _limit: number): Promise<EntraUser[]> {
    return [];
  }

  async addGroupMember(_accessToken: string, _groupId: string, _userId: string): Promise<void> {
    throw new Error("Entra integration is disabled.");
  }

  async removeGroupMember(_accessToken: string, _groupId: string, _userId: string): Promise<void> {
    throw new Error("Entra integration is disabled.");
  }
}
