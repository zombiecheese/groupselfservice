import { EntraDirectoryRepository, PortalSettingsRepository } from "../../application/contracts";
import { EntraUser, ManagedGroup } from "../../domain/models";
import { EntraDirectoryGraphRepository } from "./entra-directory-repository";
import { NoopEntraDirectoryRepository } from "./noop-entra-directory-repository";

export class ConfigurableEntraDirectoryRepository implements EntraDirectoryRepository {
  // Cache the resolved underlying repository so the Entra client can be reused
  // across method calls. The cache key is the tuple of settings the Entra
  // client cares about; if the operator changes any of them via the admin UI,
  // the next call rebuilds the repository.
  private cached?: { key: string; repo: EntraDirectoryRepository };

  constructor(private readonly settingsRepository: PortalSettingsRepository) {}

  private async resolveRepository(): Promise<EntraDirectoryRepository> {
    const settings = await this.settingsRepository.get();
    if (!settings.entra.enabled || !settings.entra.tenantId || !settings.entra.clientId) {
      return new NoopEntraDirectoryRepository();
    }

    const key = JSON.stringify({
      tenantId: settings.entra.tenantId,
      clientId: settings.entra.clientId,
      scope: settings.entra.scope,
      redirectUri: settings.entra.redirectUri,
      clientSecret: settings.entra.clientSecret || null,
    });
    if (this.cached && this.cached.key === key) {
      return this.cached.repo;
    }

    const repo = new EntraDirectoryGraphRepository(
      settings.entra.tenantId,
      settings.entra.clientId,
      settings.entra.scope,
      settings.entra.clientSecret || undefined
    );
    this.cached = { key, repo };
    return repo;
  }

  async getAuthorizationUrl(
    state: string,
    codeChallenge: string,
    _redirectUri: string,
    options?: { loginHint?: string; domainHint?: string; prompt?: "none" | "login" | "select_account" | "consent" }
  ): Promise<string> {
    const settings = await this.settingsRepository.get();
    return (await this.resolveRepository()).getAuthorizationUrl(
      state,
      codeChallenge,
      settings.entra.redirectUri,
      options
    );
  }

  async exchangeAuthorizationCode(code: string, codeVerifier: string, _redirectUri: string): Promise<string | null> {
    const settings = await this.settingsRepository.get();
    return (await this.resolveRepository()).exchangeAuthorizationCode(code, codeVerifier, settings.entra.redirectUri);
  }

  async findManagedGroups(accessToken: string, limit: number): Promise<ManagedGroup[]> {
    return (await this.resolveRepository()).findManagedGroups(accessToken, limit);
  }

  async isUserMemberOfGroup(accessToken: string, groupId: string): Promise<boolean> {
    return (await this.resolveRepository()).isUserMemberOfGroup(accessToken, groupId);
  }

  async isUserOwnerOfGroup(accessToken: string, groupId: string): Promise<boolean> {
    return (await this.resolveRepository()).isUserOwnerOfGroup(accessToken, groupId);
  }

  async getGroupMembers(accessToken: string, groupId: string, limit: number): Promise<EntraUser[]> {
    return (await this.resolveRepository()).getGroupMembers(accessToken, groupId, limit);
  }

  async searchUsers(accessToken: string, query: string, limit: number): Promise<EntraUser[]> {
    return (await this.resolveRepository()).searchUsers(accessToken, query, limit);
  }

  async addGroupMember(accessToken: string, groupId: string, userId: string): Promise<void> {
    return (await this.resolveRepository()).addGroupMember(accessToken, groupId, userId);
  }

  async removeGroupMember(accessToken: string, groupId: string, userId: string): Promise<void> {
    return (await this.resolveRepository()).removeGroupMember(accessToken, groupId, userId);
  }
}
