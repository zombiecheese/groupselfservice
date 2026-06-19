import { AdDirectoryRepository, DirectorySessionCredentials, EntraDirectoryRepository } from "./contracts";
import { UserIdentity } from "../domain/models";
import { PortalSettingsService } from "./portal-settings-service";
import { logger } from "../infrastructure/logger";

export class PortalAdminAuthorizationService {
  constructor(
    private readonly settingsService: PortalSettingsService,
    private readonly adRepository: AdDirectoryRepository,
    private readonly entraRepository: EntraDirectoryRepository
  ) {}

  async isPortalAdmin(
    user: UserIdentity,
    isBreakGlass: boolean,
    directoryCredentials?: DirectorySessionCredentials,
    entraAccessToken?: string
  ): Promise<boolean> {
    if (isBreakGlass) {
      return true;
    }

    const settings = await this.settingsService.getSettings();

    // Run AD and Entra lookups in parallel and return as soon as one hit
    // resolves true. Previously this iterated AD groups serially, then
    // Entra groups serially, so for an N-group delegated-admin
    // configuration every /admin/* request waited on every group lookup
    // even when the first one was already a match.
    const adChecks = settings.delegatedAdmin.adGroupDns.map(async (dn) => {
      try {
        return await this.adRepository.isUserMemberOfGroup(user, dn, directoryCredentials);
      } catch (err) {
        logger.warn("admin-check: AD membership lookup failed", { dn, err: (err as Error).message });
        return false;
      }
    });
    const entraChecks = entraAccessToken
      ? settings.delegatedAdmin.entraGroupIds.map(async (id) => {
          try {
            return await this.entraRepository.isUserMemberOfGroup(entraAccessToken, id);
          } catch (err) {
            logger.warn("admin-check: Entra membership lookup failed", { id, err: (err as Error).message });
            return false;
          }
        })
      : [];

    const checks = [...adChecks, ...entraChecks];
    if (checks.length === 0) return false;

    // Promise.any resolves with the first fulfilled `true`; we wrap each
    // promise to throw on `false` so Promise.any short-circuits properly.
    try {
      await Promise.any(
        checks.map((p) => p.then((ok) => (ok ? true : Promise.reject(new Error("not-member")))))
      );
      return true;
    } catch {
      return false;
    }
  }
}
