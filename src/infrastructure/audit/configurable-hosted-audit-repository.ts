import { AuditRepository, PortalSettingsRepository } from "../../application/contracts";
import { AuditRecord } from "../../domain/models";
import { HostedAuditOptions, HostedAuditRepository } from "./hosted-audit-repository";

export class ConfigurableHostedAuditRepository implements AuditRepository {
  // Cache key is the directoryPath alone. The chain state (tails map,
  // single-flight write queue) inside HostedAuditRepository is bound to the
  // directory — discarding the instance whenever syslog or retention settings
  // change would lose the in-memory chain tail and risk duplicate seq numbers
  // or a broken HMAC chain on the next append. Non-path options are hot-
  // swapped via `updateOptions()` instead.
  private cachedDirPath?: string;
  private cachedRepository?: HostedAuditRepository;

  constructor(private readonly settingsRepository: PortalSettingsRepository) {}

    private resolveRepository(options: HostedAuditOptions): HostedAuditRepository {
    // Only recreate when the directory path changes — that invalidates the
    // file-based chain state. All other options are hot-swapped.
    if (this.cachedRepository && this.cachedDirPath === options.directoryPath) {
      this.cachedRepository.updateOptions(options);
      return this.cachedRepository;
    }
    this.cachedRepository = new HostedAuditRepository(options);
    this.cachedDirPath = options.directoryPath;
    return this.cachedRepository;
  }

  private buildOptions(settings: import("../../application/contracts").PortalSettings): HostedAuditOptions {
    return {
      directoryPath: settings.audit.filePath,
      retentionDays: settings.audit.retentionDays,
      syslogEnabled: settings.audit.syslogEnabled,
      syslogHost: settings.audit.syslogHost,
      syslogPort: settings.audit.syslogPort,
      syslogProtocol: settings.audit.syslogProtocol,
      syslogAppName: settings.audit.syslogAppName,
    };
  }

  async write(record: AuditRecord): Promise<void> {
    const settings = await this.settingsRepository.get();
    if (!settings.audit.enabled) {
      return;
    }
    await this.resolveRepository(this.buildOptions(settings)).write(record);
  }

  async read(query: {
    fromIso: string;
    toIso: string;
    limit?: number;
    actorContains?: string;
    actionEquals?: string;
    sourceEquals?: "ad" | "entra";
    groupContains?: string;
    statusEquals?: "success" | "failure";
  }): Promise<AuditRecord[]> {
    const settings = await this.settingsRepository.get();
    if (!settings.audit.enabled) return [];
    return this.resolveRepository(this.buildOptions(settings)).read(query);
  }
}
