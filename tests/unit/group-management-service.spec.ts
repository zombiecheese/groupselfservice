import { describe, expect, it } from "vitest";
import { GroupManagementService } from "../../src/application/group-management-service";
import { MailService } from "../../src/application/mail-service";
import { MockAdRepository } from "../../src/infrastructure/ad/mock-ad-repository";
import { NoopAuditRepository } from "../../src/infrastructure/audit/noop-audit-repository";
import { MockEntraDirectoryRepository } from "../fixtures/mock-entra-directory-repository";
import { PortalSettingsService } from "../../src/application/portal-settings-service";
import { PortalSettings, PortalSettingsRepository } from "../../src/application/contracts";

const ALICE = {
  upn: "alice.admin@contoso.local",
  samAccountName: "alice.admin",
  displayName: "Alice Admin",
  dn: "CN=Alice Admin,OU=Users,DC=contoso,DC=local",
};

function buildSettings(overrides?: Partial<PortalSettings>): PortalSettings {
  const base = PortalSettingsService.createDefaultSettings();
  return { ...base, ...(overrides || {}) };
}

function buildService(settings: PortalSettings) {
  const settingsRepository: PortalSettingsRepository = {
    get: async () => settings,
    save: async () => undefined,
  };
  return {
    settingsRepository,
    service: new GroupManagementService(
      new MockAdRepository(),
      new MockEntraDirectoryRepository(),
      new NoopAuditRepository(),
      new PortalSettingsService(settingsRepository),
      new MailService(settingsRepository),
      200
    ),
  };
}

describe("GroupManagementService", () => {
  it("returns managed groups for a valid owner", async () => {
    const { service } = buildService(buildSettings());
    const groups = await service.getManagedGroupsForUser(ALICE, "corr-unit-1");
    expect(groups.length).toBeGreaterThan(0);
  });

  it("merges AD and Entra groups when an Entra token is provided", async () => {
    const { service } = buildService(buildSettings());
    const groups = await service.getManagedGroupsForUser(ALICE, "corr-merge", "mock-entra-token");
    const sources = groups.map((g) => g.source).sort();
    expect(sources).toContain("entra");
    expect(sources).toContain("ad");
  });

  it("refuses Entra writes when allowMemberWrites is disabled", async () => {
    const settings = buildSettings();
    settings.entra = { ...settings.entra, enabled: true, allowMemberWrites: false };
    const { service } = buildService(settings);
    await expect(
      service.addMember(
        ALICE,
        "entra:9abf7bb0-b9d8-4bcb-bec3-3fc5276f0d30",
        "entra-user:11111111-1111-1111-1111-111111111111",
        "corr-write-off",
        "mock-entra-token"
      )
    ).rejects.toThrow(/disabled/i);
  });

  it("refuses Entra writes when no token is presented", async () => {
    const settings = buildSettings();
    settings.entra = { ...settings.entra, enabled: true, allowMemberWrites: true };
    const { service } = buildService(settings);
    await expect(
      service.addMember(
        ALICE,
        "entra:9abf7bb0-b9d8-4bcb-bec3-3fc5276f0d30",
        "entra-user:11111111-1111-1111-1111-111111111111",
        "corr-no-token"
      )
    ).rejects.toThrow(/Sign in to Entra/i);
  });

  it("adds and removes Entra members through the dispatcher", async () => {
    const settings = buildSettings();
    settings.entra = { ...settings.entra, enabled: true, allowMemberWrites: true };
    const { service } = buildService(settings);
    const groupRef = "entra:9abf7bb0-b9d8-4bcb-bec3-3fc5276f0d30";

    await service.addMember(
      ALICE,
      groupRef,
      "entra-user:22222222-2222-2222-2222-222222222222",
      "corr-add",
      "mock-entra-token"
    );

    const members = await service.getGroupMembersForUser(ALICE, groupRef, "corr-list", "mock-entra-token");
    expect(members.find((m) => m.ref === "entra-user:22222222-2222-2222-2222-222222222222")).toBeDefined();

    await service.removeMember(
      ALICE,
      groupRef,
      "entra-user:22222222-2222-2222-2222-222222222222",
      "corr-remove",
      "mock-entra-token"
    );

    const after = await service.getGroupMembersForUser(ALICE, groupRef, "corr-list2", "mock-entra-token");
    expect(after.find((m) => m.ref === "entra-user:22222222-2222-2222-2222-222222222222")).toBeUndefined();
  });

  it("rejects mismatched member refs (AD group + Entra user)", async () => {
    const { service } = buildService(buildSettings());
    await expect(
      service.addMember(
        ALICE,
        "CN=HR-App-Users,OU=Groups,DC=contoso,DC=local",
        "entra-user:22222222-2222-2222-2222-222222222222",
        "corr-mix"
      )
    ).rejects.toThrow();
  });
});
