import { stringify } from "csv-stringify/sync";
import { v4 as uuidv4 } from "uuid";
import { AdDirectoryRepository, AuditRepository, DirectorySessionCredentials, EntraDirectoryRepository } from "./contracts";
import { AdUser, AuditAction, AuditRecord, EntraUser, ManagedGroup, UserIdentity } from "../domain/models";
import { MailService } from "./mail-service";
import { PortalSettingsService } from "./portal-settings-service";
import { logger } from "../infrastructure/logger";

// Group/member references on the wire are either AD distinguished names or
// Entra GUIDs prefixed with "entra:" (groups) and "entra-user:" (members).
// This module dispatches between the AD and Entra repositories based on the
// prefix so the rest of the app can stay source-agnostic.
const ENTRA_GROUP_PREFIX = "entra:";
const ENTRA_USER_PREFIX = "entra-user:";

export type DirectoryMember = {
  ref: string; // dn for AD, "entra-user:{guid}" for Entra
  displayName?: string;
  userPrincipalName?: string;
  samAccountName?: string;
  mail?: string;
  source: "ad" | "entra";
};

function isEntraGroupRef(ref: string): boolean {
  return ref.toLowerCase().startsWith(ENTRA_GROUP_PREFIX);
}

function isEntraUserRef(ref: string): boolean {
  return ref.toLowerCase().startsWith(ENTRA_USER_PREFIX);
}

function stripEntraGroupPrefix(ref: string): string {
  return ref.substring(ENTRA_GROUP_PREFIX.length);
}

function stripEntraUserPrefix(ref: string): string {
  return ref.substring(ENTRA_USER_PREFIX.length);
}

function adUserToMember(user: AdUser): DirectoryMember {
  return {
    ref: user.dn,
    displayName: user.displayName,
    userPrincipalName: user.userPrincipalName,
    samAccountName: user.samAccountName,
    mail: user.mail,
    source: "ad",
  };
}

function entraUserToMember(user: EntraUser): DirectoryMember {
  return {
    ref: `${ENTRA_USER_PREFIX}${user.id}`,
    displayName: user.displayName,
    userPrincipalName: user.userPrincipalName,
    mail: user.mail,
    source: "entra",
  };
}

export class GroupManagementService {
  constructor(
    private readonly adRepository: AdDirectoryRepository,
    private readonly entraRepository: EntraDirectoryRepository,
    private readonly auditRepository: AuditRepository,
    private readonly settingsService: PortalSettingsService,
    private readonly mailService: MailService,
    private readonly maxBatchSize: number,
    // Hard caps on per-request list sizes. Sourced from env in server.ts
    // (MAX_GROUPS_PER_LIST / MAX_MEMBERS_PER_GROUP). Defaulted to the
    // historical magic values so callers that don't pass them get
    // identical behaviour.
    private readonly maxGroupsPerList: number = 500,
    private readonly maxMembersPerGroup: number = 999
  ) {}

  async getManagedGroupsForUser(
    user: UserIdentity,
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]> {
    const settings = await this.settingsService.getSettings();
    const adGroups = await this.adRepository.findManagedGroups(
      user,
      settings.ad.includeNestedManagedBy,
      this.maxGroupsPerList,
      directoryCredentials
    );
    const entraGroups = entraAccessToken
      ? await this.entraRepository.findManagedGroups(entraAccessToken, this.maxGroupsPerList)
      : [];
    const combined = [...adGroups, ...entraGroups];

    // Apply the admin-configured group-type exclusion filter. Comparison is
    // case-insensitive and ignores any " · Dynamic" suffix so excluding a
    // base type also hides its dynamic-membership variant. Groups without a
    // detected type are always shown (no label to compare against).
    const excluded = (settings.groupDisplay?.excludedTypes ?? [])
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    const groups = excluded.length === 0
      ? combined
      : combined.filter((g) => {
          const label = (g.group.groupType || "").toLowerCase().split(" \u00b7 ")[0].trim();
          if (!label) return true;
          return !excluded.includes(label);
        });

    const filteredOut = combined.length - groups.length;
    await this.audit(
      user,
      correlationId,
      "GROUP_LIST",
      "success",
      undefined,
      undefined,
      undefined,
      `Returned ${groups.length} groups${filteredOut > 0 ? ` (${filteredOut} hidden by type filter)` : ""}`
    );
    return groups;
  }

  async getGroupMembersForUser(
    user: UserIdentity,
    groupRef: string,
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<DirectoryMember[]> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    if (isEntraGroupRef(groupRef)) {
      const id = stripEntraGroupPrefix(groupRef);
      const members = await this.entraRepository.getGroupMembers(entraAccessToken!, id, this.maxMembersPerGroup);
      await this.audit(user, correlationId, "GROUP_VIEW_MEMBERS", "success", "entra", groupRef, undefined, `Returned ${members.length} members`);
      return members.map(entraUserToMember);
    }
    const members = await this.adRepository.getGroupMembers(groupRef, directoryCredentials);
    await this.audit(user, correlationId, "GROUP_VIEW_MEMBERS", "success", "ad", groupRef, undefined, `Returned ${members.length} members`);
    return members.map(adUserToMember);
  }

  // Lightweight member-count for the groups-list inline hint. Bypasses the
  // audit emission because we don't want one GROUP_VIEW_MEMBERS record per
  // visible row on every render. Authorization is still enforced via
  // assertCanManage so a forged DN cannot probe arbitrary groups.
  async getGroupMemberCount(
    user: UserIdentity,
    groupRef: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<number> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    if (isEntraGroupRef(groupRef)) {
      const id = stripEntraGroupPrefix(groupRef);
      const members = await this.entraRepository.getGroupMembers(entraAccessToken!, id, this.maxMembersPerGroup);
      return members.length;
    }
    const members = await this.adRepository.getGroupMembers(groupRef, directoryCredentials);
    return members.length;
  }

  async addMember(
    user: UserIdentity,
    groupRef: string,
    memberRef: string,
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<void> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    if (isEntraGroupRef(groupRef)) {
      if (!isEntraUserRef(memberRef)) {
        throw new Error("Entra groups require an Entra user reference.");
      }
      const groupId = stripEntraGroupPrefix(groupRef);
      const userId = stripEntraUserPrefix(memberRef);
      await this.entraRepository.addGroupMember(entraAccessToken!, groupId, userId);
      await this.audit(user, correlationId, "GROUP_ADD_MEMBER", "success", "entra", groupRef, memberRef);
      await this.notifyEntraMembershipChange("added", user, groupRef, userId, entraAccessToken!);
      return;
    }
    if (isEntraUserRef(memberRef)) {
      throw new Error("AD groups require an AD distinguished name member reference.");
    }
    await this.adRepository.addGroupMember({ groupDn: groupRef, memberDn: memberRef }, directoryCredentials);
    await this.audit(user, correlationId, "GROUP_ADD_MEMBER", "success", "ad", groupRef, memberRef);
    await this.notifyMembershipChange("added", user, groupRef, memberRef, directoryCredentials);
  }

  async removeMember(
    user: UserIdentity,
    groupRef: string,
    memberRef: string,
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<void> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    if (isEntraGroupRef(groupRef)) {
      if (!isEntraUserRef(memberRef)) {
        throw new Error("Entra groups require an Entra user reference.");
      }
      const groupId = stripEntraGroupPrefix(groupRef);
      const userId = stripEntraUserPrefix(memberRef);
      await this.entraRepository.removeGroupMember(entraAccessToken!, groupId, userId);
      await this.audit(user, correlationId, "GROUP_REMOVE_MEMBER", "success", "entra", groupRef, memberRef);
      await this.notifyEntraMembershipChange("removed", user, groupRef, userId, entraAccessToken!);
      return;
    }
    if (isEntraUserRef(memberRef)) {
      throw new Error("AD groups require an AD distinguished name member reference.");
    }
    await this.adRepository.removeGroupMember({ groupDn: groupRef, memberDn: memberRef }, directoryCredentials);
    await this.audit(user, correlationId, "GROUP_REMOVE_MEMBER", "success", "ad", groupRef, memberRef);
    await this.notifyMembershipChange("removed", user, groupRef, memberRef, directoryCredentials);
  }

    async bulkAdd(
    user: UserIdentity,
    groupRef: string,
    memberRefs: string[],
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<{ added: number; skipped: number; failed: number }> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    this.assertBatchSize(memberRefs.length);

    let added = 0;
    let skipped = 0;
    let failed = 0;
    const isEntraGroup = isEntraGroupRef(groupRef);
    for (const ref of memberRefs) {
      const trimmed = ref.trim();
      if (!trimmed) {
        skipped += 1;
        continue;
      }
      if (isEntraGroup) {
        if (!isEntraUserRef(trimmed)) {
          skipped += 1;
          continue;
        }
        const userId = stripEntraUserPrefix(trimmed);
        const groupId = stripEntraGroupPrefix(groupRef);
        try {
          await this.entraRepository.addGroupMember(entraAccessToken!, groupId, userId);
          await this.notifyEntraMembershipChange("added", user, groupRef, userId, entraAccessToken!);
          added += 1;
        } catch (err) {
          failed += 1;
          logger.warn("Bulk add member failed", { groupRef, memberRef: trimmed, err: (err as Error).message });
        }
      } else {
        if (isEntraUserRef(trimmed)) {
          skipped += 1;
          continue;
        }
        try {
          await this.adRepository.addGroupMember({ groupDn: groupRef, memberDn: trimmed }, directoryCredentials);
          await this.notifyMembershipChange("added", user, groupRef, trimmed, directoryCredentials);
          added += 1;
        } catch (err) {
          failed += 1;
          logger.warn("Bulk add member failed", { groupRef, memberRef: trimmed, err: (err as Error).message });
        }
      }
    }

    await this.audit(user, correlationId, "GROUP_BULK_ADD", failed > 0 ? "failure" : "success", isEntraGroup ? "entra" : "ad", groupRef, undefined, `added=${added}; skipped=${skipped}; failed=${failed}`);
    return { added, skipped, failed };
  }

    async bulkRemove(
    user: UserIdentity,
    groupRef: string,
    memberRefs: string[],
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<{ removed: number; skipped: number; failed: number }> {
    await this.assertCanManage(user, groupRef, entraAccessToken, directoryCredentials);
    this.assertBatchSize(memberRefs.length);

    let removed = 0;
    let skipped = 0;
    let failed = 0;
    const isEntraGroup = isEntraGroupRef(groupRef);
    for (const ref of memberRefs) {
      const trimmed = ref.trim();
      if (!trimmed) {
        skipped += 1;
        continue;
      }
      if (isEntraGroup) {
        if (!isEntraUserRef(trimmed)) {
          skipped += 1;
          continue;
        }
        const userId = stripEntraUserPrefix(trimmed);
        const groupId = stripEntraGroupPrefix(groupRef);
        try {
          await this.entraRepository.removeGroupMember(entraAccessToken!, groupId, userId);
          await this.notifyEntraMembershipChange("removed", user, groupRef, userId, entraAccessToken!);
          removed += 1;
        } catch (err) {
          failed += 1;
          logger.warn("Bulk remove member failed", { groupRef, memberRef: trimmed, err: (err as Error).message });
        }
      } else {
        if (isEntraUserRef(trimmed)) {
          skipped += 1;
          continue;
        }
        try {
          await this.adRepository.removeGroupMember({ groupDn: groupRef, memberDn: trimmed }, directoryCredentials);
          await this.notifyMembershipChange("removed", user, groupRef, trimmed, directoryCredentials);
          removed += 1;
        } catch (err) {
          failed += 1;
          logger.warn("Bulk remove member failed", { groupRef, memberRef: trimmed, err: (err as Error).message });
        }
      }
    }

    await this.audit(user, correlationId, "GROUP_BULK_REMOVE", failed > 0 ? "failure" : "success", isEntraGroup ? "entra" : "ad", groupRef, undefined, `removed=${removed}; skipped=${skipped}; failed=${failed}`);
    return { removed, skipped, failed };
  }

  async exportMembersCsv(
    user: UserIdentity,
    groupRef: string,
    correlationId: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<string> {
    const members = await this.getGroupMembersForUser(user, groupRef, correlationId, entraAccessToken, directoryCredentials);
    const csv = stringify(
      members.map((member) => ({
        displayName: member.displayName ?? "",
        samAccountName: member.samAccountName ?? "",
        userPrincipalName: member.userPrincipalName ?? "",
        mail: member.mail ?? "",
        ref: member.ref,
        source: member.source,
      })),
      { header: true }
    );
    await this.audit(user, correlationId, "GROUP_EXPORT_MEMBERS", "success", isEntraGroupRef(groupRef) ? "entra" : "ad", groupRef);
    return csv;
  }

  async searchPrincipals(
    user: UserIdentity,
    query: string,
    limit: number,
    correlationId: string,
    options: {
      source?: "ad" | "entra";
      groupRef?: string;
      entraAccessToken?: string;
      directoryCredentials?: DirectorySessionCredentials;
    } = {}
  ): Promise<DirectoryMember[]> {
    const settings = await this.settingsService.getSettings();
    // Pick directory automatically when caller passes a group ref; otherwise
    // honor an explicit source override (defaults to AD for backwards compat).
    const inferredSource: "ad" | "entra" = options.source
      ? options.source
      : options.groupRef && isEntraGroupRef(options.groupRef)
      ? "entra"
      : "ad";

    if (inferredSource === "entra") {
      if (!options.entraAccessToken) {
        return [];
      }
      // If a specific group is provided, verify ownership
      if (options.groupRef) {
        const groupId = stripEntraGroupPrefix(options.groupRef);
        const isOwner = await this.entraRepository.isUserOwnerOfGroup(options.entraAccessToken, groupId);
        if (!isOwner) {
          return [];
        }
      }
      const users = await this.entraRepository.searchUsers(options.entraAccessToken, query, limit);
      await this.audit(user, correlationId, "GROUP_VIEW_MEMBERS", "success", "entra", undefined, undefined, `search=${query}; results=${users.length}`);
      return users.map(entraUserToMember);
    }

    // AD path: verify user owns the specific group (if provided) or any group
    const groups = await this.adRepository.findManagedGroups(
      user,
      settings.ad.includeNestedManagedBy,
      999, // fetch all to check ownership of specific group if provided
      options.directoryCredentials
    );
    if (groups.length === 0) {
      return [];
    }

    // If a specific group is provided, verify it's in the user's managed list
    if (options.groupRef) {
      const ownsGroup = groups.some((g) => g.group.dn === options.groupRef);
      if (!ownsGroup) {
        return [];
      }
    }

    const principals = await this.adRepository.searchPrincipals(query, limit, options.directoryCredentials);
    await this.audit(user, correlationId, "GROUP_VIEW_MEMBERS", "success", "ad", undefined, undefined, `search=${query}; results=${principals.length}`);
    return principals.map(adUserToMember);
  }

  private async assertCanManage(
    user: UserIdentity,
    groupRef: string,
    entraAccessToken?: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<void> {
    const settings = await this.settingsService.getSettings();
    if (isEntraGroupRef(groupRef)) {
      if (!settings.entra.enabled) {
        throw new Error("Entra integration is disabled.");
      }
      if (!settings.entra.allowMemberWrites) {
        throw new Error("Entra group write access is disabled in portal settings.");
      }
      if (!entraAccessToken) {
        throw new Error("Sign in to Entra to manage this group.");
      }
      const groupId = stripEntraGroupPrefix(groupRef);
      const isOwner = await this.entraRepository.isUserOwnerOfGroup(entraAccessToken, groupId);
      if (!isOwner) {
        throw new Error("You are not an owner of this Entra group.");
      }
      return;
    }
    const isAllowed = await this.adRepository.canUserManageGroup(
      user,
      groupRef,
      settings.ad.includeNestedManagedBy,
      directoryCredentials
    );
    if (!isAllowed) {
      // Better error: tell the user who *can* manage this group so they know
      // who to ask, instead of a flat "not authorized". Best-effort lookup;
      // a failure here falls back to the generic message.
      try {
        const group = await this.adRepository.getGroup(groupRef, directoryCredentials);
        if (group?.managedByDn) {
          const owner = await this.adRepository.getUserByDn(group.managedByDn, directoryCredentials);
          const ownerLabel =
            owner?.displayName ||
            owner?.userPrincipalName ||
            owner?.samAccountName ||
            group.managedByDn;
          throw new Error(
            `You are not listed in this group's managedBy attribute. Owner: ${ownerLabel}.`
          );
        }
      } catch (err) {
        // If we already threw above with the friendlier message, rethrow it.
        if (err instanceof Error && err.message.includes("managedBy")) throw err;
        // Otherwise fall through to the generic message.
      }
      throw new Error("You are not authorized to manage this group.");
    }
  }

  private assertBatchSize(size: number): void {
    if (size > this.maxBatchSize) {
      throw new Error(`Batch size of ${size} exceeds maximum of ${this.maxBatchSize}.`);
    }
  }

  private async notifyMembershipChange(
    kind: "added" | "removed",
    actor: UserIdentity,
    groupDn: string,
    memberDn: string,
    directoryCredentials?: DirectorySessionCredentials
  ): Promise<void> {
    try {
      const settings = await this.settingsService.getSettings();
      if (!settings.mail.enabled) {
        return;
      }
      const enabled = kind === "added"
        ? settings.notifications.memberAddedEnabled
        : settings.notifications.memberRemovedEnabled;
      if (!enabled) {
        return;
      }
      const subjectTemplate = kind === "added"
        ? settings.notifications.memberAddedSubject
        : settings.notifications.memberRemovedSubject;
      const bodyTemplate = kind === "added"
        ? settings.notifications.memberAddedBody
        : settings.notifications.memberRemovedBody;

      const [target, group] = await Promise.all([
        this.adRepository.getUserByDn(memberDn, directoryCredentials),
        this.adRepository.getGroup(groupDn, directoryCredentials),
      ]);

      const recipient = target?.mail || target?.userPrincipalName;
      if (!recipient) {
        return;
      }

      const variables = {
        "%targetuser%": target?.displayName || target?.userPrincipalName || target?.samAccountName || memberDn,
        "%groupname%": group?.name || groupDn,
        "%domain%": this.extractDomainFromDn(groupDn) || this.extractDomainFromDn(memberDn) || "",
        "%performedby%": actor.displayName || actor.upn || actor.samAccountName,
      };

      const subject = this.applyTemplate(subjectTemplate, variables);
      const body = this.applyTemplate(bodyTemplate, variables);

      await this.mailService.send({
        to: recipient,
        subject,
        text: body,
      });
    } catch (error) {
      logger.warn("Membership-change notification failed", { err: error, kind, memberDn, groupDn });
    }
  }

  private async notifyEntraMembershipChange(
    kind: "added" | "removed",
    actor: UserIdentity,
    groupRef: string,
    userId: string,
    accessToken: string
  ): Promise<void> {
    try {
      const settings = await this.settingsService.getSettings();
      if (!settings.mail.enabled) {
        return;
      }
      const enabled = kind === "added"
        ? settings.notifications.memberAddedEnabled
        : settings.notifications.memberRemovedEnabled;
      if (!enabled) {
        return;
      }
      const subjectTemplate = kind === "added"
        ? settings.notifications.memberAddedSubject
        : settings.notifications.memberRemovedSubject;
      const bodyTemplate = kind === "added"
        ? settings.notifications.memberAddedBody
        : settings.notifications.memberRemovedBody;

      // Re-read members to find the freshly added/removed user details. For
      // removals the user is no longer in the group so search the directory
      // instead. Failures are non-fatal.
      let recipient = "";
      let displayName = userId;
      try {
        const directoryHits = await this.entraRepository.searchUsers(accessToken, userId, 1);
        const hit = directoryHits[0];
        if (hit) {
          recipient = hit.mail || hit.userPrincipalName || "";
          displayName = hit.displayName || hit.userPrincipalName || userId;
        }
      } catch {
        // ignore â€” best-effort lookup
      }
      if (!recipient) {
        return;
      }

      const variables: Record<string, string> = {
        "%targetuser%": displayName,
        "%groupname%": groupRef,
        "%domain%": "",
        "%performedby%": actor.displayName || actor.upn || actor.samAccountName,
      };
      const subject = this.applyTemplate(subjectTemplate, variables);
      const body = this.applyTemplate(bodyTemplate, variables);
      await this.mailService.send({ to: recipient, subject, text: body });
    } catch (error) {
      logger.warn("Entra membership-change notification failed", { err: error, kind, userId, groupRef });
    }
  }

  private applyTemplate(template: string, variables: Record<string, string>): string {
    let output = template || "";
    for (const [key, value] of Object.entries(variables)) {
      output = output.split(key).join(value);
    }
    return output;
  }

  private extractDomainFromDn(dn: string): string {
    const parts = dn
      .split(",")
      .map((segment) => segment.trim())
      .filter((segment) => segment.toUpperCase().startsWith("DC="))
      .map((segment) => segment.substring(3));
    return parts.join(".");
  }

  private async audit(
    user: UserIdentity,
    correlationId: string,
    action: AuditAction,
    status: "success" | "failure",
    source?: "ad" | "entra",
    targetGroupDn?: string,
    targetMemberDn?: string,
    details?: string
  ): Promise<void> {
    const record: AuditRecord = {
      id: uuidv4(),
      timestampUtc: new Date().toISOString(),
      actorUpn: user.upn,
      actorSamAccountName: user.samAccountName,
      correlationId,
      action,
      source,
      targetGroupDn,
      targetMemberDn,
      status,
      details,
    };
    try {
      await this.auditRepository.write(record);
    } catch (error) {
      logger.error("Audit write failed (non-fatal)", { record, err: error });
      // Do not re-throw; audit failures should not block the primary operation
    }
  }
}
