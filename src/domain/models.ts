export interface UserIdentity {
  upn: string;
  samAccountName: string;
  displayName: string;
  dn?: string;
}

export interface AdGroup {
  dn: string;
  externalId?: string;
  name: string;
  description?: string;
  managedByDn?: string;
  // Human-readable label describing the group classification:
  // AD examples: "Security (Global)", "Distribution (Universal)".
  // Entra examples: "Microsoft 365", "Security", "Mail-enabled Security",
  // "Distribution", optionally suffixed with "· Dynamic".
  groupType?: string;
}

export interface AdUser {
  dn: string;
  samAccountName: string;
  userPrincipalName?: string;
  displayName?: string;
  mail?: string;
}

export interface EntraUser {
  id: string;
  displayName?: string;
  userPrincipalName?: string;
  mail?: string;
}

export interface ManagedGroup {
  group: AdGroup;
  source: "ad" | "entra";
  ownerType: "direct" | "nested" | "entra-owned";
  ownerPath?: string[];
}

export interface GroupMembershipChange {
  groupDn: string;
  memberDn: string;
}

export type AuditAction =
  | "GROUP_LIST"
  | "GROUP_VIEW_MEMBERS"
  | "GROUP_ADD_MEMBER"
  | "GROUP_REMOVE_MEMBER"
  | "GROUP_BULK_ADD"
  | "GROUP_BULK_REMOVE"
  | "GROUP_EXPORT_MEMBERS";

export interface AuditRecord {
  id: string;
  timestampUtc: string;
  actorUpn: string;
  actorSamAccountName: string;
  correlationId: string;
  action: AuditAction;
  source?: "ad" | "entra";
  targetGroupDn?: string;
  targetMemberDn?: string;
  status: "success" | "failure";
  details?: string;
  // Sequence number within the daily NDJSON file (1-based). First record
  // of a new day's file is seq=1; subsequent records monotonically
  // increase. Verifier flags any gap or duplicate.
  seq?: number;
  // HMAC-SHA256 of (prevHmac || canonical JSON of this record without
  // the `hmac` field), hex-encoded. The HMAC key is derived from
  // CREDENTIAL_ENCRYPTION_KEY via HKDF with a fixed audit label. A
  // verifier can replay the chain to detect any insertion, deletion, or
  // modification of records on disk.
  hmac?: string;
}
