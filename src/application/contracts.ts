import {
  AdGroup,
  AdUser,
  AuditRecord,
  EntraUser,
  GroupMembershipChange,
  ManagedGroup,
  UserIdentity,
} from "../domain/models";

export interface AdIntegrationSettings {
  enabled: boolean;
  ldapUrl: string;
  baseDn: string;
  includeNestedManagedBy: boolean;
  tlsCaPem: string;
  tlsRejectUnauthorized: boolean;
  tlsServerName: string;
  ipv4Only: boolean;
}

export interface EntraIntegrationSettings {
  enabled: boolean;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  redirectUri: string;
  allowMemberWrites: boolean;
}

export interface AuditIntegrationSettings {
  enabled: boolean;
  filePath: string;
  retentionDays: number;
  syslogEnabled: boolean;
  syslogHost: string;
  syslogPort: number;
  syslogProtocol: "udp4" | "udp6";
  syslogAppName: string;
}

export interface MailIntegrationSettings {
  enabled: boolean;
  mode: "smtp" | "entra";
  fromAddress: string;
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    requireAuth: boolean;
    username: string;
    password: string;
    ignoreTls: boolean;
    allowUntrustedTls: boolean;
  };
  entra: {
    tenantId: string;
    clientId: string;
    clientSecret: string;
    senderUpn: string;
  };
}

export interface BreakGlassSettings {
  username: string;
  passwordSalt: string;
  passwordHash: string;
  // Optional for backward compatibility. Hashes written before the upgrade to
  // 600,000 iterations carry no value here; absence implies the legacy count.
  passwordHashIterations?: number;
}

export interface DelegatedAdminSettings {
  adGroupDns: string[];
  entraGroupIds: string[];
}

export interface NotificationSettings {
  memberAddedEnabled: boolean;
  memberAddedSubject: string;
  memberAddedBody: string;
  memberRemovedEnabled: boolean;
  memberRemovedSubject: string;
  memberRemovedBody: string;
}

export type ThemeMode = "auto" | "light" | "dark";

export interface BrandingSettings {
  siteName: string;
  headerTitle: string;
  themeMode: ThemeMode;
  themePrimary: string;
  themeSecondary: string;
  notificationSuccessColor: string;
  notificationFailColor: string;
  logoDataUrl: string;
}

export interface WebTlsSettings {
  enabled: boolean;
  certPem: string;
  keyPem: string;
  passphrase: string;
  redirectHttpEnabled: boolean;
  redirectHttpPort: number;
}

export interface PortalSettings {
  breakGlass: BreakGlassSettings;
  ad: AdIntegrationSettings;
  entra: EntraIntegrationSettings;
  audit: AuditIntegrationSettings;
  mail: MailIntegrationSettings;
  notifications: NotificationSettings;
  delegatedAdmin: DelegatedAdminSettings;
  branding: BrandingSettings;
  webTls: WebTlsSettings;
  groupDisplay: GroupDisplaySettings;
}

export interface GroupDisplaySettings {
  // Group-type labels (matching the strings produced by the AD/Entra repos
  // in `AdGroup.groupType`) that should be hidden from end users on the
  // groups list. Comparison is case-insensitive and ignores any
  // " \u00b7 Dynamic" suffix so excluding e.g. "Microsoft 365" also hides
  // the dynamic-membership variant.
  excludedTypes: string[];
}

export interface DirectorySessionCredentials {
  username: string;
  password: string;
  /** Opaque random token used as the LDAP connection-pool key. Contains no password material. */
  poolToken: string;
}

export interface AdDirectoryRepository {
  authenticateUser(upnOrSam: string, password: string): Promise<UserIdentity | null>;
  getCurrentUser(upnOrSam: string, credentials?: DirectorySessionCredentials): Promise<UserIdentity | null>;
  findManagedGroups(
    user: UserIdentity,
    includeNested: boolean,
    limit: number,
    credentials?: DirectorySessionCredentials
  ): Promise<ManagedGroup[]>;
  getGroupMembers(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdUser[]>;
  searchPrincipals(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdUser[]>;
  searchAdGroups(query: string, limit: number, credentials?: DirectorySessionCredentials): Promise<AdGroup[]>;
  addGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void>;
  removeGroupMember(change: GroupMembershipChange, credentials?: DirectorySessionCredentials): Promise<void>;
  canUserManageGroup(
    user: UserIdentity,
    groupDn: string,
    includeNested: boolean,
    credentials?: DirectorySessionCredentials
  ): Promise<boolean>;
  isUserMemberOfGroup(user: UserIdentity, groupDn: string, credentials?: DirectorySessionCredentials): Promise<boolean>;
  getGroup(groupDn: string, credentials?: DirectorySessionCredentials): Promise<AdGroup | null>;
  getUserByDn(dn: string, credentials?: DirectorySessionCredentials): Promise<AdUser | null>;
}

export interface EntraDirectoryRepository {
  getAuthorizationUrl(
    state: string,
    codeChallenge: string,
    redirectUri: string,
    options?: { loginHint?: string; domainHint?: string; prompt?: "none" | "login" | "select_account" | "consent" }
  ): Promise<string>;
  exchangeAuthorizationCode(
    code: string,
    codeVerifier: string,
    redirectUri: string
  ): Promise<string | null>;
  findManagedGroups(accessToken: string, limit: number): Promise<ManagedGroup[]>;
  isUserMemberOfGroup(accessToken: string, groupId: string): Promise<boolean>;
  isUserOwnerOfGroup(accessToken: string, groupId: string): Promise<boolean>;
  getGroupMembers(accessToken: string, groupId: string, limit: number): Promise<EntraUser[]>;
  searchUsers(accessToken: string, query: string, limit: number): Promise<EntraUser[]>;
  addGroupMember(accessToken: string, groupId: string, userId: string): Promise<void>;
  removeGroupMember(accessToken: string, groupId: string, userId: string): Promise<void>;
}

export interface PortalSettingsRepository {
  get(): Promise<PortalSettings>;
  save(settings: PortalSettings): Promise<void>;
}

export interface AuditRepository {
  write(record: AuditRecord): Promise<void>;
}
