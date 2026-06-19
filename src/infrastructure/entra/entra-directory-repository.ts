import { EntraDirectoryRepository } from "../../application/contracts";
import { EntraUser, ManagedGroup } from "../../domain/models";

interface EntraGroupResponse {
  id: string;
  displayName?: string;
  description?: string;
  securityEnabled?: boolean;
  mailEnabled?: boolean;
  groupTypes?: string[];
}

interface EntraUserResponse {
  id: string;
  displayName?: string;
  userPrincipalName?: string;
  mail?: string;
}

interface EntraTokenResponse {
  access_token?: string;
  expires_in?: number;
}

function escapeOData(value: string): string {
  return value.replace(/'/g, "''");
}

// Map Microsoft Graph's group flags to a friendly label.
//   Unified                   -> Microsoft 365
//   securityEnabled + mail    -> Mail-enabled Security
//   securityEnabled           -> Security
//   mailEnabled               -> Distribution
// Suffix " · Dynamic" when the group has dynamic membership.
function decodeEntraGroupType(
  securityEnabled?: boolean,
  mailEnabled?: boolean,
  groupTypes?: string[]
): string | undefined {
  const types = (groupTypes || []).map((t) => t.toLowerCase());
  const isUnified = types.includes("unified");
  const isDynamic = types.includes("dynamicmembership");
  let base: string | undefined;
  if (isUnified) {
    base = "Microsoft 365";
  } else if (securityEnabled && mailEnabled) {
    base = "Mail-enabled Security";
  } else if (securityEnabled) {
    base = "Security";
  } else if (mailEnabled) {
    base = "Distribution";
  }
  if (!base) return undefined;
  return isDynamic ? `${base} \u00b7 Dynamic` : base;
}

async function readGraphErrorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    if (body && body.error) {
      const code = body.error.code ? `${body.error.code}: ` : "";
      return `${code}${body.error.message || ""}`.trim() || `Graph error (HTTP ${response.status})`;
    }
  } catch {
    // fall through
  }
  return `Graph error (HTTP ${response.status})`;
}

export class EntraDirectoryGraphRepository implements EntraDirectoryRepository {
  constructor(
    private readonly tenantId: string,
    private readonly clientId: string,
    private readonly scope: string,
    private readonly clientSecret?: string
  ) {}

  async getAuthorizationUrl(
    state: string,
    codeChallenge: string,
    redirectUri: string,
    options?: { loginHint?: string; domainHint?: string; prompt?: "none" | "login" | "select_account" | "consent" }
  ): Promise<string> {
    const authEndpoint = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/authorize`;
    const query = new URLSearchParams({
      client_id: this.clientId,
      response_type: "code",
      redirect_uri: redirectUri,
      response_mode: "query",
      scope: this.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    // login_hint pre-fills the email field on Microsoft's sign-in page, so a
    // user who has just authenticated to AD doesn't have to retype their UPN.
    // domain_hint can short-circuit home-realm discovery for federated
    // tenants, sometimes skipping the account-picker step entirely.
    if (options?.loginHint) {
      query.set("login_hint", options.loginHint);
    }
    if (options?.domainHint) {
      query.set("domain_hint", options.domainHint);
    }
    // `prompt=none` asks AAD to issue a token without any interactive UI. If
    // the browser already has a Microsoft session we land back on /callback
    // instantly; otherwise AAD redirects back with error=login_required and
    // the caller can retry without the prompt parameter.
    if (options?.prompt) {
      query.set("prompt", options.prompt);
    }
    return `${authEndpoint}?${query.toString()}`;
  }

  async exchangeAuthorizationCode(
    code: string,
    codeVerifier: string,
    redirectUri: string
  ): Promise<string | null> {
    const tokenEndpoint = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code,
      redirect_uri: redirectUri,
      scope: this.scope,
      code_verifier: codeVerifier,
    });

    if (this.clientSecret) {
      body.set("client_secret", this.clientSecret);
    }

    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return null;
    }

    const token = (await response.json()) as EntraTokenResponse;
    return token.access_token ?? null;
  }

  async findManagedGroups(accessToken: string, limit: number): Promise<ManagedGroup[]> {
    const response = await fetch("https://graph.microsoft.com/v1.0/me/ownedObjects/microsoft.graph.group?$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return [];
    }

    const json = (await response.json()) as { value?: EntraGroupResponse[] };
    const groups = json.value ?? [];

    return groups.slice(0, limit).map((group) => ({
      group: {
        dn: `entra:${group.id}`,
        externalId: group.id,
        name: group.displayName ?? group.id,
        description: group.description,
        groupType: decodeEntraGroupType(group.securityEnabled, group.mailEnabled, group.groupTypes),
      },
      source: "entra",
      ownerType: "entra-owned",
    }));
  }

  async isUserMemberOfGroup(accessToken: string, groupId: string): Promise<boolean> {
    const response = await fetch("https://graph.microsoft.com/v1.0/me/checkMemberGroups", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        groupIds: [groupId],
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return false;
    }

    const json = (await response.json()) as { value?: string[] };
    return (json.value ?? []).some((id) => id.toLowerCase() === groupId.toLowerCase());
  }

  async isUserOwnerOfGroup(accessToken: string, groupId: string): Promise<boolean> {
    const url = `https://graph.microsoft.com/v1.0/me/ownedObjects/microsoft.graph.group?$select=id&$top=999`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
      return false;
    }
    const json = (await response.json()) as { value?: Array<{ id: string }> };
    const target = groupId.toLowerCase();
    return (json.value ?? []).some((g) => (g.id || "").toLowerCase() === target);
  }

  async getGroupMembers(accessToken: string, groupId: string, limit: number): Promise<EntraUser[]> {
    const top = Math.min(Math.max(limit, 1), 999);
    const url =
      `https://graph.microsoft.com/v1.0/groups/${encodeURIComponent(groupId)}/members?` +
      `$select=id,displayName,userPrincipalName,mail&$top=${top}`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
      throw new Error(await readGraphErrorMessage(response));
    }
    const json = (await response.json()) as { value?: EntraUserResponse[] };
    return (json.value ?? []).slice(0, limit).map((u) => ({
      id: u.id,
      displayName: u.displayName,
      userPrincipalName: u.userPrincipalName,
      mail: u.mail,
    }));
  }

  async searchUsers(accessToken: string, query: string, limit: number): Promise<EntraUser[]> {
    const top = Math.min(Math.max(limit, 1), 100);
    // Validate query against allowlist pattern to prevent OData filter injection.
    // Allow alphanumeric, dots, @, spaces, underscores, and hyphens (common in email/UPN).
    const validQueryPattern = /^[a-zA-Z0-9.@_ -]*$/;
    if (!validQueryPattern.test(query)) {
      return [];
    }
    const q = escapeOData(query);
    const filter = `startswith(displayName,'${q}') or startswith(userPrincipalName,'${q}') or startswith(mail,'${q}')`;
    const url =
      `https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail&$top=${top}` +
      `&$filter=${encodeURIComponent(filter)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}`, ConsistencyLevel: "eventual" },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) {
      throw new Error(await readGraphErrorMessage(response));
    }
    const json = (await response.json()) as { value?: EntraUserResponse[] };
    return (json.value ?? []).slice(0, limit).map((u) => ({
      id: u.id,
      displayName: u.displayName,
      userPrincipalName: u.userPrincipalName,
      mail: u.mail,
    }));
  }

  async addGroupMember(accessToken: string, groupId: string, userId: string): Promise<void> {
    const url = `https://graph.microsoft.com/v1.0/groups/${encodeURIComponent(groupId)}/members/$ref`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        "@odata.id": `https://graph.microsoft.com/v1.0/directoryObjects/${userId}`,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    // 204 No Content on success. 400 with "already exists" is treated as idempotent success.
    if (response.status === 204 || response.status === 201) {
      return;
    }
    const message = await readGraphErrorMessage(response);
    if (response.status === 400 && /already exist|exist/i.test(message)) {
      return;
    }
    throw new Error(message);
  }

  async removeGroupMember(accessToken: string, groupId: string, userId: string): Promise<void> {
    const url = `https://graph.microsoft.com/v1.0/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}/$ref`;
    const response = await fetch(url, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(15_000),
    });
    // 204 No Content on success. 404 is treated as idempotent success (already not a member).
    if (response.status === 204 || response.status === 404) {
      return;
    }
    throw new Error(await readGraphErrorMessage(response));
  }
}
