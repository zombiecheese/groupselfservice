import { Session, SessionData } from "express-session";
import { DirectorySessionCredentials } from "../application/contracts";
import { config } from "../config/env";
import {
  decryptDirectoryCredentials,
  encryptDirectoryCredentials,
  decryptEntraAccessToken,
  encryptEntraAccessToken,
} from "../infrastructure/security/session-crypto";

export function setDirectoryCredentials(
  session: Session & Partial<SessionData>,
  credentials?: DirectorySessionCredentials
): void {
  if (!credentials) {
    session.encryptedDirectoryCredentials = undefined;
    return;
  }

  session.encryptedDirectoryCredentials = encryptDirectoryCredentials(
    credentials,
    config.CREDENTIAL_ENCRYPTION_KEY
  );
}

export function getDirectoryCredentials(
  session: Session & Partial<SessionData>
): DirectorySessionCredentials | undefined {
  if (!session.encryptedDirectoryCredentials) {
    return undefined;
  }

  return (
    decryptDirectoryCredentials(
      session.encryptedDirectoryCredentials,
      config.CREDENTIAL_ENCRYPTION_KEY
    ) ?? undefined
  );
}

export function setEntraAccessToken(
  session: Session & Partial<SessionData>,
  token?: string
): void {
  if (!token) {
    session.encryptedEntraAccessToken = undefined;
    return;
  }

  session.encryptedEntraAccessToken = encryptEntraAccessToken(token, config.CREDENTIAL_ENCRYPTION_KEY);
}

export function getEntraAccessToken(
  session: Session & Partial<SessionData>
): string | undefined {
  if (!session.encryptedEntraAccessToken) {
    return undefined;
  }

  return decryptEntraAccessToken(session.encryptedEntraAccessToken, config.CREDENTIAL_ENCRYPTION_KEY) ?? undefined;
}
