import { NextFunction, Request, Response } from "express";
import { UserIdentity } from "../domain/models";

declare module "express-session" {
  interface SessionData {
    user?: UserIdentity;
    entraAccessToken?: string;
    entraAuthState?: string;
    entraPkceVerifier?: string;
    entraSilentAttempted?: boolean;
    entraBannerDismissed?: boolean;
    isBreakGlass?: boolean;
    isPortalAdmin?: boolean;
    // Cached portal-admin decision with epoch-ms expiry. Populated by the
    // /admin/* gating middleware; ignored when expired or when relevant
    // session inputs (entra token, break-glass flag) change.
    isPortalAdminCheckedAt?: number;
    isPortalAdminCheckEntraToken?: string;
    encryptedDirectoryCredentials?: string;
    encryptedEntraAccessToken?: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      user?: UserIdentity;
      correlationId: string;
      csrfToken: () => string;
    }
  }
}

export function attachUserFromSession(req: Request, _res: Response, next: NextFunction): void {
  if (req.session.user) {
    req.user = req.session.user;
  }

  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.redirect("/auth/login");
    return;
  }
  next();
}
