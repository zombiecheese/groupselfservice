// Typed HTTP error. Service-layer code throws these to signal a specific
// 4xx outcome (validation, authorisation, not found) without the global
// error handler having to rely on string matching against `err.message`.
//
// Routes can keep throwing plain Error for genuinely unexpected failures —
// those still surface as 500 with the correlation id. HttpError is for the
// known, user-actionable cases.
//
// Usage:
//   throw HttpError.notFound("Group not found");
//   throw HttpError.forbidden("Only managedBy owners may edit this group");
//   throw HttpError.badRequest("Member DN is malformed");

export class HttpError extends Error {
  public readonly status: number;
  public readonly publicMessage: string;
  public readonly code?: string;

  constructor(status: number, publicMessage: string, code?: string) {
    super(publicMessage);
    this.name = "HttpError";
    this.status = status;
    this.publicMessage = publicMessage;
    this.code = code;
  }

  static badRequest(message: string, code?: string): HttpError {
    return new HttpError(400, message, code);
  }

  static unauthorized(message = "Sign-in required", code?: string): HttpError {
    return new HttpError(401, message, code);
  }

  static forbidden(message = "Access denied", code?: string): HttpError {
    return new HttpError(403, message, code);
  }

  static notFound(message = "Not found", code?: string): HttpError {
    return new HttpError(404, message, code);
  }

  static conflict(message: string, code?: string): HttpError {
    return new HttpError(409, message, code);
  }

  static tooManyRequests(message = "Too many requests", code?: string): HttpError {
    return new HttpError(429, message, code);
  }
}

export function isHttpError(value: unknown): value is HttpError {
  return value instanceof HttpError;
}
