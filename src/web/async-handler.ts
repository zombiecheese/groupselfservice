import { Request, Response, NextFunction, RequestHandler } from "express";

// Express 4 does not catch rejected promises from async route handlers or
// middleware. If an `async (req, res) => { ... }` callback rejects, the
// error disappears into an UnhandledPromiseRejection and the client hangs
// forever (or, in Node 15+, the process crashes). This wrapper forwards any
// rejection to `next(err)` so Express's global error handler renders a
// proper error page / JSON response.
//
// Usage:
//   router.get("/path", asyncHandler(async (req, res) => { ... }));
//   router.use(asyncHandler(async (req, res, next) => { ... }));

type AsyncRequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void>;

export function asyncHandler(fn: AsyncRequestHandler): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
