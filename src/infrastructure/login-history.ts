import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { writeFileAtomic } from "./atomic-write";

// Minimal duck-typed view of express-session's Store. Only `get(sid, cb)`
// is used for reconciliation; declaring our own interface here avoids a
// hard dependency on the express-session type just so the login-history
// store can sweep stale sids.
interface SessionStoreLike {
  get(
    sid: string,
    callback: (err: Error | null, session?: unknown) => void
  ): void;
}

// Tracks two pieces of per-user state for the security-visibility UI:
//
//   1. The previous successful login timestamp + IP + UA for each user
//      (persisted JSON at data/login-history.json so it survives restarts).
//
//   2. The set of currently-active sessions per user. Held in memory only:
//      the portal is intentionally single-instance (see
//      `single-instance-lock.ts` and the README), so this map is the
//      authoritative view for the running process. A second process is
//      refused at startup.
//
// The store is owned by a single instance of LoginHistoryStore that the
// auth and groups routes share.

export interface LoginAttemptInfo {
  timestamp: string; // ISO-8601
  ip?: string;
  userAgent?: string;
}

export interface ActiveSessionInfo {
  sid: string;
  createdAt: string;
  ip?: string;
  userAgent?: string;
}

type DiskShape = Record<string, { previous?: LoginAttemptInfo; latest?: LoginAttemptInfo }>;

function nowIso(): string {
  return new Date().toISOString();
}

export class LoginHistoryStore {
  private readonly filePath: string;
  private cache: DiskShape = {};
  private writeQueue: Promise<void> = Promise.resolve();
  private readonly active = new Map<string, Map<string, ActiveSessionInfo>>();

  constructor(filePath: string) {
    this.filePath = filePath;
    try {
      if (fs.existsSync(filePath)) {
        const raw = fs.readFileSync(filePath, "utf-8");
        if (raw.trim()) {
          this.cache = JSON.parse(raw) as DiskShape;
        }
      }
    } catch {
      // Corrupt or unreadable: start fresh; the next write rewrites the file.
      this.cache = {};
    }
  }

  // ---- Login history (persisted) -----------------------------------------

  getLastLogin(username: string): LoginAttemptInfo | undefined {
    const key = this.normalize(username);
    return key ? this.cache[key]?.previous : undefined;
  }

  async recordLogin(username: string, info: LoginAttemptInfo): Promise<void> {
    const key = this.normalize(username);
    if (!key) return;
    const entry = this.cache[key] ?? {};
    entry.previous = entry.latest;
    entry.latest = info;
    this.cache[key] = entry;
    await this.persist();
  }

  // ---- Active sessions (in-memory) ---------------------------------------

  registerSession(username: string, sid: string, info: Omit<ActiveSessionInfo, "sid" | "createdAt">): void {
    const key = this.normalize(username);
    if (!key || !sid) return;
    let bucket = this.active.get(key);
    if (!bucket) {
      bucket = new Map();
      this.active.set(key, bucket);
    }
    bucket.set(sid, {
      sid,
      createdAt: nowIso(),
      ip: info.ip,
      userAgent: info.userAgent,
    });
  }

  unregisterSession(username: string, sid: string): void {
    const key = this.normalize(username);
    if (!key || !sid) return;
    const bucket = this.active.get(key);
    if (!bucket) return;
    bucket.delete(sid);
    if (bucket.size === 0) this.active.delete(key);
  }

  // Returns every sid for the user except the one passed in. Caller is
  // responsible for asking express-session to destroy them.
  listOtherSessionIds(username: string, currentSid: string): string[] {
    const key = this.normalize(username);
    if (!key) return [];
    const bucket = this.active.get(key);
    if (!bucket) return [];
    return Array.from(bucket.keys()).filter((s) => s !== currentSid);
  }

  forgetOtherSessions(username: string, currentSid: string): number {
    const ids = this.listOtherSessionIds(username, currentSid);
    const key = this.normalize(username);
    if (!key || ids.length === 0) return 0;
    const bucket = this.active.get(key);
    if (!bucket) return 0;
    for (const id of ids) bucket.delete(id);
    if (bucket.size === 0) this.active.delete(key);
    return ids.length;
  }

  // ---- Reconciliation ----------------------------------------------------

  // Walk the user's tracked sids and drop any whose session is gone from
  // the underlying express-session store. Closing a browser tab does not
  // hit the logout endpoint, so without this sweep the "N other active
  // sessions" widget over-reports. Called lazily before reading the
  // widget; cheap because most users have ≤ 2 sids and `get()` against
  // session-file-store is a single fs.stat + read.
  async reconcileWithStore(username: string, store: SessionStoreLike): Promise<void> {
    const key = this.normalize(username);
    if (!key) return;
    const bucket = this.active.get(key);
    if (!bucket || bucket.size === 0) return;
    const sids = Array.from(bucket.keys());
    await Promise.all(
      sids.map(
        (sid) =>
          new Promise<void>((resolve) => {
            store.get(sid, (err, session) => {
              // Treat anything other than "got a session object back" as
              // gone. Errors usually mean the file was reaped or never
              // existed, both of which should drop the entry. Be conservative:
              // we never resurrect a real session by mistake here.
              if (err || !session) {
                bucket.delete(sid);
              }
              resolve();
            });
          })
      )
    );
    if (bucket.size === 0) this.active.delete(key);
  }

  // ---- Internals ---------------------------------------------------------

  private normalize(username: string | undefined | null): string {
    return (username || "").trim().toLowerCase();
  }

    private async persist(): Promise<void> {
    // Single-flight writer so concurrent recordLogin calls don't race on
    // the file. Uses atomic write (tmp + rename) so a crash never leaves
    // the file truncated.
    //
    // Important: the queue promise must always resolve so that the *next*
    // write still runs. A rejected `.then()` would cause `.then()` on the
    // next call to skip its callback, permanently silencing all future
    // writes for the lifetime of the process. We keep the queue moving
    // with `.catch(() => undefined)` while still surfacing the error to
    // the immediate caller via the separate `task` reference.
    const task = this.writeQueue.then(async () => {
      await fsp.mkdir(path.dirname(this.filePath), { recursive: true });
      await writeFileAtomic(
        this.filePath,
        JSON.stringify(this.cache, null, 2),
        { mode: 0o600 }
      );
    });
    this.writeQueue = task.catch(() => undefined);
    return task;
  }
}
