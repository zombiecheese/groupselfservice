import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

// Single-instance guard. The portal is intentionally single-instance per
// data directory (the lockout map, member-count cache, login-history active
// sessions, and AD ownership cache all live in process memory; a second
// process would silently halve the lockout threshold and undercount active
// sessions). This module enforces that at startup by writing a PID file
// next to the data directory and refusing to boot when it finds the file
// already owned by a live process.
//
// The lock is best-effort: it cannot prevent a determined operator from
// deleting the file, and it will go stale if a previous process was killed
// with -9 before its shutdown handler could run. Stale locks (PID no longer
// alive) are harmlessly reclaimed on the next start.

export interface AcquireResult {
  acquired: boolean;
  // When acquired === false, this is the PID currently holding the lock.
  conflictingPid?: number;
  // Path to the lock file (always set, regardless of outcome).
  lockPath: string;
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isFinite(pid) || pid <= 0) return false;
  try {
    // signal 0 performs no actual signal but throws ESRCH if the process
    // is gone. EPERM means the process exists but is owned by another
    // user — for our purposes the lock is still held.
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EPERM") return true;
    return false;
  }
}

export async function acquireSingleInstanceLock(
  dataDir: string,
  fileName = ".portal.pid"
): Promise<AcquireResult> {
  const lockPath = path.join(dataDir, fileName);
  await fsp.mkdir(dataDir, { recursive: true });

  // Attempt atomic exclusive creation first (O_CREAT | O_EXCL | O_WRONLY).
  // On NFSv4 (including AWS EFS) this is a single server-side operation and
  // cannot race: exactly one caller wins EEXIST vs success. This replaces the
  // previous read-check-write pattern that was non-atomic and could let two
  // processes both read ENOENT and both write their PID.
  let ownedByUs = false;
  try {
    const handle = await fsp.open(lockPath, "wx", 0o600);
    try {
      await handle.writeFile(String(process.pid), "utf-8");
    } finally {
      await handle.close().catch(() => undefined);
    }
    ownedByUs = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    // File already exists — fall through to check whether it is stale.
  }

  if (ownedByUs) {
    return { acquired: true, lockPath };
  }

  // Read the existing lock and decide whether it belongs to a live process.
  let existingPid: number | undefined;
  try {
    const raw = await fsp.readFile(lockPath, "utf-8");
    const parsed = Number((raw || "").trim());
    if (Number.isFinite(parsed) && parsed > 0) existingPid = parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    // File was removed between our failed open and this read (e.g. the owner
    // just shut down). Retry acquisition once.
    try {
      const handle = await fsp.open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(String(process.pid), "utf-8");
      } finally {
        await handle.close().catch(() => undefined);
      }
      return { acquired: true, lockPath };
    } catch {
      // Another process beat us to the retry — treat as locked.
      return { acquired: false, lockPath };
    }
  }

  if (existingPid === process.pid) {
    // Same process — re-acquire is a no-op.
    return { acquired: true, lockPath };
  }

  if (existingPid !== undefined && isProcessAlive(existingPid)) {
    return { acquired: false, conflictingPid: existingPid, lockPath };
  }

  // Stale lock: owner is gone. Unlink and retry with O_EXCL so the
  // operation remains atomic even if two starters race the cleanup.
  try {
    await fsp.unlink(lockPath);
  } catch {
    /* best-effort — another starter may have already claimed it */
  }
  try {
    const handle = await fsp.open(lockPath, "wx", 0o600);
    try {
      await handle.writeFile(String(process.pid), "utf-8");
    } finally {
      await handle.close().catch(() => undefined);
    }
    return { acquired: true, lockPath };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      return { acquired: false, lockPath };
    }
    throw err;
  }
}

export function releaseSingleInstanceLock(lockPath: string): void {
  // Synchronous because this runs in shutdown hooks where the event loop
  // may already be torn down. Best-effort: a stale file is harmless on the
  // next start because we re-check the PID.
  try {
    const raw = fs.readFileSync(lockPath, "utf-8");
    const parsed = Number((raw || "").trim());
    // Only delete the file if it still belongs to us, to avoid clobbering
    // a lock acquired by a successor process during a hand-off.
    if (Number.isFinite(parsed) && parsed === process.pid) {
      fs.unlinkSync(lockPath);
    }
  } catch {
    /* best-effort */
  }
}
