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

  // Read any existing lock and decide whether it's stale.
  let existingPid: number | undefined;
  try {
    const raw = await fsp.readFile(lockPath, "utf-8");
    const parsed = Number((raw || "").trim());
    if (Number.isFinite(parsed) && parsed > 0) existingPid = parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  if (existingPid !== undefined) {
    if (existingPid === process.pid) {
      // Same process — somehow we're being asked to re-acquire. Treat as ok.
      return { acquired: true, lockPath };
    }
    if (isProcessAlive(existingPid)) {
      return { acquired: false, conflictingPid: existingPid, lockPath };
    }
    // Stale lock: previous owner is gone. Fall through and overwrite.
  }

  await fsp.writeFile(lockPath, String(process.pid), "utf-8");
  try {
    await fsp.chmod(lockPath, 0o600);
  } catch {
    /* best-effort; no-op on Windows */
  }
  return { acquired: true, lockPath };
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
