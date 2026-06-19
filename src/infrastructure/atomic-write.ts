import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

// Atomic write helper. The previous "open + truncate + write" pattern would
// leave the file zero-length if the process crashed or lost power between
// truncate and the final flush — which then made `get()` fall through to
// "create defaults", silently rotating the break-glass admin password. The
// safe pattern is: write to a sibling tmp file in the same directory, fsync
// it, then atomic rename over the destination. POSIX rename is atomic
// within a directory; on Windows, ReplaceFile semantics give the same
// guarantee for files that exist already, which is the steady-state case
// here (the file is created on first save).
//
// For new-file creation the rename is also atomic — the destination either
// exists with the new contents or doesn't exist at all. A previously
// written file is never seen partial.

export interface AtomicWriteOptions {
  // POSIX file mode applied after rename. Best-effort; no-op on Windows.
  mode?: number;
}

export async function writeFileAtomic(
  filePath: string,
  data: string | Buffer,
  options: AtomicWriteOptions = {}
): Promise<void> {
  const dir = path.dirname(filePath);
  await fsp.mkdir(dir, { recursive: true });

  // Tmp file in the same directory so rename is on the same device. A
  // random suffix avoids collisions when concurrent saves happen (callers
  // are expected to single-flight, but we are defensive in case they
  // don't).
  const suffix = crypto.randomBytes(6).toString("hex");
  const tmp = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${suffix}.tmp`);

  let handle: import("node:fs/promises").FileHandle | undefined;
  try {
    handle = await fsp.open(tmp, "w", 0o600);
    await handle.writeFile(data);
    // Flush page cache to disk so a power-cut between write and rename does
    // not give us a renamed-but-empty file. Best-effort: some filesystems
    // (e.g. tmpfs) don't honour fsync, but the rename remains atomic.
    try {
      await handle.sync();
    } catch {
      /* best-effort */
    }
  } finally {
    if (handle) {
      try {
        await handle.close();
      } catch {
        /* already closed */
      }
    }
  }

    try {
    await fsp.rename(tmp, filePath);
  } catch (err) {
    // On Windows, rename() over an existing file that is still open by
    // another handle throws EPERM (-4048). Fall back to copy+unlink which
    // works even when the destination is open.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EPERM" && process.platform === "win32") {
      try {
        await fsp.copyFile(tmp, filePath);
        await fsp.unlink(tmp).catch(() => undefined);
      } catch (fallbackErr) {
        await fsp.unlink(tmp).catch(() => undefined);
        throw fallbackErr;
      }
    } else {
      // Cross-device or other permission failure: clean up the tmp file
      // so we don't leak it on retry.
      try {
        await fsp.unlink(tmp);
      } catch {
        /* best-effort */
      }
      throw err;
    }
  }

  if (options.mode !== undefined) {
    try {
      await fsp.chmod(filePath, options.mode);
    } catch {
      /* best-effort; no-op on Windows */
    }
  }
}
