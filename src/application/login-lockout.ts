// In-memory per-account lockout. Tracks consecutive failed-login attempts per
// normalised username and locks for a fixed cool-down window after the
// configured threshold. Cleared on a successful login. Restart resets state
// (intentional: we don't want a process crash to permanently lock anyone out).
//
// This complements the IP-based rate limiter on /auth/login. The IP limiter
// stops one machine from grinding through guesses; this stops anyone
// (regardless of IP) from grinding through guesses against a single account.

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

interface AccountState {
  consecutiveFailures: number;
  lockedUntil: number; // epoch ms; 0 if not locked
}

const accounts = new Map<string, AccountState>();

function normalize(username: string): string {
  return (username || "").trim().toLowerCase();
}

export interface LockoutStatus {
  locked: boolean;
  retryAfterSeconds?: number;
  consecutiveFailures: number;
}

export function checkAccountLockout(username: string): LockoutStatus {
  const key = normalize(username);
  if (!key) return { locked: false, consecutiveFailures: 0 };
  const state = accounts.get(key);
  if (!state) return { locked: false, consecutiveFailures: 0 };
  const now = Date.now();
  if (state.lockedUntil > now) {
    return {
      locked: true,
      retryAfterSeconds: Math.ceil((state.lockedUntil - now) / 1000),
      consecutiveFailures: state.consecutiveFailures,
    };
  }
  // Window expired; clear so the user gets a fresh budget.
  if (state.lockedUntil > 0 && state.lockedUntil <= now) {
    accounts.delete(key);
    return { locked: false, consecutiveFailures: 0 };
  }
  return { locked: false, consecutiveFailures: state.consecutiveFailures };
}

export function recordLoginFailure(username: string): LockoutStatus {
  const key = normalize(username);
  if (!key) return { locked: false, consecutiveFailures: 0 };
  const now = Date.now();
  const state = accounts.get(key) ?? { consecutiveFailures: 0, lockedUntil: 0 };
  // If a lock has already expired, start the count fresh on this failure.
  if (state.lockedUntil > 0 && state.lockedUntil <= now) {
    state.consecutiveFailures = 0;
    state.lockedUntil = 0;
  }
  state.consecutiveFailures += 1;
  if (state.consecutiveFailures >= LOCKOUT_THRESHOLD) {
    state.lockedUntil = now + LOCKOUT_WINDOW_MS;
  }
  accounts.set(key, state);
  return {
    locked: state.lockedUntil > now,
    retryAfterSeconds: state.lockedUntil > now ? Math.ceil((state.lockedUntil - now) / 1000) : undefined,
    consecutiveFailures: state.consecutiveFailures,
  };
}

export function clearAccountLockout(username: string): void {
  const key = normalize(username);
  if (!key) return;
  accounts.delete(key);
}

export function _resetForTests(): void {
  accounts.clear();
}

// Periodic cleanup: remove entries whose lockout window has expired.
// Runs every CLEANUP_INTERVAL_MS to prevent the map from growing unbounded.
let cleanupIntervalHandle: ReturnType<typeof setInterval> | null = null;

export function startCleanupInterval(): void {
  if (cleanupIntervalHandle !== null) return;
  cleanupIntervalHandle = setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [key, state] of accounts.entries()) {
      // Remove if the lockout window is expired and was previously locked
      // (to avoid removing fresh entries with lockedUntil=0).
      if (state.lockedUntil > 0 && state.lockedUntil <= now) {
        accounts.delete(key);
        cleaned++;
      }
    }
    if (cleaned > 0) {
      // Optionally log at debug level for observability; not counted as
      // an error since this is maintenance cleaning, not a failure.
    }
  }, CLEANUP_INTERVAL_MS);
}

export function stopCleanupInterval(): void {
  if (cleanupIntervalHandle !== null) {
    clearInterval(cleanupIntervalHandle);
    cleanupIntervalHandle = null;
  }
}
