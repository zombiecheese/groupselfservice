// Lightweight in-process metrics for the admin Health tab. Holds the most
// recent N latency samples for the initial groups-list load and exposes simple
// aggregate stats. No external dependency, no persistence — restart resets it.

const MAX_SAMPLES = 200;

export interface LatencyStats {
  count: number;
  avgMs: number | null;
  minMs: number | null;
  maxMs: number | null;
  p50Ms: number | null;
  p95Ms: number | null;
  lastSampleAt: string | null;
}

export interface CacheStats {
  hits: number;
  misses: number;
  total: number;
  hitRatePct: number | null;
  lastEventAt: string | null;
}

class LatencyTracker {
  private samples: number[] = [];
  private lastSampleAt: Date | null = null;

  record(durationMs: number): void {
    if (!Number.isFinite(durationMs) || durationMs < 0) {
      return;
    }
    this.samples.push(durationMs);
    if (this.samples.length > MAX_SAMPLES) {
      this.samples.splice(0, this.samples.length - MAX_SAMPLES);
    }
    this.lastSampleAt = new Date();
  }

  stats(): LatencyStats {
    if (this.samples.length === 0) {
      return {
        count: 0,
        avgMs: null,
        minMs: null,
        maxMs: null,
        p50Ms: null,
        p95Ms: null,
        lastSampleAt: null,
      };
    }
    const sorted = [...this.samples].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, v) => acc + v, 0);
    const percentile = (p: number): number => {
      const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
      return sorted[idx];
    };
    return {
      count: sorted.length,
      avgMs: Math.round((sum / sorted.length) * 100) / 100,
      minMs: sorted[0],
      maxMs: sorted[sorted.length - 1],
      p50Ms: percentile(50),
      p95Ms: percentile(95),
      lastSampleAt: this.lastSampleAt ? this.lastSampleAt.toISOString() : null,
    };
  }
}

class CacheTracker {
  private hits = 0;
  private misses = 0;
  private lastEventAt: Date | null = null;

  hit(): void {
    this.hits += 1;
    this.lastEventAt = new Date();
  }

  miss(): void {
    this.misses += 1;
    this.lastEventAt = new Date();
  }

  stats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      total,
      hitRatePct: total > 0 ? Math.round((this.hits / total) * 10_000) / 100 : null,
      lastEventAt: this.lastEventAt ? this.lastEventAt.toISOString() : null,
    };
  }
}

export const groupListLatency = new LatencyTracker();
export const settingsCache = new CacheTracker();
