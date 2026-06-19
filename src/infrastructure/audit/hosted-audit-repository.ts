import dgram from "node:dgram";
import fs from "node:fs/promises";
import path from "node:path";
import { AuditRepository } from "../../application/contracts";
import { AuditRecord } from "../../domain/models";
import { ChainTail, computeRecordHmac } from "./audit-chain";

export interface HostedAuditOptions {
  directoryPath: string;
  retentionDays: number;
  syslogEnabled: boolean;
  syslogHost: string;
  syslogPort: number;
  syslogProtocol: "udp4" | "udp6";
  syslogAppName: string;
}

export class HostedAuditRepository implements AuditRepository {
  private writesSinceCleanup = 0;
  // Per-file chain tail. Keyed by daily file name so we don't re-read the
  // file from disk on every append. Populated lazily — the first write of
  // a process for a given file scans the file to recover the tail. Single-
  // instance deployment makes this safe; multi-instance would race here.
  private readonly tails = new Map<string, ChainTail>();
  // Single-flight write queue so concurrent `write()` calls can't both
  // read the same tail and produce duplicate seq numbers / a broken chain.
  private writeQueue: Promise<void> = Promise.resolve();
  // Persistent UDP socket for syslog, lazily initialized and reused.
  private syslogSocket: ReturnType<typeof dgram.createSocket> | null = null;

  constructor(private options: HostedAuditOptions) {}

  // Update non-path options in-place. The chain state (tails, writeQueue)
  // is tied to the directoryPath and must NOT be discarded when only
  // syslog/retention settings change. Callers must create a new instance
  // if directoryPath changes.
  updateOptions(next: HostedAuditOptions): void {
    // Close the syslog socket if host/port/protocol changed to force re-creation
    // with new settings on next send.
    if (
      this.syslogSocket &&
      (next.syslogHost !== this.options.syslogHost ||
        next.syslogPort !== this.options.syslogPort ||
        next.syslogProtocol !== this.options.syslogProtocol)
    ) {
      this.syslogSocket.close();
      this.syslogSocket = null;
    }
    this.options = next;
  }

  // Read records from the daily NDJSON files between two ISO-8601 timestamps
  // (both inclusive). The filename uses UTC date so the file selection set
  // is built from the start/end days; per-record filtering uses the actual
  // timestampUtc. Returns records sorted by timestamp descending (newest
  // first) and capped at `limit`. Designed for the admin Audit viewer; not
  // suitable for very large windows because everything is held in memory.
  async read(query: {
    fromIso: string;
    toIso: string;
    limit?: number;
    actorContains?: string;
    actionEquals?: string;
    sourceEquals?: "ad" | "entra";
    groupContains?: string;
    statusEquals?: "success" | "failure";
  }): Promise<AuditRecord[]> {
    const limit = Math.max(1, Math.min(query.limit ?? 1000, 10_000));
    const fromMs = Date.parse(query.fromIso);
    const toMs = Date.parse(query.toIso);
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs > toMs) {
      return [];
    }

    let entries: { name: string; isFile: () => boolean }[];
    try {
      entries = await fs.readdir(this.options.directoryPath, { withFileTypes: true });
    } catch {
      return [];
    }

    const inWindow = (name: string): boolean => {
      // audit-YYYY-MM-DD.ndjson
      const m = /^audit-(\d{4})-(\d{2})-(\d{2})\.ndjson$/.exec(name);
      if (!m) return false;
      const fileDayMs = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
      // Include the file if its calendar day overlaps the window.
      return fileDayMs >= Date.UTC(
        new Date(fromMs).getUTCFullYear(),
        new Date(fromMs).getUTCMonth(),
        new Date(fromMs).getUTCDate()
      ) && fileDayMs <= toMs;
    };

    const candidateFiles = entries
      .filter((e) => e.isFile() && e.name.startsWith("audit-") && e.name.endsWith(".ndjson") && inWindow(e.name))
      .map((e) => e.name)
      .sort()
      .reverse(); // newest day first

    const actorNeedle = (query.actorContains || "").trim().toLowerCase();
    const groupNeedle = (query.groupContains || "").trim().toLowerCase();
    const actionFilter = (query.actionEquals || "").trim();
    const sourceFilter = query.sourceEquals;
    const statusFilter = query.statusEquals;

    const results: AuditRecord[] = [];
    for (const name of candidateFiles) {
      if (results.length >= limit) break;
      let text: string;
      try {
        text = await fs.readFile(path.join(this.options.directoryPath, name), "utf-8");
      } catch {
        continue;
      }
      const lines = text.split(/\r?\n/);
      // Iterate newest-first within a file. Lines are appended in order so
      // we reverse to surface the most recent entries first.
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        const line = lines[i];
        if (!line) continue;
        let record: AuditRecord;
        try {
          record = JSON.parse(line) as AuditRecord;
        } catch {
          continue;
        }
        const ts = Date.parse(record.timestampUtc);
        if (!Number.isFinite(ts) || ts < fromMs || ts > toMs) continue;
        if (actorNeedle) {
          const haystack = `${record.actorUpn || ""} ${record.actorSamAccountName || ""}`.toLowerCase();
          if (haystack.indexOf(actorNeedle) === -1) continue;
        }
        if (actionFilter && record.action !== actionFilter) continue;
        if (sourceFilter && record.source !== sourceFilter) continue;
        if (statusFilter && record.status !== statusFilter) continue;
        if (groupNeedle) {
          const groupHay = (record.targetGroupDn || "").toLowerCase();
          if (groupHay.indexOf(groupNeedle) === -1) continue;
        }
        results.push(record);
        if (results.length >= limit) break;
      }
    }
    return results;
  }

  async write(record: AuditRecord): Promise<void> {
    // Serialise writes through a single-flight queue so the seq / hmac
    // chain can never race. Each enqueued task awaits the prior, reads
    // the chain tail (from cache or recovers from the file), computes
    // seq and hmac for this record, appends the line, and updates the
    // in-memory tail.
    const queued = this.writeQueue.then(() => this.appendChained(record));
    // Swallow errors on the chain to keep the queue moving; the per-call
    // caller still sees the rejection via the returned promise.
    this.writeQueue = queued.catch(() => undefined);
    await queued;

    if (this.options.syslogEnabled) {
      await this.sendToSyslog(record);
    }

    this.writesSinceCleanup += 1;
    if (this.writesSinceCleanup >= 20) {
      this.writesSinceCleanup = 0;
      await this.cleanupExpiredFiles();
    }
  }

  private async appendChained(record: AuditRecord): Promise<void> {
    await fs.mkdir(this.options.directoryPath, { recursive: true });

    const fileName = this.getDailyFileName(record.timestampUtc);
    const filePath = path.join(this.options.directoryPath, fileName);
    const isNewFile = !(await fs.stat(filePath).then(() => true).catch(() => false));

    let tail = this.tails.get(fileName);
    if (!tail) {
      // First write for this file in this process. Recover the tail by
      // reading the file's last non-empty line (avoids replaying the
      // whole chain just to find seq+1). If the file is missing / empty,
      // start fresh.
      tail = await this.recoverTail(filePath);
      this.tails.set(fileName, tail);
    }

    const nextSeq = tail.lastSeq + 1;
    // Mutate the caller's record to attach the chain fields before
    // serialising. Order matters for canonical JSON: seq + hmac are
    // appended last so the rest of the record matches the historical
    // shape.
    const signed: AuditRecord = { ...record, seq: nextSeq };
    const hmac = computeRecordHmac(tail.lastHmac, signed);
    signed.hmac = hmac;
    // Mutate the caller-supplied record too so downstream observers
    // (e.g. syslog forwarder) see the seq/hmac fields.
    (record as AuditRecord).seq = nextSeq;
    (record as AuditRecord).hmac = hmac;

    await fs.appendFile(filePath, `${JSON.stringify(signed)}\n`, "utf-8");
    if (isNewFile) {
      try {
        await fs.chmod(filePath, 0o600);
      } catch {
        /* best-effort */
      }
    }
    tail.lastSeq = nextSeq;
    tail.lastHmac = hmac;
  }

  private async recoverTail(filePath: string): Promise<ChainTail> {
    let text: string;
    try {
      text = await fs.readFile(filePath, "utf-8");
    } catch {
      return { lastSeq: 0, lastHmac: "" };
    }
    const lines = text.split(/\r?\n/);
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      const line = lines[i];
      if (!line) continue;
      try {
        const last = JSON.parse(line) as AuditRecord;
        return {
          lastSeq: typeof last.seq === "number" ? last.seq : 0,
          lastHmac: typeof last.hmac === "string" ? last.hmac : "",
        };
      } catch {
        return { lastSeq: 0, lastHmac: "" };
      }
    }
    return { lastSeq: 0, lastHmac: "" };
  }

  private getDailyFileName(timestampUtc: string): string {
    const date = new Date(timestampUtc);
    const yyyy = date.getUTCFullYear();
    const mm = `${date.getUTCMonth() + 1}`.padStart(2, "0");
    const dd = `${date.getUTCDate()}`.padStart(2, "0");
    return `audit-${yyyy}-${mm}-${dd}.ndjson`;
  }

  private async cleanupExpiredFiles(): Promise<void> {
    if (this.options.retentionDays <= 0) {
      return;
    }

    const cutoff = Date.now() - this.options.retentionDays * 24 * 60 * 60 * 1000;
    const entries = await fs.readdir(this.options.directoryPath, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.startsWith("audit-") || !entry.name.endsWith(".ndjson")) {
        continue;
      }

      const filePath = path.join(this.options.directoryPath, entry.name);
      const stat = await fs.stat(filePath);
      if (stat.mtimeMs < cutoff) {
        await fs.unlink(filePath);
      }
    }
  }

  private async sendToSyslog(record: AuditRecord): Promise<void> {
    // Lazily create or reuse the persistent UDP socket.
    if (!this.syslogSocket) {
      this.syslogSocket = dgram.createSocket(this.options.syslogProtocol);
    }

    const severity = record.status === "success" ? 6 : 3;
    const facility = 16;
    const pri = facility * 8 + severity;
    const timestamp = new Date(record.timestampUtc).toISOString();
    const hostname = "groupselfservice";
    const appName = this.options.syslogAppName;
    const msg = JSON.stringify(record);
    const payload = `<${pri}>1 ${timestamp} ${hostname} ${appName} - - - ${msg}`;

    await new Promise<void>((resolve, reject) => {
      this.syslogSocket!.send(
        Buffer.from(payload, "utf-8"),
        this.options.syslogPort,
        this.options.syslogHost,
        (error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        }
      );
    });
  }
}
