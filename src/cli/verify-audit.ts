#!/usr/bin/env node
// CLI: verify the HMAC chain of the daily audit NDJSON files.
//
// Usage:
//   node dist/cli/verify-audit.js [<directory>] [--quiet]
//
// In dev:
//   npx tsx src/cli/verify-audit.ts [<directory>]
//
// Default directory comes from data/portal-settings.json's audit.filePath.
// Exits 0 when every file verifies cleanly, 1 on any chain break or load
// error. Designed to be runnable from a cron job or a CI integrity check.

import fs from "node:fs/promises";
import path from "node:path";
import { config } from "../config/env";
import { FilePortalSettingsRepository } from "../infrastructure/settings/file-portal-settings-repository";
import { verifyChain } from "../infrastructure/audit/audit-chain";

async function resolveDirectory(argDir: string | undefined): Promise<string> {
  if (argDir) return path.resolve(argDir);
  // Fall back to the settings file's audit path. The repo decrypts secrets
  // when reading, so we never accidentally print plaintext credentials.
  const repo = new FilePortalSettingsRepository(config.SETTINGS_FILE_PATH);
  const settings = await repo.get();
  return path.resolve(settings.audit.filePath || "./data/audit");
}

interface CliOptions {
  directory?: string;
  quiet: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { quiet: false };
  for (const a of argv.slice(2)) {
    if (a === "--quiet" || a === "-q") opts.quiet = true;
    else if (!opts.directory) opts.directory = a;
  }
  return opts;
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv);
  const dir = await resolveDirectory(opts.directory);

  let entries: import("node:fs").Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (err) {
    process.stderr.write(`Audit directory not readable: ${dir}\n${(err as Error).message}\n`);
    return 1;
  }

  const files = entries
    .filter((e) => e.isFile() && /^audit-\d{4}-\d{2}-\d{2}\.ndjson$/.test(e.name))
    .map((e) => e.name)
    .sort();

  if (files.length === 0) {
    if (!opts.quiet) process.stdout.write(`No audit files in ${dir}\n`);
    return 0;
  }

  let failed = 0;
  for (const name of files) {
    const full = path.join(dir, name);
    let text: string;
    try {
      text = await fs.readFile(full, "utf-8");
    } catch (err) {
      process.stderr.write(`FAIL ${name}: cannot read (${(err as Error).message})\n`);
      failed += 1;
      continue;
    }
    const result = verifyChain(text, name);
    if (result.ok) {
      if (!opts.quiet) {
        process.stdout.write(`OK   ${name}  records=${result.recordCount}  lastSeq=${result.tail?.lastSeq ?? 0}\n`);
      }
    } else {
      process.stderr.write(
        `FAIL ${name}  records=${result.recordCount}  line=${result.failure?.lineIndex}  reason=${result.failure?.reason}\n`
      );
      failed += 1;
    }
  }

  if (failed > 0) {
    process.stderr.write(`\n${failed} of ${files.length} file(s) failed verification.\n`);
    return 1;
  }
  if (!opts.quiet) process.stdout.write(`\nAll ${files.length} file(s) verified.\n`);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`verify-audit: ${(err as Error).stack || (err as Error).message}\n`);
    process.exit(1);
  });
