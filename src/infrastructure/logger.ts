import { createLogger, format, transport, transports } from "winston";
import DailyRotateFile from "winston-daily-rotate-file";

// Logger transports.
//
// By default we only write to stdout — the right choice for containerised
// deployments (docker / k8s / systemd-journal handles rotation, capture,
// and shipping). For bare-metal installs the operator can set LOG_DIR to
// any writable directory and we'll add a daily-rotated file transport
// alongside stdout. Files are JSON (one record per line), rotate at
// midnight or 20 MB, and are kept for 14 days. None of this is on the
// request hot path.
const enabledTransports: transport[] = [new transports.Console()];

const logDir = (process.env.LOG_DIR || "").trim();
if (logDir) {
  const fileTransport = new DailyRotateFile({
    dirname: logDir,
    filename: "groupselfservice-%DATE%.log",
    datePattern: "YYYY-MM-DD",
    maxSize: "20m",
    maxFiles: "14d",
    zippedArchive: true,
    auditFile: `${logDir.replace(/[\\/]+$/, "")}/.rotate-audit.json`,
    extension: ".log",
  });
  enabledTransports.push(fileTransport);
}

export const logger = createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  format: format.combine(format.timestamp(), format.errors({ stack: true }), format.json()),
  transports: enabledTransports,
});
