import { AuditRepository } from "../../application/contracts";
import { AuditRecord } from "../../domain/models";

export class NoopAuditRepository implements AuditRepository {
  async write(_record: AuditRecord): Promise<void> {
    return;
  }
}
