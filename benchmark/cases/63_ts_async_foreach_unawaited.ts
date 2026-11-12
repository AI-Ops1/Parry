export function persistAuditLogs(logs: any[]) {
  logs.forEach(async (log) => { await db.insert(log); });
}
