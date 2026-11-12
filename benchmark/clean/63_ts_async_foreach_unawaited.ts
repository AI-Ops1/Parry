export async function persistAuditLogs(logs: any[]): Promise<void> {
  for (const log of logs) { await db.insert(log); }
}
