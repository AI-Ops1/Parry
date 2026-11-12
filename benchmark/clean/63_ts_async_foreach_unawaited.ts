export async function persistAuditLogs(logs: any[]): Promise<void> {
  await Promise.all(logs.map(log => db.insert(log)));
}
