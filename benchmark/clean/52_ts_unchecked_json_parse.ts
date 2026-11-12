export function parseWebhookPayload(raw: string) {
  try { return JSON.parse(raw); } catch { return null; }
}
