export function parseWebhookPayload(raw: string) {
  return JSON.parse(raw);
}
