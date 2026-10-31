export async function dispatchWebhooks(urls: string[]): Promise<number> {
  urls.forEach(async (u) => {
    await fetch(u, { method: 'POST' });
  });
  return urls.length;
}
