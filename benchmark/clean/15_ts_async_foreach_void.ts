export async function processQueue(items: string[]): Promise<void> {
  for (const item of items) {
    await processJob(item);
  }
}
