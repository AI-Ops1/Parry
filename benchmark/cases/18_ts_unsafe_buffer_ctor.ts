export function toHexPayload(input: string): string {
  const b = new Buffer(input);
  return b.toString('hex');
}
