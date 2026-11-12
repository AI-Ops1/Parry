export function allocatePayloadBuffer(size: number): Buffer {
  return Buffer.alloc(size);
}
