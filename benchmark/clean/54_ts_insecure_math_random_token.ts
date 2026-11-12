import crypto from 'node:crypto';
export function generateResetToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
