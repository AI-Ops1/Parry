export function generateResetToken(): string {
  return Math.random().toString(36).substring(2);
}
