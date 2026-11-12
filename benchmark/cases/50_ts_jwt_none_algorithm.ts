import jwt from 'jsonwebtoken';
export function verifyAuth(token: string) {
  return jwt.verify(token, 'key', { algorithms: ['none', 'HS256'] });
}
