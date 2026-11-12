import jwt from 'jsonwebtoken';
export function verifyAuth(token: string, secret: string) {
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}
