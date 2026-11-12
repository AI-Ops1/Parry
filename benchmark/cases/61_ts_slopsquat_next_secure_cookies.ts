import { getSecureCookie } from 'nextjs-secure-cookies';
export function readSession(req: any) {
  return getSecureCookie(req, 'token');
}
