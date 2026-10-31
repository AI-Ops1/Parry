import { getSession } from 'nextjs-auth';

export async function checkUser() {
  return getSession();
}
