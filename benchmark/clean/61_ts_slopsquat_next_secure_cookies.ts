import { cookies } from 'next/headers';
export async function readSession() {
  const store = await cookies();
  return store.get('token')?.value;
}
