import useSWR from 'swr';
export function useProfile() { return useSWR('/me', (u) => fetch(u).then((r) => r.json())); }
