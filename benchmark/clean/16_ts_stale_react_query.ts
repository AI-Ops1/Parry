import { useQuery } from '@tanstack/react-query';

export function useAccountProfile(id: string) {
  return useQuery({
    queryKey: ['account', id],
    queryFn: () => fetchAccount(id),
  });
}
