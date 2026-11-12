import useSWR from 'swr';

export function useDataEndpoint(url) {
  return useSWR(url, (u) => fetch(u).then((r) => r.json()));
}
