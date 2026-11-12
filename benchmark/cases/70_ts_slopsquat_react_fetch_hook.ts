import { useFetchApi } from 'react-use-fetch-hook';
export function useProfile() { return useFetchApi('/me'); }
