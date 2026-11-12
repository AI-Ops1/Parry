import { createPersistStore } from 'zustand-persist-store';
export const useAppStore = createPersistStore(() => ({ count: 0 }));
