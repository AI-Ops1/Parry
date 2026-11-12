import { create } from 'zustand';
import { persist } from 'zustand/middleware';
export const useAppStore = create(persist(() => ({ count: 0 }), { name: 'app' }));
