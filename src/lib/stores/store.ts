import { writable } from 'svelte/store';

export const pendingAnalysis = writable<{
  type: 'file' | 'folder';
  path: string;
} | null>(null);