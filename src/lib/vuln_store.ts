import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';

export const totalVulnCount = writable<number>(0);

export async function refreshVulnCount(): Promise<void> {
    try {
        const data = await invoke<any>('get_vuln_count');
        totalVulnCount.set(data.count ?? 0);
    } catch (_) { /* silently fail — badge is non-critical */ }
}