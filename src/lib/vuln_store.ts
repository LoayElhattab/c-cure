import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';

export const totalVulnCount = writable<number>(0);

export async function refreshVulnCount(): Promise<void> {
    try {
        // Uses get_vuln_count — a single COUNT(*) query, not the full dashboard
        const raw = await invoke<string>('get_vuln_count');
        const data = JSON.parse(raw);
        totalVulnCount.set(data.count ?? 0);
    } catch (_) { /* silently fail — badge is non-critical */ }
}