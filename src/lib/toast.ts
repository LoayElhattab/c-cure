import { writable } from 'svelte/store';

export type Toast = {
    id: number;
    message: string;
    type: 'success' | 'error' | 'info';
};

export const toasts = writable<Toast[]>([]);

let counter = 0;

export function toast(message: string, type: Toast['type'] = 'info', duration = 3000) {
    const id = counter++;
    toasts.update(t => [...t, { id, message, type }]);
    setTimeout(() => {
        toasts.update(t => t.filter(x => x.id !== id));
    }, duration);
}

export const success = (msg: string) => toast(msg, 'success');
export const error = (msg: string) => toast(msg, 'error', 4000);
export const info = (msg: string) => toast(msg, 'info');