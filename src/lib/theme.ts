import { writable } from 'svelte/store';

const stored = typeof localStorage !== 'undefined'
    ? (localStorage.getItem('theme') ?? 'dark')
    : 'dark';

export const theme = writable<'dark' | 'light'>(stored as 'dark' | 'light');

theme.subscribe(val => {
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem('theme', val);
    }
    if (typeof document !== 'undefined') {
        document.documentElement.classList.toggle('dark', val === 'dark');
        document.documentElement.classList.toggle('light', val === 'light');
    }
});