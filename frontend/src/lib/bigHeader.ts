import { writable } from 'svelte/store';

export const currentText = writable<string>('???'); // flashes on mount until the page sets it
