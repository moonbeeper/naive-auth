import { writable } from 'svelte/store';

export const currentText = writable<string>('Unknown');
