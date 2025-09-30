import { get, writable } from 'svelte/store';
import type { components } from './api/v1';
import client from './api/baseFetch';
import { browser } from '$app/environment';
import { redirect } from '@sveltejs/kit';

// null means not logged in
// undefined means not yet loaded
export const user = writable<components['schemas']['User'] | null | undefined>(undefined);

// my gah, having to put () in if statements makes me get confused
export async function updateAuth(fetch: typeof globalThis.fetch) {
	try {
		const res = await client.GET('/v1/user/me', { fetch });
		if (res.response.ok) {
			user.set(res.data);
			return;
		} else {
			// when there's any error, even the "not logged in" one, we just say that the user is not logged in
			console.info('not logged in, get out of here: ', res.error);
			user.set(null);
			return;
		}
	} catch (e) {
		console.error('error updating authentication status because of:', e);
		user.set(null);
		return;
	}
}

export function redirectIfNotAuthenticated() {
	if (browser && get(user) == null) {
		redirect(303, '/');
	}
}

export function redirectIfAuthenticated() {
	if (browser && get(user)) {
		redirect(303, '/settings');
	}
}
