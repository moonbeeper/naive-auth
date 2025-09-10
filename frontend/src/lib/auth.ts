import { writable } from 'svelte/store';
import type { components } from './api/v1';
import client from './api/baseFetch';

// null means not logged in
// undefined means not yet loaded
export const user = writable<components['schemas']['User'] | null | undefined>(undefined);

export async function updateAuth() {
	const res = await client.GET('/v1/user/me');

	// my gah, having to put () in if statements makes me get confused
	if (res.response.ok) {
		user.set(res.data);
		return;
	} else {
		// when there's any error, even the "not logged in" one, we just say that the user is not logged in
		console.info('not logged in, get out of here: ', res.error);
		user.set(null);
		return;
	}
}
