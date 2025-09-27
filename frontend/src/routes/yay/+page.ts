import { browser } from '$app/environment';
import { redirectIfNotAuthenticated, updateAuth } from '$lib/auth';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	if (!browser) return;
	await updateAuth(fetch);
	redirectIfNotAuthenticated();
	return;
};
