import { browser } from '$app/environment';
import client from '$lib/api/baseFetch';
import type { components } from '$lib/api/v1';
import { redirectIfNotAuthenticated, updateAuth } from '$lib/auth';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	if (!browser) return;
	await updateAuth(fetch);
	redirectIfNotAuthenticated();

	return {
		apps: await getApps(fetch)
	};
};

async function getApps(
	fetch: typeof globalThis.fetch
): Promise<components['schemas']['OauthApp'][]> {
	try {
		const res = await client.GET('/v1/oauth/apps', { fetch });

		if (res.error) {
			return [];
		}

		return res.data;
	} catch (e) {
		console.error(e);
		return [];
	}
}
