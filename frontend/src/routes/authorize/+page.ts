export const ssr = false;

import type { PageLoad } from './$types';
import { browser } from '$app/environment';
import { redirectIfNotAuthenticated, updateAuth } from '$lib/auth';
import client, { type ApiHttpError } from '$lib/api/baseFetch';
import { error } from '@sveltejs/kit';
import { scopesToLegible } from '$lib/oauthScopes';

export const load: PageLoad = async ({ fetch }) => {
	if (!browser) return;
	await updateAuth(fetch);
	redirectIfNotAuthenticated();

	if (browser) {
		const res = await client.GET('/v1/auth/oauth/context', {
			fetch
		});
		// console.log(res);

		if (res.error?.error === ('OauthFlowNotFound' as ApiHttpError)) {
			error(404, 'The OAuth flow was not found. Try again?');
		}

		const legible_scopes = scopesToLegible(res.data?.scopes || []);
		console.log({ legible_scopes });

		return {
			name: res.data?.name,
			scopes: legible_scopes,
			redirectUrl: res.data?.redirect_uri
		};
	}

	return;
};
