import { z } from 'zod/v4';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { redirectIfNotAuthenticated, updateAuth, user } from '$lib/auth';
import { get } from 'svelte/store';

const schema = z.object({
	link: z.ulid() // that's neat
});

// TODO: Maybe add a status endpoint to check if the link id is valid for a shortcircuit?
export const load: PageLoad = async ({ params, url }) => {
	if (!browser)
		return {
			link: '00000000000000000000000000',
			email: 'hello'
		};
	await updateAuth(fetch);
	redirectIfNotAuthenticated();

	const email = url.searchParams.get('email');
	const parsed = schema.safeParse({
		link: params.link,
		email
	});

	if (!parsed.success) {
		error(400, 'The sudo enable link seems to be invalid');
	}

	return {
		link: parsed.data.link,
		email: get(user)?.email ?? 'unknown@unknown'
	};
};
