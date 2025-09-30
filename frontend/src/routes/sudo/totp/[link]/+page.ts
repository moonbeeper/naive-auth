import { z } from 'zod/v4';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { redirectIfNotAuthenticated, updateAuth } from '$lib/auth';

const schema = z.object({
	link: z.ulid() // that's neat
});

export const load: PageLoad = async ({ params }) => {
	if (!browser)
		return {
			link: '00000000000000000000000000'
		};
	await updateAuth(fetch);
	redirectIfNotAuthenticated();

	const parsed = schema.safeParse({
		link: params.link
	});

	if (!parsed.success) {
		error(400, 'The sudo enable link seems to be invalid');
	}

	return {
		link: parsed.data.link
	};
};
