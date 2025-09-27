import { z } from 'zod/v4';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { redirectIfAuthenticated, updateAuth } from '$lib/auth';

const schema = z.object({
	link: z.ulid() // that's neat
});

// TODO: Maybe add a status endpoint to check if the link id is valid for a shortcircuit?
export const load: PageLoad = async ({ params }) => {
	if (!browser)
		return {
			link: '00000000000000000000000000'
		};
	await updateAuth(fetch);
	redirectIfAuthenticated();

	const parsed = schema.safeParse({
		link: params.link
	});

	if (!parsed.success) {
		error(400, 'Invalid TOTP flow');
	}

	return {
		link: parsed.data.link
	};
};
