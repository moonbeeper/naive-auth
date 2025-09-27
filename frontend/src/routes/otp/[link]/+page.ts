import { z } from 'zod/v4';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { redirectIfAuthenticated, updateAuth } from '$lib/auth';

const schema = z.object({
	link: z.ulid(), // that's neat
	email: z.email()
});

// TODO: Maybe add a status endpoint to check if the link id is valid for a shortcircuit?
export const load: PageLoad = async ({ params, url }) => {
	if (!browser) return {
		link: '00000000000000000000000000',
		email: 'hello'
	};
	await updateAuth(fetch);
	redirectIfAuthenticated();

	const email = url.searchParams.get('email');
	const parsed = schema.safeParse({
		link: params.link,
		email
	});

	if (!parsed.success) {
		error(400, 'Invalid OTP flow');
	}

	return {
		link: parsed.data.link,
		email: parsed.data.email
	};
};
