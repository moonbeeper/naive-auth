import { z } from 'zod/v4';
import { error, redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';
import client, { type ApiHttpError } from '$lib/api/baseFetch';
import { browser } from '$app/environment';

const schema = z.object({
	link: z.ulid() // that's neat
});

export const load: PageLoad = async ({ params }) => {
	const parsed = schema.safeParse({
		link: params.link
	});

	if (!parsed.success) {
		error(400, 'Invalid password reset link');
	}

	if (browser) {
		const res = await client.GET('/v1/auth/reset/{id}', {
			params: {
				path: {
					id: parsed.data.link
				}
			},
			fetch
		});

		// TODO: should make a +error.svelte page here
		if (res.error?.error === ('RecoveryLinkNotFound' as ApiHttpError)) {
			error(400, 'Invalid password reset link');
		} else if (res.error) {
			error(500, 'An unknown error occurred');
		}

		if (res.data.status !== 'needs_totp') {
			const template = '/reset-password/{id}';
			redirect(303, template.replace('{id}', parsed.data.link));
		}
	}

	return {
		link: parsed.data.link
	};
};
