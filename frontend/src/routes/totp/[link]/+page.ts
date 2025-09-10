import { z } from 'zod/v4';
import type { PageLoad } from './$types';
import { error } from '@sveltejs/kit';

const schema = z.object({
	link: z.ulid() // that's neat
});

// TODO: Maybe add a status endpoint to check if the link id is valid for a shortcircuit?
export const load: PageLoad = async ({ params }) => {
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
