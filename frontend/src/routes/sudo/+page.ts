import { browser } from '$app/environment';
import client, { type ApiHttpError } from '$lib/api/baseFetch';
import { redirectIfNotAuthenticated, updateAuth } from '$lib/auth';
import { error, redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	if (!browser) return;
	await updateAuth(fetch);
	redirectIfNotAuthenticated();
	if (browser) {
		const res_staus = await client.GET('/v1/sudo/status', {
			fetch
		});

		if (res_staus.data?.enabled) {
			redirect(303, '/settings');
		}

		const res_options = await client.GET('/v1/sudo', {
			fetch
		});
		const res = await client.POST('/v1/sudo', {
			body: {
				option: res_options.data?.otp ? 'otp' : 'totp'
			}
		});

		if (res.error?.error === ('SudoCannotBeEnabled' as ApiHttpError)) {
			error(400, 'Cannot enable sudo at this time, try again later.');
		} else if (res.error?.error === ('SudoIsAlreadyEnabled' as ApiHttpError)) {
			redirect(303, '/settings');
		} else if (res.error) {
			console.error(res.error);
			error(500, 'Something went pretty wrong while trying to enable sudo.');
		}

		if (res.data.option === 'otp') {
			const template = '/sudo/otp/{link}';
			redirect(303, template.replace('{link}', res.data.link_id ?? '00000000000000000000000000'));
		} else if (res.data.option === 'totp') {
			const template = '/sudo/totp/{link}';
			redirect(303, template.replace('{link}', res.data.link_id ?? '00000000000000000000000000'));
		}
	}

	return;
};
