import createClient from 'openapi-fetch';
import type { components, paths } from './v1';
import { PUBLIC_API_URL } from '$env/static/public';

const client = createClient<paths>({
	baseUrl: PUBLIC_API_URL,
	headers: {
		'Content-Type': 'application/json'
	},
	credentials: 'include'
});

export type ApiHttpError = components['schemas']['ApiHttpError'];
export default client;
