<script lang="ts">
	import { goto } from '$app/navigation';
	import Link from '$comps/link.svelte';
	import { PUBLIC_API_URL } from '$env/static/public';
	import client from '$lib/api/baseFetch';
	import { user } from '$lib/auth';
	import { currentText } from '$lib/bigHeader';
	import Button from '../../components/button.svelte';

	currentText.set('yippie');
	let api_explorer = $derived(PUBLIC_API_URL + 'scalar');

	async function signout() {
		await client.POST('/v1/auth/signout');
		user.set(null); // clear it even if it fails lol
		await goto('/');
	}
</script>

<main>
	<div class="title">
		<h1>You are logged in!</h1>
		<p>
			there's not much to see here. Maybe try creating a OAuth2 app with the <Link
				href={api_explorer}>API</Link
			> and then use it here?
		</p>
	</div>
	<p>your email: <strong>{$user?.email}</strong></p>

	<Button onclick={() => signout()}>Sign out</Button>
</main>

<style lang="scss">
	.title {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;

		p {
			font-size: 1.125rem;
			padding: 0.5rem;
			text-align: center;
		}
	}

	main {
		padding: 2.5rem 0;
		display: flex;
		align-items: center;
		flex-direction: column;
		z-index: 1;
		gap: 1.75rem;
	}

	h1 {
		font-size: 1.625rem;
		font-weight: 600;
		letter-spacing: var(--text-tight-spacing);
		text-align: center;
	}
</style>
