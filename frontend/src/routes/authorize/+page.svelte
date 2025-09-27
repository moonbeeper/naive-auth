<script lang="ts">
	import { currentText } from '$lib/bigHeader';
	import Button from '$comps/button.svelte';
	import type { PageProps } from './$types';
	import { onMount } from 'svelte';
	import { PUBLIC_API_URL } from '$env/static/public';

	currentText.set('OAuth Prompt');

	let { data }: PageProps = $props();
	let submit_disabled = $state(true);
	let api_url = $derived(PUBLIC_API_URL + 'v1/auth/oauth/authorize');

	onMount(() => {
		setTimeout(() => {
			submit_disabled = false;
		}, 4000);
	});
</script>

<main>
	<div class="container">
		<h1>Authorize {data.name}</h1>
		<p><strong>{data.name}</strong> wants to access your account:</p>
		<ul>
			{#each data.scopes ?? [] as scope}
				<li>{scope}</li>
			{/each}
		</ul>
		<form method="POST" action={api_url}>
			<Button
				type="submit"
				name="authorize"
				value="true"
				primary
				full_width
				disabled={submit_disabled}>Authorize</Button
			>
			<Button type="submit" name="authorize" value="false" full_width>Cancel</Button>
		</form>
		<p class="redirect">You'll be redirected to <strong>{data.redirectUrl}</strong></p>
	</div>
</main>

<style lang="scss">
	h1 {
		font-size: 1.5rem;
		font-weight: 600;
		letter-spacing: var(--text-tight-spacing);
		text-align: center;
	}

	main {
		padding: 2.5rem 0;
		display: flex;
		align-items: center;
		flex-direction: column;
		z-index: 1;
		gap: 1.75rem;
	}

	p {
		font-size: 1rem;
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}

	ul {
		list-style: circle;
		padding-left: 1.25rem;
		margin-top: 0.5rem;
		display: flex;
		gap: 0.5rem;
		flex-direction: column;
		font-size: 0.95rem;
	}

	.container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		align-items: center;
		min-width: 300px;
		max-width: 300px;
	}

	form {
		margin-top: 0.5rem;
		display: flex;
		flex-direction: column;
		gap: 0.5em;
		width: 100%;
	}

	.redirect {
		text-align: center;
		display: flex;
		flex-direction: column;
		width: 100%;
		font-size: 0.875rem;
	}
</style>
