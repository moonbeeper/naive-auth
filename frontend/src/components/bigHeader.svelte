<script lang="ts">
	import Button from './button.svelte';
	import { currentText } from '$lib/bigHeader';
	import { user } from '$lib/auth';
	import client from '$lib/api/baseFetch';
	import { goto } from '$app/navigation';

	// let headerText = $state('???');
	// currentText.subscribe((text) => {
	// 	headerText = text;
	// });
	// let headerText = get(currentText);
	let headerText = $derived($currentText); // i get it (not really)
	// let isLogged = $derived(!!$user);

	// async function signout() {
	// 	await client.POST('/v1/auth/signout');
	// 	user.set(null); // clear it even if it fails lol
	// 	await goto('/');
	// }
</script>

<header>
	<h1>{headerText}</h1>
	<!-- <nav>
		{#if isLogged}
			<Button onclick={() => signout()}>Sign out</Button>
		{/if}
	</nav> -->
</header>

<style lang="scss">
	header {
		display: flex;
		padding: 1rem 2rem;
		min-height: 80px;
		height: 80px;
		align-items: center;
		--title-spacing: 0em;
	}

	// 18 20 24       32 40 48
	// magic number land
	h1 {
		flex: 1 0 auto; // woops, seems this makes it have the correct bounding box in the devtools
		font-weight: 700;
		font-size: clamp(1.125rem, 0.9rem + 1.2vw, 2rem);
		letter-spacing: var(--title-spacing);
		white-space: nowrap;
		min-width: 0;
	}

	@media (min-width: 544px) {
		header {
			--title-spacing: var(--text-almost-tight-spacing);
		}
		h1 {
			font-size: clamp(1.25rem, 1rem + 1.4vw, 2.5rem);
		}
	}

	@media (min-width: 768px) {
		header {
			--title-spacing: var(--text-tight-spacing);
		}
		h1 {
			font-size: clamp(1.5rem, 1.1rem + 1.8vw, 3rem);
		}
	}

	// nav {
	// 	width: 100%;
	// 	display: flex;
	// 	flex-direction: row;
	// 	justify-content: end;
	// 	align-items: center;
	// }
</style>
