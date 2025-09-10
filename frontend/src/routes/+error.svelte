<script lang="ts">
	// TODO: Make a proper error page
	import { page } from '$app/state';
	import { currentText } from '$lib/bigHeader';
	currentText.set('Oh snap!');

	let message = $derived(page.error?.message ?? 'An unexpected error occurred.');
</script>

<main>
	<h1>Something went wrong.</h1>

	<h2>{message}</h2>
</main>

<style lang="scss">
	main {
		padding: 2.5rem 0;
		display: flex;
		align-items: center;
		flex-direction: column;
		z-index: 1;
		gap: 1.75rem;
		text-align: center;
	}

	h1 {
		font-size: 2.5rem;
		font-weight: 900;
	}

	h2 {
		font-size: 2rem;
		font-weight: 500;
	}
</style>
