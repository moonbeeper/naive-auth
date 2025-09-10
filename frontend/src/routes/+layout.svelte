<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';
	import '../styles/reset.scss';
	import '@fontsource-variable/manrope';
	import '../styles/root.scss';
	import BigHeader from '../components/bigHeader.svelte';
	import { updateAuth } from '$lib/auth';

	let { children } = $props();

	// cached for all pages (??????????)
	$effect(() => {
		updateAuth();
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<BigHeader />

{@render children?.()}
