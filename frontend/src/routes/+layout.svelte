<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';
	import '../styles/reset.scss';
	import '../styles/root.scss';
	import '@fontsource-variable/manrope';
	import '@fontsource-variable/jetbrains-mono';
	import BigHeader from '../components/bigHeader.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<BigHeader />

{@render children?.()}
