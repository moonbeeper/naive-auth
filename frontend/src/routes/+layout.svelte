<script lang="ts">
	import '../styles/reset.scss';
	import '../styles/root.scss';
	import '@fontsource-variable/manrope';
	import '@fontsource-variable/jetbrains-mono';
	import BigHeader from '../components/bigHeader.svelte';

	let { children } = $props();
</script>

<BigHeader />

{@render children?.()}
