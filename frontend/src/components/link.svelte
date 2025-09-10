<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLAnchorAttributes } from 'svelte/elements';

	let {
		children,
		blocked,
		...rest
	}: { children?: Snippet; blocked?: boolean } & HTMLAnchorAttributes = $props();
</script>

<a {...rest} class:blocked>{@render children?.()}</a>
