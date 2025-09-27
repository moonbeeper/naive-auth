<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLAnchorAttributes } from 'svelte/elements';

	let {
		children,
		disabled = false,
		...rest
	}: { children?: Snippet; disabled?: boolean } & HTMLAnchorAttributes = $props();
</script>

<a {...rest} aria-disabled={disabled}>{@render children?.()}</a>
