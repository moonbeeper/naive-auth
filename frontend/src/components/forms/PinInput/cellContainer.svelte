<script lang="ts">
	import type { Snippet } from 'svelte';

	let { children }: { children?: Snippet } = $props();
</script>

<div class="cell">
	{@render children?.()}
</div>

<style lang="scss">
	.cell {
		display: flex;
		width: 100%;
	}
</style>
