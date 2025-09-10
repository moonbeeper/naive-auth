<script lang="ts">
	import { Label, type LabelProps } from 'formsnap';
	import type { Snippet } from 'svelte';
	import type { HTMLLabelAttributes } from 'svelte/elements';

	let { children, ...rest }: { children?: Snippet } & LabelProps = $props();
</script>

<Label {...rest}>
	{#snippet child({ props })}
		<label {...props}>{@render children?.()}</label>
	{/snippet}
</Label>

<style lang="scss">
	label {
		font: inherit; // should inherit everything else but the things bellow
		font-weight: 500;
		font-size: 0.875rem;
		transition: color 0.1s ease-out;

		&[data-fs-error] {
			color: var(--color-bad);
		}
	}
</style>
