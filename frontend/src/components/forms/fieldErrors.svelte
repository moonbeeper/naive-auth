<script lang="ts">
	import { FieldErrors } from 'formsnap';

	let {} = $props();
</script>

<FieldErrors>
	{#snippet children({ errors, errorProps })}
		{#each errors as err}
			<div {...errorProps}>
				<p>{err}</p>
			</div>
		{/each}
	{/snippet}
</FieldErrors>

<style lang="scss">
	div {
		display: flex;
		flex-direction: row;
		gap: 0.5rem; // for icons
		align-items: center;
	}

	p {
		font: inherit;
		font-size: 0.875rem;
		color: var(--color-bad);
	}
</style>
