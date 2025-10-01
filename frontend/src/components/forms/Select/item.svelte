<script lang="ts">
	import { Check } from '@lucide/svelte';
	import { Select, type SelectItemProps } from 'bits-ui';

	let { label, ...rest }: SelectItemProps = $props();
</script>

<Select.Item {...rest} {label} class="select-item">
	{#snippet children({ selected })}
		<span>
			{label}
		</span>
		{#if selected}
			<div class="selected-indicator">
				<Check size="16" />
			</div>
		{/if}
	{/snippet}
</Select.Item>

<style lang="scss">
	:global(.select-item) {
		outline: 0;
		display: flex;
		gap: 0.75rem;
		width: 100%;
		border-radius: 8px;
		padding: 0.5rem 0.75rem;
		font-size: 14px;
		height: 32px;
		align-items: center;
		justify-content: space-between;
		background-color: rgba($color: #444444, $alpha: 0.7);

		span {
			width: 100%;
		}
		:global(.selected-indicator) {
			margin-inline: auto;
		}
	}
</style>
