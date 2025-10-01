<script lang="ts">
	import { ChevronDownIcon } from '@lucide/svelte';
	import { Select } from 'bits-ui';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: Select.TriggerProps = $props();
</script>

<Select.Trigger bind:ref class="select-trigger" {...restProps}>
	{@render children?.()}
	<ChevronDownIcon />
</Select.Trigger>

<style lang="scss">
	:global(.select-trigger) {
		display: flex;
		width: fit-content;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		white-space: nowrap;
		border-radius: 8px;
		border: 2px solid var(--bg-semidark);
		padding: 0.375rem 0.75rem;
		font-size: 14px;
		outline: none;
		background-color: transparent;
		color: var(--text);
		transition: color 0.2s ease-out;
		flex-shrink: 0;
		user-select: none;
	}
</style>
