<script lang="ts">
	import { ChevronUp } from '@lucide/svelte';
	import { Select } from 'bits-ui';
	import type { Snippet } from 'svelte';

	let { children }: { children?: Snippet } = $props();
</script>

<Select.Portal>
	<Select.Content sideOffset={10} class="select-content">
		<Select.ScrollUpButton class="scroll-up-button">
			<ChevronUp />
		</Select.ScrollUpButton>

		<Select.Viewport class="viewport">
			{@render children?.()}
		</Select.Viewport>
	</Select.Content>
</Select.Portal>

<style lang="scss">
	:global(.select-content) {
		z-index: 999;
        position: relative;
        overflow-y: auto;
        overflow-x: hidden;
		background-color: var(--bg-dark);
		border: 2px solid var(--bg-semidark);
        padding: .25rem ;
        border-radius: 12px;

		:global(.scroll-up-button) {
			display: flex;
			align-items: center;
			justify-content: center;
			padding-top: 4px;
		}

		:global(.viewport) {
			padding: 4px;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
		}
	}
</style>
