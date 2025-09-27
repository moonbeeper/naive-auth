<script lang="ts">
	import { PinInput, type PinInputCellProps } from 'bits-ui';

	let { cell, ...rest }: PinInputCellProps = $props();
</script>

<PinInput.Cell {cell} {...rest}>
	{cell.char}
	{#if cell.hasFakeCaret}
		<span class="caret"></span>
	{/if}
</PinInput.Cell>

<style lang="scss">
	:global([data-pin-input-cell]) {
		width: 100%;
		height: 5.75rem;
		display: flex;
		font-size: 3rem;
		font-weight: 400;
		align-items: center;
		color: var(--text);
		justify-content: center;
		transition:
			outline,
			border-color 0.1s ease-out; // maybe I shouldn't transition the border? looks kinda bad?

		outline: 0;
		border: 2px solid var(--border-color);

		&:first-child {
			border-radius: 0.625rem 0 0 0.625rem;
		}

		&:not(:first-child) {
			border-left: 0;
		}

		&:last-child {
			border-radius: 0 0.625rem 0.625rem 0;
		}
	}

	:global([data-pin-input-cell][data-active]) {
		// border: 2px solid var(--color-yellow);
		outline: 2px solid var(--color-yellow);
		border: 1px solid var(--color-yellow-darkened);
	}

	@media (max-width: 425px) {
		:global([data-pin-input-cell]) {
			height: 3.75rem;
			font-size: 2.5rem;
		}
	}

	.caret {
		border: 1px solid var(--text);
		width: 1px;
		height: 32px;
		animation: blink 1500ms cubic-bezier(0.075, 0.82, 0.165, 1) infinite; // can't use 1.5s?
	}

	@keyframes blink {
		0% {
			opacity: 0;
		}
		50% {
			opacity: 1;
		}
		100% {
			opacity: 0;
		}
	}
</style>
