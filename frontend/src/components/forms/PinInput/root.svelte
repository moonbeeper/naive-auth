<script lang="ts">
	import {
		PinInput,
		REGEXP_ONLY_CHARS,
		REGEXP_ONLY_DIGITS,
		REGEXP_ONLY_DIGITS_AND_CHARS,
		type PinInputRootProps,
		type PinInputRootSnippetProps
	} from 'bits-ui';

	let {
		value = $bindable(''),
		pattern,
		...rest
	}: Omit<PinInputRootProps, 'pattern'> & {
		pattern: 'digits' | 'alphanumeric' | 'mixed';
	} = $props();

	let regex = $derived.by(() => {
		if (pattern === 'digits') return REGEXP_ONLY_DIGITS;
		if (pattern === 'alphanumeric') return REGEXP_ONLY_CHARS;
		return REGEXP_ONLY_DIGITS_AND_CHARS;
	});

	// type CellProps = PinInputRootSnippetProps['cells'][0];
</script>

<PinInput.Root pattern={regex} bind:value {...rest} />

<!-- {#snippet children({ cells })}
		<div class="container">
		<div class="cell">
			{#each cells.slice(0, 3) as cell}
				{@render Cell(cell)}
			{/each}
		</div>
		<span class="separator"></span>
		<div class="cell">
			{#each cells.slice(3, 6) as cell}
				{@render Cell(cell)}
			{/each}
		</div>
		</div>
	{/snippet}
</PinInput.Root> -->

<!-- {#snippet Cell(cell: CellProps)}
	<PinInput.Cell {cell}>
		{cell.char}
		{#if cell.hasFakeCaret}
			<span class="caret"></span>
		{/if}
	</PinInput.Cell>
{/snippet} -->

<style lang="scss">
	// // .container {
	// // 	display: flex;
	// // 	align-items: center;
	// // 	width: 100%;
	// // 	max-width: 504px;

	// // 	gap: 0.25rem;
	// // }

	// .cell {
	// 	display: flex;
	// 	width: 100%;
	// }

	// compiler can't see this. :(
	:global([data-pin-input-root]) {
		display: flex;
		align-items: center;
		width: 100%;
		gap: 0.5rem;
		padding: 0 1rem;
		// max-width: 504px;
		max-width: var(--pin-max-width, 504px);
		--border-color: var(--bg-notdark);

		// :has(:disabled) {
		// 	opacity: 0;
		// }
	}

	:global([data-pin-input-root] input[aria-disabled='true']) {
		color: transparent !important;
	}

	:global([data-pin-input-root]:has(:disabled)) {
		--border-color: var(--bg-semidark);
		--pin-cursor: progress;
	}

	:global([data-pin-input-root]:has([data-fs-error])) {
		--border-color: var(--color-bad);
	}

	:global([data-pin-input-input]) {
		cursor: var(--pin-cursor, text);
	}

	// :global([data-pin-input-input]::selection) { can't make it transparent when doing CTRL+A
	// 	color: transparent;
	// }

	// :global([data-pin-input-cell]) {
	// 	width: 100%;
	// 	height: 5.75rem;
	// 	display: flex;
	// 	font-size: 3.125rem;
	// 	font-weight: 400;
	// 	align-items: center;
	// 	color: var(--text);
	// 	justify-content: center;
	// 	transition: outline 0.1s ease-out; // shouldn't transition the border. looks bad

	// 	outline: 0;
	// 	border: 2px solid var(--border-color);

	// 	&:first-child {
	// 		border-radius: 0.625rem 0 0 0.625rem;
	// 		// border-end-end-radius: 0;
	// 		// border-start-end-radius: 0;
	// 	}

	// 	&:not(:first-child) {
	// 		border-left: 0; // beautiful
	// 	}

	// 	&:last-child {
	// 		border-radius: 0 0.625rem 0.625rem 0;
	// 	}

	// 	// &[data-active] {  makes it appear as unused
	// 	// 	border: 2px solid var(--color-yellow);
	// 	// }
	// 	// :global([data-active]) {
	// 	// 	border: 2px solid var(--color-yellow);
	// 	// 	color: red;
	// 	// }
	// }

	// :global([data-pin-input-cell][data-active]) {
	// 	// border: 2px solid var(--color-yellow);
	// 	outline: 2px solid var(--color-yellow);
	// 	border: 1px solid var(--color-yellow-darkened);
	// }

	// .caret {
	// 	border: 1px solid var(--text);

	// 	width: 1px;
	// 	height: 32px;

	// 	animation: blink 1500ms cubic-bezier(0.075, 0.82, 0.165, 1) infinite; // can't use 1.5s?
	// }

	// .separator {
	// 	border-radius: 50%;
	// 	background-color: var(--text-placeholder); // looks better lol
	// 	width: 1rem;
	// 	height: 0.5rem;
	// }

	// @keyframes blink {
	// 	0% {
	// 		opacity: 0;
	// 	}
	// 	50% {
	// 		opacity: 1;
	// 	}
	// 	100% {
	// 		opacity: 0;
	// 	}
	// }
</style>
