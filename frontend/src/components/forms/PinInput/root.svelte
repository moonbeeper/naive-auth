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

<style lang="scss">
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
</style>
