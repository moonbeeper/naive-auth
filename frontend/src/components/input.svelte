<script lang="ts">
	import { flip } from 'svelte/animate';
	import type { HTMLInputAttributes } from 'svelte/elements';
	import { slide, fade, fly } from 'svelte/transition';

	let {
		type,
		name,
		placeholder,
		big,
		small,
		label,
		value = $bindable()
	}: HTMLInputAttributes & {
		label: string;
		big?: boolean;
		small?: boolean;
		value?: string;
	} = $props();

	let input: HTMLInputElement;

	export function focus() {
		input.focus();
	}

	export function blur() {
		input.blur();
	}
</script>

<div>
	<label for={name}>{label}</label>
	<input
		{type}
		{name}
		id={name}
		{placeholder}
		class:big
		class:small
		class="input"
		bind:this={input}
	/>
</div>

<style lang="scss">
	div {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		width: 100%; // sneeky bug
	}

	label {
		font-weight: 500;
		font-size: 0.875rem;
	}

	input {
		height: 36px; // 32px, 36px, 40px

		&.small {
			height: 32px;
		}

		&.big {
			height: 40px;
		}
	}
</style>
