<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	let {
		type,
		placeholder,
		big,
		small,
		value = $bindable(),
		disabled = false,
		...rest
	}: HTMLInputAttributes & {
		big?: boolean;
		small?: boolean;
		disabled?: boolean;
	} = $props();

	let input: HTMLInputElement;

	export function focus() {
		input.focus();
	}

	export function blur() {
		input.blur();
	}
</script>

<input
	{type}
	{placeholder}
	class:big
	class:small
	class="input"
	bind:this={input}
	bind:value
	{disabled}
	aria-disabled={disabled}
	{...rest}
/>

<style lang="scss">
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
