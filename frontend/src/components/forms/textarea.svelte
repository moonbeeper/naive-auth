<script lang="ts">
	import type { HTMLTextareaAttributes } from 'svelte/elements';

	let {
		placeholder,
		value = $bindable(),
		disabled = false,
		...rest
	}: HTMLTextareaAttributes & {
		disabled?: boolean;
	} = $props();

	let input: HTMLTextAreaElement;

	export function focus() {
		input.focus();
	}

	export function blur() {
		input.blur();
	}
</script>

<textarea
	{placeholder}
	class="input"
	bind:this={input}
	bind:value
	{disabled}
	aria-disabled={disabled}
	rows="3"
	{...rest}
></textarea>

<style lang="scss">
	textarea {
		resize: none;
		padding-top: .5rem;
	}
</style>
