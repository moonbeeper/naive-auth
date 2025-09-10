<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';

	let {
		type,
		disabled = false,
		loading,
		href,
		children,
		big,
		small,
		primary,
		bad,
		full_width,
		icon,
		...rest
	}: HTMLButtonAttributes &
		HTMLAnchorAttributes & {
			// type?: HTMLButtonAttributes['type'];
			disabled?: boolean;
			// href?: HTMLAnchorAttributes['href'];
			children?: Snippet;
			big?: boolean;
			small?: boolean;
			primary?: boolean;
			full_width?: boolean;
			loading?: boolean;
			bad?: boolean;
			icon?: Snippet;
		} = $props();
</script>

{#if href}
	<a
		{...rest}
		{href}
		{type}
		aria-disabled={disabled}
		class:big
		class:small
		class:primary
		class:full_width
		class:loading
		class:bad
	>
		{@render icon?.()}
		{@render children?.()}
	</a>
{:else}
	<button
		{...rest}
		{type}
		{disabled}
		class:big
		class:small
		class:primary
		class:full_width
		class:loading
		class:bad
		aria-disabled={disabled}
	>
		{@render icon?.()}
		{@render children?.()}
	</button>
{/if}

<style lang="scss">
	a,
	button {
		background-color: #171717;
		padding: 0 0.75rem;
		font-size: 0.875rem;
		outline: 0;
		border: var(--bg-semidark) 0.1rem solid;
		color: var(--text);
		border-radius: 0.625rem;
		font-family: inherit;
		transition: background-color outline 0.1s ease-out;
		font-weight: 500;
		cursor: pointer;
		height: 36px;
		user-select: none;

		display: flex;
		align-items: center;
		justify-content: center;

		gap: 0.5rem;

		&.big {
			height: 40px;
		}

		&.small {
			height: 32px;
		}

		&:hover {
			background-color: var(--bg-semidark);
		}

		&[aria-disabled='true'] {
			background-color: var(--bg-semidark);
		}

		&.primary {
			background-color: var(--white);
			color: var(--text-darkened);

			&:hover {
				background-color: var(--white-darkened);
			}

			&[aria-disabled='true'] {
				background-color: var(--white-darkened);
				cursor: not-allowed;
			}
		}

		&.bad {
			border-color: var(--color-bad-darkened);
			color: var(--color-bad);
		}

		&.full_width {
			width: 100%;
		}

		&.loading {
			cursor: progress;
		}

		&:focus {
			outline: 2px solid var(--color-yellow);
			outline-offset: 2px;
		}
	}
</style>
