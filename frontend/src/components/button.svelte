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
		font-weight: 500;
		text-transform: capitalize;
		cursor: pointer;
		height: 36px;
		user-select: none;
		transition: background-color 0.1s ease-out; // I don't think that the outline should be animated

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
			cursor: not-allowed;
		}

		&.primary {
			background-color: var(--white);
			color: var(--text-darkened);

			&:hover {
				background-color: var(--white-darkened);
			}

			&[aria-disabled='true'] {
				background-color: var(--white-darkened);
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
