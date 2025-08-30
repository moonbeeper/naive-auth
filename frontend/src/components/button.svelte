<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';

	let {
		type,
		disabled,
		href,
		children,
		big,
		small,
		primary,
		full_width,
		...rest
	}: HTMLButtonAttributes &
		HTMLAnchorAttributes & {
			// type?: HTMLButtonAttributes['type'];
			// disabled?: HTMLButtonAttributes['disabled'];
			// href?: HTMLAnchorAttributes['href'];
			children?: Snippet;
			big?: boolean;
			small?: boolean;
			primary?: boolean;
			full_width?: boolean;
		} = $props();
</script>

<!-- the button class is used to be able to style the button outside of this component easily VIA :global()-->
{#if href}
	<a
		{...rest}
		{href}
		{type}
		aria-disabled={disabled}
		class:big
		class:small
		class:primary
		class="button"
		class:full_width
	>
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
		class="button"
		class:full_width
	>
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
		transition: background-color 0.1s ease-out;
		font-weight: 500;
		cursor: pointer;
		height: 36px;

		&.big {
			height: 40px;
		}

		&.small {
			height: 32px;
		}

		&:hover {
			background-color: var(--bg-semidark);
		}

		&.primary {
			background-color: var(--white);
			color: var(--text-darkened);

			&:hover {
				background-color: var(--white-darkened);
			}
		}
		&.full_width {
			width: 100%;
		}
	}
</style>
