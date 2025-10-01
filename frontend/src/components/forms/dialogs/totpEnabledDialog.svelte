<script lang="ts">
	import Button from '$comps/button.svelte';
	import { CircleCheckBig, X } from '@lucide/svelte';
	import { Dialog } from 'bits-ui';
	import Input from '../input.svelte';
	import { fade, scale } from 'svelte/transition';
	import type { components } from '$lib/api/v1';
	import { scopeDefinitions } from '$lib/oauthScopes';
	import { defaults, setError, superForm } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { Control, Field } from 'formsnap';
	import FieldContainer from '../fieldContainer.svelte';
	import Label from '../label.svelte';
	import Textarea from '../textarea.svelte';
	import FormContainer from '../formContainer.svelte';
	import FieldErrors from '../fieldErrors.svelte';
	import Select from '../Select';
	import { invalidateAll } from '$app/navigation';

	// TODO: this should be separated into components.

	let { open: isOpen = $bindable() }: { open: boolean } = $props();
</script>

<Dialog.Root bind:open={isOpen}>
	<Dialog.Portal>
		<Dialog.Overlay class="dialog-overlay" forceMount>
			{#snippet child({ props, open })}
				{#if open}
					<div {...props} transition:fade={{ duration: 100 }}></div>
				{/if}
			{/snippet}
		</Dialog.Overlay>
		<Dialog.Content class="dialog-root-content" forceMount>
			{#snippet child({ props, open })}
				{#if open}
					<div {...props} in:scale={{ duration: 200 }}>
						<div class="dialog-header">
							<Dialog.Title>Two-Factor Authentication Enabled</Dialog.Title>
							<Dialog.Close>
								{#snippet child({ props })}
									<Button primary {...props}>
										{#snippet icon()}
											<X size="20" />
										{/snippet}
									</Button>
								{/snippet}
							</Dialog.Close>
						</div>
						<div class="dialog-content">
							<div class="icon-container">
								<CircleCheckBig class="icon" />
							</div>
							<p>Two-Factor authentication has been successfully enabled for your account!</p>
						</div>
						<div class="dialog-footer">
							<Button primary onclick={() => (isOpen = false)}>Close</Button>
						</div>
					</div>
				{/if}
			{/snippet}
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>

<style lang="scss">
	:global(.dialog-overlay) {
		position: fixed;
		inset: 0;
		z-index: 968;
		background-color: rgba(0, 0, 0, 0.4);
		backdrop-filter: blur(2px);
	}

	:global(.dialog-root-content) {
		--dialog-padding: 1rem;
		z-index: 969;
		position: fixed;
		left: 50%;
		top: 50%;
		transform: translate(-50%, -50%);
		display: flex;
		flex-direction: column;
		width: 640px;
		border-radius: 16px;
		background-color: var(--bg-dark);
		border: 1px solid var(--bg-semidark);
		min-width: 300px;
		max-width: 90vw;
		max-height: 90vh;

		.dialog-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			padding: 8px;
			border-bottom: 1px solid var(--bg-semidark);

			:global([data-dialog-title]) {
				font-weight: 600;
				padding-left: 8px;
			}
		}

		.dialog-content {
			padding: var(--dialog-padding);
			display: flex;
			flex-direction: column;
			gap: 1rem;
			align-items: center;

			.icon-container {
				display: flex;
				width: 100%;
				margin-inline: auto;
				align-items: center;
				justify-content: center;
			}

			:global(.icon) {
				color: var(--color-yellow);
				width: 48px;
				height: 48px;
			}
		}

		.dialog-footer {
			padding: var(--dialog-padding);
			padding-top: 0;
			display: flex;
			flex-direction: row-reverse;
			gap: 0.5rem;
		}
	}
</style>
