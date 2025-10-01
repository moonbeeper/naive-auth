<script lang="ts" module>
	import { z } from 'zod/v4';

	const schema = z.object({
		callback_url: z.url('The callback URL must be a valid URL.'),
		name: z
			.string()
			.trim()
			.min(6, 'The app name must be at least 6 characters long.')
			.max(32, 'The app name must be at most 32 characters long.'),
		description: z
			.string()
			.trim()
			.max(256, 'The app description must be at most 256 characters long.'),
		scopes: z
			.array(z.enum(Object.keys(scopeDefinitions) as [string, ...string[]]))
			.nonempty('Select at least one scope')
	});
</script>

<script lang="ts">
	import Button from '$comps/button.svelte';
	import { X } from '@lucide/svelte';
	import { Dialog } from 'bits-ui';
	import Input from '../input.svelte';
	import { fade, scale } from 'svelte/transition';
	import type { components } from '$lib/api/v1';
	import { scopeDefinitions } from '$lib/oauthScopes';
	import { defaults, superForm } from 'sveltekit-superforms';
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

	let {
		data,
		open: isOpen = $bindable()
	}: { data: components['schemas']['OauthApp']; open: boolean } = $props();

	let niceData = $derived.by(() => {
		return {
			callback_url: data.callback_url,
			name: data.name,
			description: data.description ?? '',
			scopes: data.scopes
		};
	});

	const form = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.PUT('/v1/oauth/apps/{id}', {
					body: {
						callback_url: f.data.callback_url,
						name: f.data.name,
						description: f.data.description,
						scopes: f.data.scopes
					},
					params: {
						path: {
							id: data.id
						}
					}
				});

				// sorry... am to hecking lazy to make proper error handling for this dialog and everything else. zzz
				if (res.error?.error === ('OAuthAppNotFound' as ApiHttpError)) {
					isOpen = false;
					invalidateAll();
				} else if (res.error?.error === ('OAuthAppNotOwned' as ApiHttpError)) {
					isOpen = false;
					invalidateAll();
				} else if (res.error) {
					console.error(res.error);
				}

				if (res.response.ok) {
					isOpen = false;
					invalidateAll();
				}
			}
		},
		id: 'update-oauth-app-dialog'
	});

	const { enhance, form: formData, delayed } = form;

	const selectedScopes = $derived(
		$formData.scopes.length ? $formData.scopes.map((c) => c).join(', ') : 'Select scopes'
	);

	$effect(() => {
		$formData = niceData;
	});
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
							<Dialog.Title>Updating App Information</Dialog.Title>
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
							<form use:enhance>
								<FormContainer>
									<Field {form} name="name">
										<FieldContainer>
											<Control>
												{#snippet children({ props })}
													<Label>App Name</Label>
													<Input
														{...props}
														bind:value={$formData.name}
														type="text"
														placeholder="proot and birb external"
													/>
												{/snippet}
											</Control>
											<FieldErrors />
										</FieldContainer>
									</Field>
									<Field {form} name="description">
										<FieldContainer>
											<Control>
												{#snippet children({ props })}
													<Label>Description</Label>
													<Textarea
														{...props}
														bind:value={$formData.description}
														placeholder="i like proot and birb. nom nom yummy ddr3 ram"
													/>
												{/snippet}
											</Control>
											<FieldErrors />
										</FieldContainer>
									</Field>
									<Field {form} name="callback_url">
										<FieldContainer>
											<Control>
												{#snippet children({ props })}
													<Label>Callback URL</Label>
													<Input
														{...props}
														bind:value={$formData.callback_url}
														type="text"
														placeholder="https://example.com/callback"
													/>
												{/snippet}
											</Control>
											<FieldErrors />
										</FieldContainer>
									</Field>
									<Field {form} name="scopes">
										<FieldContainer>
											<Control>
												{#snippet children({ props })}
													<Label>Scopes</Label>
													<Select.Root
														type="multiple"
														name={props.name}
														bind:value={$formData.scopes}
													>
														<Select.Trigger {...props}>
															{selectedScopes}
														</Select.Trigger>
														<Select.Content>
															{#each Object.keys(scopeDefinitions) as key}
																<Select.Item value={key} label={key} />
															{/each}
														</Select.Content>
													</Select.Root>
												{/snippet}
											</Control>
											<FieldErrors />
										</FieldContainer>
									</Field>
								</FormContainer>
							</form>
						</div>
						<div class="dialog-footer">
							<Button primary onclick={() => form.submit()} disabled={$delayed} loading={$delayed}>
								Update app
							</Button>
							<Button onclick={() => (isOpen = false)}>Cancel</Button>
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
