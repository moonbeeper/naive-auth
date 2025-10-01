<script lang="ts" module>
	import { z } from 'zod/v4';

	const schema = z.object({
		code: z.string().length(6, 'The two-factor code must be 6 digits long')
	});
</script>

<script lang="ts">
	import Button from '$comps/button.svelte';
	import { ChevronLeft, ChevronRight, ClipboardIcon, X } from '@lucide/svelte';
	import { Dialog } from 'bits-ui';
	import Input from '../input.svelte';
	import { fade, scale } from 'svelte/transition';
	import type { components } from '$lib/api/v1';
	import { defaults, setError, superForm } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { Control, Field } from 'formsnap';
	import FieldContainer from '../fieldContainer.svelte';
	import Label from '../label.svelte';
	import FormContainer from '../formContainer.svelte';
	import FieldErrors from '../fieldErrors.svelte';
	import { invalidateAll } from '$app/navigation';
	import QR from '@svelte-put/qr/svg/QR.svelte';
	import { getTotpQrData, user } from '$lib/auth';
	import { copyText } from 'svelte-copy';

	// TODO: this should be separated into components.

	let {
		data,
		open: isOpen = $bindable(),
		otherOpen = $bindable()
	}: {
		data: components['schemas']['EnableResponse'];
		open: boolean;
		otherOpen: boolean;
	} = $props();

	let currentStep = $state(0);

	const form = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/totp/enable/exchange', {
					body: {
						code: f.data.code
					}
				});

				// sorry... am to hecking lazy to make proper error handling for this dialog and everything else. zzz
				if (res.error?.error === ('TOTPIsAlreadyEnabled' as ApiHttpError)) {
					isOpen = false;
					invalidateAll();
				} else if (res.error?.error === ('InvalidTOTPCode' as ApiHttpError)) {
					setError(f, 'code', 'The code you entered is invalid');
				} else if (res.error?.error === ('TOTPFlowNotFound' as ApiHttpError)) {
					isOpen = false;
					invalidateAll();
				} else if (res.error) {
					console.error(res.error);
				}

				if (res.response.ok) {
					isOpen = false;
					otherOpen = true;
					invalidateAll();
				}
			}
		},
		id: 'enable-totp-dialog'
	});

	const { enhance, form: formData, delayed } = form;

	function nextStep() {
		if (currentStep < 2) currentStep += 1;
	}

	function prevStep() {
		if (currentStep > 0) currentStep -= 1;
	}
</script>

<Dialog.Root
	bind:open={isOpen}
	onOpenChange={(e) => {
		if (!e) {
			currentStep = 0;
			form.reset();
		}
	}}
>
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
							<Dialog.Title>Enable Two-Factor Authentication</Dialog.Title>
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
							{#if currentStep === 0}
								<p>
									Once enabled, you'll be prompted to enter a code from your authenticator app (2FAS
									Auth, Google Authenticator...) when you log in and try to enable sudo mode.
								</p>
								<QR
									data={getTotpQrData(data.secret, $user?.email ?? '')}
									style="width: 250px; height: 250px; margin-inline: auto; display: block;"
								/>

								<div class="secret-container">
									<p>Can't scan the QR code? Copy the code below:</p>
									<div class="secret">
										<span><strong>{data.secret}</strong></span>
										<Button small onclick={() => copyText(data.secret)}>
											{#snippet icon()}
												<ClipboardIcon size="20" />
											{/snippet}
										</Button>
									</div>
								</div>
							{/if}
							{#if currentStep === 1}
								<p>
									<strong>Save these back-up codes in a safe place</strong>. They are used when you
									lose access to your authenticator app and need to be able to log in again. These
									codes can be only used once.
								</p>
								<ul class="recovery-container">
									{#each data.recovery_codes as code}
										<li style="width: 50%; float: left; text-align: center; padding-inline: 8px;">
											{code}
										</li>
									{/each}
								</ul>
							{/if}
							{#if currentStep === 2}
								<p>To complete the setup, enter the code from your authenticator app</p>
								<form use:enhance>
									<FormContainer>
										<Field {form} name="code">
											<FieldContainer>
												<Control>
													{#snippet children({ props })}
														<Label>Two-Factor Code</Label>
														<Input
															{...props}
															bind:value={$formData.code}
															type="text"
															placeholder="000000"
														/>
													{/snippet}
												</Control>
												<FieldErrors />
											</FieldContainer>
										</Field>
									</FormContainer>
								</form>
							{/if}
						</div>
						<div class="dialog-footer">
							{#if currentStep === 2}
								<Button
									primary
									onclick={() => form.submit()}
									disabled={$delayed}
									loading={$delayed}
								>
									Save
								</Button>
							{:else}
								<Button primary onclick={nextStep} disabled={$delayed} loading={$delayed}>
									{#snippet icon()}
										<ChevronRight />
									{/snippet}
									Continue
								</Button>
							{/if}
							<Button onclick={() => (isOpen = false)} disabled={$delayed} loading={$delayed}
								>Cancel</Button
							>
							<Button onclick={prevStep} disabled={$delayed} loading={$delayed}>
								{#snippet icon()}
									<ChevronLeft />
								{/snippet}
								Go back
							</Button>
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

			.secret-container {
				display: flex;
				flex-direction: column;
				gap: 0.5rem;
			}

			.secret {
				display: flex;
				align-items: center;
				gap: 0.5rem;

				span {
					padding: 0.5rem;
					background-color: var(--bg-semidark);
					font-family: var(--font-mono);
					border-radius: 8px;
					white-space: nowrap;
					text-overflow: ellipsis;
					overflow: hidden;
				}
			}

			.recovery-container {
				background-color: var(--bg-semidark);
				border-radius: 8px;
				padding: 0.5rem 0;
				border: 1px solid var(--color-yellow);
				font-family: var(--font-mono);
				margin-inline: auto;
				width: 300px;
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
