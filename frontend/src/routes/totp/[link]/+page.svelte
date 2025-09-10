<script lang="ts" module>
	import z from 'zod/v4';
	const codeSchema = z.object({
		code: z.string().min(6).max(6)
	});
	const recoverySchema = z.object({
		recovery: z.string().min(10).max(10)
	});
</script>

<script lang="ts">
	import type { PageProps } from './$types';
	import { currentText } from '$lib/bigHeader';
	import { defaults, superForm, message as sMessage } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { goto } from '$app/navigation';
	import { Control, Field } from 'formsnap';
	import Spinner from '../../../components/spinner.svelte';
	import PinInput from '../../../components/forms/PinInput';
	import Button from '../../../components/button.svelte';

	let { data }: PageProps = $props();
	currentText.set('2FA Login');

	let recoveryMode = $state(false);

	const codeForm = superForm(defaults(zod4(codeSchema)), {
		validators: zod4(codeSchema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/totp/exchange-login', {
					body: {
						code_or_recovery: f.data.code,
						link_id: data.link
					}
				});

				if (res.error?.error === ('InvalidTOTPCode' as ApiHttpError)) {
					sMessage(f, res.error.message);
					codeForm.reset();
				} else if (res.error) {
					console.error(res.error);
					await goto('/'); // redirect with flash? idk
				}

				if (res.response.ok) {
					await goto('/yay');
				}
			}
		}
	});

	const recoveryForm = superForm(defaults(zod4(recoverySchema)), {
		validators: zod4(recoverySchema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const recovery = f.data.recovery.slice(0, 5) + '-' + f.data.recovery.slice(5, 10);
				const res = await client.POST('/v1/auth/totp/exchange-login', {
					body: {
						code_or_recovery: recovery,
						link_id: data.link
					}
				});

				if (res.error?.error === ('UsedRecoveryCode' as ApiHttpError)) {
					sMessage(f, res.error.message);
					codeForm.reset();
				} else if (res.error?.error === ('InvalidRecoveryCode' as ApiHttpError)) {
					sMessage(f, res.error.message);
					codeForm.reset();
				} else if (res.error) {
					await goto('/'); // redirect with flash? idk
				}

				if (res.response.ok) {
					await goto('/yay');
				}
			}
		}
	});

	const {
		enhance: codeEnhance,
		form: codeFormData,
		delayed: codeDelayed,
		message: codeMessage
	} = codeForm;

	const {
		enhance: recoveryEnhance,
		form: recoveryFormData,
		delayed: recoveryDelayed,
		message: recoveryMessage
	} = recoveryForm;

	const swapMode = () => {
		if ($recoveryDelayed || $codeDelayed) return;
		recoveryMode = !recoveryMode;
		recoveryForm.reset();
		codeForm.reset();
	};
</script>

<main>
	<div class="title">
		{#if !recoveryMode}
			<h1>Enter your Two-Factor code</h1>
		{:else}
			<h1>Enter your Two-Factor recovery code</h1>
		{/if}
		{#if !recoveryMode}
			<p>Enter the code from your authenticator app below</p>
		{:else}
			<p>Enter one of the backup recovery codes below</p>
		{/if}
	</div>

	{#if recoveryMode}
		<form use:recoveryEnhance>
			<Field form={recoveryForm} name="recovery">
				<Control>
					{#snippet children({ props })}
						<PinInput.root
							{...props}
							maxlength={10}
							pattern="mixed"
							bind:value={$recoveryFormData.recovery}
							onComplete={recoveryForm.submit}
							disabled={$recoveryDelayed}
							aria-disabled={$recoveryDelayed}
							class="recovery"
							pasteTransformer={(text) => text.replace(/-/g, '')}
						>
							{#snippet children({ cells })}
								<PinInput.cellContainer>
									{#each cells.slice(0, 5) as cell}
										<PinInput.cell {cell} />
									{/each}
								</PinInput.cellContainer>
								<PinInput.separator />
								<PinInput.cellContainer>
									{#each cells.slice(5, 10) as cell}
										<PinInput.cell {cell} />
									{/each}
								</PinInput.cellContainer>
							{/snippet}
						</PinInput.root>
					{/snippet}
				</Control>
			</Field>

			{#if $recoveryDelayed}
				<p>Verifying recovery code <Spinner /></p>
			{/if}

			{#if $recoveryMessage}
				<div class="message">
					<p>{$recoveryMessage}</p>
				</div>
			{/if}
		</form>
	{:else}
		<form use:codeEnhance>
			<Field form={codeForm} name="code">
				<Control>
					{#snippet children({ props })}
						<PinInput.root
							{...props}
							maxlength={6}
							pattern="digits"
							bind:value={$codeFormData.code}
							onComplete={codeForm.submit}
							disabled={$codeDelayed}
							aria-disabled={$codeDelayed}
						>
							{#snippet children({ cells })}
								<PinInput.cellContainer>
									{#each cells.slice(0, 3) as cell}
										<PinInput.cell {cell} />
									{/each}
								</PinInput.cellContainer>
								<PinInput.separator />
								<PinInput.cellContainer>
									{#each cells.slice(3, 6) as cell}
										<PinInput.cell {cell} />
									{/each}
								</PinInput.cellContainer>
							{/snippet}
						</PinInput.root>
					{/snippet}
				</Control>
			</Field>
			{#if $codeDelayed}
				<p>Verifying code <Spinner /></p>
			{/if}

			{#if $codeMessage}
				<div class="message">
					<p>{$codeMessage}</p>
				</div>
			{/if}
		</form>
	{/if}

	<div class="buttons">
		{#if recoveryMode}
			<Button big full_width onclick={swapMode}>Use Authenticator App</Button>
		{:else}
			<Button big full_width bad onclick={swapMode}>Use 2FA Recovery Code</Button>
		{/if}
	</div>
</main>

<style lang="scss">
	// copy of fieldErrors styles. should find a way to make a component
	.message {
		display: flex;
		flex-direction: row;
		gap: 0.5rem; // for icons
		align-items: center;
		p {
			font: inherit;
			font-size: 0.875rem;
			color: var(--color-bad);
		}
	}

	:global(.recovery) {
		--pin-max-width: 820px;
	}

	.buttons {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		min-width: 300px;
		max-width: 300px;
	}
	.title {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;

		p {
			font-size: 1.125rem;
		}
	}

	main {
		padding: 2.5rem 0;
		display: flex;
		align-items: center;
		flex-direction: column;
		z-index: 1;
		gap: 1.75rem;
	}

	h1 {
		font-size: 1.625rem;
		font-weight: 600;
		letter-spacing: var(--text-tight-spacing);
		text-align: center;
	}

	form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		align-items: center;
		width: 100%;
		p {
			font-size: 16px;
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}
	}
</style>
