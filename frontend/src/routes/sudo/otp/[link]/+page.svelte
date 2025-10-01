<script lang="ts" module>
	import z from 'zod/v4';
	const schema = z.object({
		code: z.string().length(6)
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
	import PinInput from '$comps/forms/PinInput';
	import Spinner from '$comps/spinner.svelte';
	import { fade, slide } from 'svelte/transition';

	let { data }: PageProps = $props();

	currentText.set('OTP Sudo');

	const codeForm = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/otp/exchange', {
					body: {
						code: f.data.code,
						link_id: data.link,
						email: data.email
					}
				});

				if (res.error?.error === ('InvalidOTPCode' as ApiHttpError)) {
					// todo: Find a way to make this add the data-fs-error attribute to the input (?)
					sMessage(f, res.error.message);
					codeForm.reset();
				} else if (res.error) {
					await goto('/'); // redirect with flash? idk
				}

				if (res.response.ok) {
					await goto('/settings');
				}
			}
		}
	});

	const { enhance, form: formData, delayed, message } = codeForm;
</script>

<main>
	<div class="title">
		<h1>Check your email</h1>
		<p>
			We sent an email with your code to <strong>{data.email}</strong>. Input it below to continue
		</p>
	</div>

	<form use:enhance>
		<Field form={codeForm} name="code">
			<Control>
				{#snippet children({ props })}
					<PinInput.Root
						{...props}
						maxlength={6}
						pattern="digits"
						bind:value={$formData.code}
						onComplete={codeForm.submit}
						disabled={$delayed}
						aria-disabled={$delayed}
					>
						{#snippet children({ cells })}
							<PinInput.cellContainer>
								{#each cells.slice(0, 3) as cell}
									<PinInput.Cell {cell} />
								{/each}
							</PinInput.cellContainer>
							<PinInput.Separator />
							<PinInput.cellContainer>
								{#each cells.slice(3, 6) as cell}
									<PinInput.Cell {cell} />
								{/each}
							</PinInput.cellContainer>
						{/snippet}
					</PinInput.Root>
				{/snippet}
			</Control>
		</Field>

		{#if $delayed}
			<p transition:slide>Verifying code <Spinner /></p>
		{/if}

		{#if $message}
			<div class="message">
				<p>{$message}</p>
			</div>
		{/if}
	</form>
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

	.title {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;

		p {
			font-size: 1rem;
			font-weight: 450;
			text-align: center;
		}

		h1 {
			font-size: 1.5rem;
			font-weight: 600;
			letter-spacing: var(--text-tight-spacing);
			text-align: center;
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
