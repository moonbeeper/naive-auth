<script lang="ts" module>
	import z from 'zod/v4';
	const schema = z.object({
		code: z.string().min(6).max(6)
	});
</script>

<script lang="ts">
	import { updateAuth } from '$lib/auth';
	import { currentText } from '$lib/bigHeader';
	import { defaults, superForm, message as sMessage } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { goto } from '$app/navigation';
	import Spinner from '../../components/spinner.svelte';
	import { Control, Field } from 'formsnap';
	import type { components as schemaComponents } from '$lib/api/v1';
	import PinInput from '../../components/forms/PinInput';

	currentText.set('yippie');

	$effect(() => {
		updateAuth();
	});

	const codeForm = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/otp/exchange-login', {
					body: {
						code: f.data.code,
						link_id: 'todo',
						email: 'todo'
					}
				});

				if (res.error?.error === ('InvalidOTPCode' as ApiHttpError)) {
					sMessage(f, res.error.message, { status: 400 });
				} else if (res.error) {
					sMessage(f, res.error.message, { status: 400 }); // redirect here?
				}

				if (res.response.ok) {
					await goto('/yay');
				}
			}
		}
	});

	const { enhance, form: formData, delayed, message } = codeForm;
</script>

yay you got a session!

<main>
	<div class="title">
		<h1>Check your email</h1>
		<p>We sent an email with your code to EMAIL. Input it below to continue</p>
	</div>

	<form use:enhance>
		<Field form={codeForm} name="code">
			<Control>
				{#snippet children({ props })}
					<PinInput.root
						maxlength={6}
						pattern="digits"
						{...props}
						bind:value={$formData.code}
						onComplete={codeForm.submit}
						disabled={$delayed}
						aria-disabled={$delayed}
					/>
				{/snippet}
			</Control>
		</Field>
		{#if $delayed}
			<p>Verifying code <Spinner /></p>
		{/if}

		{$message}
	</form>
</main>

<style lang="scss">
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
