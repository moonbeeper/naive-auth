<script lang="ts" module>
	import z from 'zod/v4';

	const schema = z
		.object({
			password: z
				.string()
				.trim()
				.min(8, 'Password must be at least 8 characters long')
				.max(74, 'That password is too long!'), // owasp says 64. me say 74
			password_confirm: z
				.string()
				.trim()
				.min(8, 'Password must be at least 8 characters long')
				.max(74, 'That password is too long!')
		})
		.refine((data) => data.password === data.password_confirm, {
			message: 'Seems like the passwords do not match. Try again?',
			path: ['password_confirm']
		});
</script>

<script>
	import { currentText } from '$lib/bigHeader';
	import Button from '../../../components/button.svelte';
	import Input from '../../../components/forms/input.svelte';
	import Spinner from '../../../components/spinner.svelte';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import { defaults, superForm, message as sMessage } from 'sveltekit-superforms';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { goto } from '$app/navigation';
	import { Control, Field } from 'formsnap';
	import Label from '../../../components/forms/label.svelte';
	import FieldContainer from '../../../components/forms/fieldContainer.svelte';
	import FieldErrors from '../../../components/forms/fieldErrors.svelte';
	import FormContainer from '../../../components/forms/formContainer.svelte';
	import type { PageProps } from './$types';
	import { error } from '@sveltejs/kit';

	currentText.set('Reset Password');

	let { data }: PageProps = $props();
	let doneWorking = $state(false);

	const form = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.PUT('/v1/auth/reset/{id}/set', {
					body: {
						password: f.data.password,
						password_confirm: f.data.password_confirm
					},
					params: {
						path: {
							id: data.link
						}
					}
				});

				if (
					res.error?.error === ('RecoveryLinkNotFound' as ApiHttpError) &&
					res.response.status === 404
				) {
					error(400, 'Invalid password reset link');
				} else if (res.error) {
					sMessage(f, res.error.message);
					form.reset();
				}

				if (res.response.ok) {
					await goto('/reset-password/finished');
				}
			}
		}
	});

	const { enhance, form: formData, delayed, message } = form;
</script>

<main>
	<div class="title">
		{#if !doneWorking}
			<h1>Reset your password</h1>
			<p>Enter your new password below for your account</p>
		{:else}
			<h1>Password updated!</h1>
			<p>Your password has been updated! You have been logged out.</p>
		{/if}
	</div>

	{#if !doneWorking}
		{#if $message}
			<div class="message">
				<p>{$message}</p>
			</div>
		{/if}

		<form class="container" use:enhance>
			<FormContainer>
				<Field {form} name="password">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Password</Label>
								<Input
									{...props}
									disabled={$delayed}
									type="password"
									placeholder="•••••••••••••"
									big
									autocomplete="off"
									bind:value={$formData.password}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
				<Field {form} name="password_confirm">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Confirm new password</Label>
								<Input
									{...props}
									disabled={$delayed}
									type="password"
									placeholder="•••••••••••••"
									big
									autocomplete="off"
									bind:value={$formData.password_confirm}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
			</FormContainer>

			<Button big primary full_width type="submit" disabled={$delayed} loading={$delayed}>
				{#snippet icon()}
					{#if $delayed}
						<Spinner dark />
					{/if}
				{/snippet}
				Change Password
			</Button>
		</form>
	{/if}
</main>

<style lang="scss">
	// copy of fieldErrors styles. should find a way to make a component
	.message {
		border: 1px solid var(--color-bad-darkened);
		padding: 0.5rem;
		border-radius: 8px;
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

	p {
		font-size: 0.875rem;
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}

	.container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		align-items: center;
		min-width: 300px;
		max-width: 300px;
	}
</style>
