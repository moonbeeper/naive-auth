<script lang="ts" module>
	import z from 'zod/v4';

	const schema = z.object({
		email: z.email("I don't think that's a valid email")
	});
</script>

<script>
	import { currentText } from '$lib/bigHeader';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import { defaults, superForm, message as sMessage } from 'sveltekit-superforms';
	import client from '$lib/api/baseFetch';
	import { Control, Field } from 'formsnap';
	import FormContainer from '$comps/forms/formContainer.svelte';
	import FieldContainer from '$comps/forms/fieldContainer.svelte';
	import Input from '$comps/forms/input.svelte';
	import Label from '$comps/forms/label.svelte';
	import FieldErrors from '$comps/forms/fieldErrors.svelte';
	import Button from '$comps/button.svelte';
	import Spinner from '$comps/spinner.svelte';
	import { slide } from 'svelte/transition';

	currentText.set('Reset Password');

	let done = $state(false);
	let email: string = $state('');

	const form = superForm(defaults(zod4(schema)), {
		validators: zod4(schema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/reset', {
					body: {
						email: f.data.email
					}
				});

				if (res.error) {
					sMessage(f, res.error.message);
					form.reset();
				}

				if (res.response.ok) {
					done = true;
					email = f.data.email;
				}
			}
		}
	});

	const { enhance, form: formData, delayed, message } = form;

	function go_back() {
		done = false;
		email = '';
		form.reset();
	}
</script>

<svelte:head>
	<title>Reset Password | BeepAuth</title>
</svelte:head>

<main>
	<div class="title">
		{#if !done}
			<h1>Reset your password</h1>
			<p>To reset your password, enter your email address below</p>
		{:else}
			<h1>Reset link sent!</h1>
			<p>
				We sent an email with your reset link at <strong>{email.trimEnd()}</strong>. Check your
				inbox!
			</p>
		{/if}
	</div>

	{#if !done}
		{#if $message}
			<div class="message">
				<p>{$message}</p>
			</div>
		{/if}

		<form class="container" use:enhance>
			<FormContainer>
				<Field {form} name="email">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Email address</Label>
								<Input
									{...props}
									disabled={$delayed}
									type="email"
									placeholder="reset-me@example.com"
									big
									autocomplete="email"
									bind:value={$formData.email}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
			</FormContainer>

			<Button big primary full_width type="submit" disabled={$delayed} loading={$delayed}>
				{#snippet icon()}
					<span transition:slide={{ axis: 'x' }}>
						<Spinner dark />
					</span>
				{/snippet}
				Send reset link
			</Button>
		</form>
	{:else}
		<div class="container">
			<Button big full_width disabled={$delayed} loading={$delayed} onclick={go_back}>
				Wrong email address?
			</Button>
		</div>
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

	.container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		align-items: center;
		min-width: 300px;
		max-width: 300px;
	}
</style>
