<script lang="ts" module>
	import { z } from 'zod/v4'; // why?

	const otpSchema = z.object({
		email: z.email("I don't think that's a valid email")
	});

	const passwordSchema = z.object({
		email: z
			.email("I don't think that's a valid email")
			.or(z.string().trim().min(6, 'Your login should be at least 6 characters long')),
		password: z.string().trim().min(8, 'Password must be at least 8 characters long')
	});
</script>

<script lang="ts">
	import { defaults, superForm, message as sMessage } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import { Control, Field } from 'formsnap';
	import { goto } from '$app/navigation';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import FormContainer from '$comps/forms/formContainer.svelte';
	import FieldContainer from '$comps/forms/fieldContainer.svelte';
	import Label from '$comps/forms/label.svelte';
	import Input from '$comps/forms/input.svelte';
	import FieldErrors from '$comps/forms/fieldErrors.svelte';
	import Link from '$comps/link.svelte';
	import Button from '$comps/button.svelte';
	import Spinner from '$comps/spinner.svelte';
	import { currentText } from '$lib/bigHeader';

	currentText.set('Log in');
	let passwordMode = $state(false);

	const otpForm = superForm(defaults(zod4(otpSchema)), {
		validators: zod4(otpSchema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/otp/login', {
					body: {
						email: f.data.email
					}
				});

				if (res.error) {
					sMessage(f, res.error.message);
					otpForm.reset();
				}
				if (res.response.ok) {
					let template = '/otp/{link}?email={email}';

					await goto(
						template.replace('{link}', res.data?.link_id ?? '').replace('{email}', f.data.email)
					);
				}
			}
		}
	});

	const passwordForm = superForm(defaults(zod4(passwordSchema)), {
		validators: zod4(passwordSchema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/login', {
					body: {
						login: f.data.email,
						password: f.data.password
					}
				});

				if (res.error?.error === ('TOTPIsRequired' as ApiHttpError)) {
					const template = '/totp/{link}';
					await goto(template.replace('{link}', res.error.link_id ?? '00000000000000000000000000'));
				} else if (res.error) {
					sMessage(f, res.error.message);
					otpForm.reset();
				}

				if (res.response.ok) {
					await goto('/settings');
				}
			}
		}
	});

	const {
		enhance: otpEnhance,
		form: otpFormData,
		delayed: otpDelayed,
		message: otpMessage
	} = otpForm;
	const {
		enhance: passwordEnhance,
		form: passwordFormData,
		delayed: passwordDelayed,
		message: passwordMessage
	} = passwordForm;

	const swapMode = () => {
		if ($otpDelayed || $passwordDelayed) return;
		passwordMode = !passwordMode;
		otpForm.reset();
		passwordForm.reset();
	};
</script>

<main>
	<h1>Log in to your account</h1>

	{#if $passwordMessage}
		<div class="message">
			<p>{$passwordMessage}</p>
		</div>
	{/if}

	{#if $otpMessage}
		<div class="message">
			<p>{$otpMessage}</p>
		</div>
	{/if}

	{#if !passwordMode}
		<form class="container" use:otpEnhance>
			<FormContainer>
				<Field form={otpForm} name="email">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Email address</Label>
								<Input
									{...props}
									disabled={$otpDelayed}
									type="email"
									placeholder="beep@example.com"
									big
									autocomplete="email"
									bind:value={$otpFormData.email}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
			</FormContainer>

			<p>
				or use <Link href="/" onclick={() => swapMode()} disabled={$otpDelayed}>your password</Link>
			</p>

			<Button big primary full_width type="submit" disabled={$otpDelayed} loading={$otpDelayed}>
				{#snippet icon()}
					{#if $otpDelayed}
						<Spinner dark />
					{/if}
				{/snippet}
				Continue with Email
			</Button>
		</form>
	{:else}
		<form class="container" use:passwordEnhance>
			<FormContainer>
				<Field form={passwordForm} name="email">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Email address</Label>
								<Input
									{...props}
									disabled={$passwordDelayed}
									type="email"
									placeholder="beep@example.com"
									big
									autocomplete="email"
									bind:value={$passwordFormData.email}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
				<Field form={passwordForm} name="password">
					<FieldContainer>
						<Control>
							{#snippet children({ props })}
								<Label>Password</Label>
								<Input
									{...props}
									disabled={$passwordDelayed}
									type="password"
									placeholder="•••••••••••••"
									big
									autocomplete="off"
									bind:value={$passwordFormData.password}
								/>
							{/snippet}
						</Control>
						<FieldErrors />
					</FieldContainer>
				</Field>
			</FormContainer>

			<p>
				or use a <Link href="/" onclick={() => swapMode()} disabled={$passwordDelayed}
					>one-time code</Link
				>
			</p>
			<p>
				Forgot your password? <Link href="/reset-password">Reset it here</Link>
			</p>

			<Button
				big
				primary
				full_width
				type="submit"
				disabled={$passwordDelayed}
				loading={$passwordDelayed}
			>
				{#snippet icon()}
					{#if $passwordDelayed}
						<Spinner dark />
					{/if}
				{/snippet}

				Continue with Password
			</Button>
		</form>
	{/if}
	<em></em>
	<div class="container">
		<Button big full_width disabled>Continue with Github</Button>
		<Button big full_width disabled>Continue with Google</Button>
	</div>
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

	h1 {
		font-size: 1.5rem;
		font-weight: 600;
		letter-spacing: var(--text-almost-tight-spacing);
	}

	em {
		width: 300px;
		border: #222222 1px solid;
	}
</style>
