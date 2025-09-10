<script lang="ts" module>
	import { z } from 'zod/v4'; // why?

	const otpSchema = z.object({
		email: z.email("I don't think that's a valid email!")
	});

	const passwordSchema = z.object({
		email: z
			.email("I don't think that's a valid email!")
			.or(z.string().min(6, 'Your login should be at least 6 characters long')),
		password: z.string().min(8, 'Password must be at least 8 characters long!')
	});
</script>

<script lang="ts">
	import Button from '../components/button.svelte';
	import Input from '../components/forms/input.svelte';
	import { currentText } from '$lib/bigHeader';
	import Link from '../components/link.svelte';
	import { defaults, superForm } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import { Control, Field } from 'formsnap';
	import Label from '../components/forms/label.svelte';
	import FormContainer from '../components/forms/container.svelte';
	import FieldErrors from '../components/forms/fieldErrors.svelte';
	import client from '$lib/api/baseFetch';
	import Spinner from '../components/spinner.svelte';
	import { goto } from '$app/navigation';

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

				if (res.response.ok) {
					await goto('/yay');
				}
			}
		}
	});

	const { enhance: otpEnhance, form: otpFormData, delayed: otpDelayed } = otpForm;
	const {
		enhance: passwordEnhance,
		form: passwordFormData,
		delayed: passwordDelayed
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

	<div class="wawa"></div>
	{#if !passwordMode}
		<form class="container" use:otpEnhance>
			<Field form={otpForm} name="email">
				<FormContainer>
					<Control>
						{#snippet children({ props })}
							<Label>Email address</Label>
							<Input
								{...props}
								disabled={$otpDelayed}
								type="text"
								placeholder="beep@example.com"
								big
								autocomplete="email"
								bind:value={$otpFormData.email}
							/>
						{/snippet}
					</Control>
					<FieldErrors />
				</FormContainer>
			</Field>

			<p>or use <Link href="/" onclick={() => swapMode()}>your password</Link></p>

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
			<Field form={passwordForm} name="email">
				<FormContainer>
					<Control>
						{#snippet children({ props })}
							<Label>Email address</Label>
							<Input
								{...props}
								disabled={$passwordDelayed}
								type="text"
								placeholder="beep@example.com"
								big
								autocomplete="email"
								bind:value={$passwordFormData.email}
							/>
						{/snippet}
					</Control>
					<FieldErrors />
				</FormContainer>
			</Field>
			<Field form={passwordForm} name="password">
				<FormContainer>
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
				</FormContainer>
			</Field>

			<p>
				or use a <Link href="/" onclick={() => swapMode()}>one-time code</Link>
			</p>
			<p>
				Don't have an account yet? <a href="/signup">Sign up</a>
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
		<Button big full_width>Continue with Github</Button>
		<Button big full_width>Continue with Google</Button>
	</div>
</main>

<style lang="scss">
	.wawa {
		padding: 0.5rem;
		
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
		font-size: 14px;
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
		font-size: 1.625rem;
		font-weight: 600;
		letter-spacing: var(--text-tight-spacing);
	}

	em {
		width: 300px;
		border: #222222 1px solid;
	}
</style>
