<script lang="ts" module>
	import z from 'zod/v4';

	const passwordSchema = z.object({
		new_password: z.string().trim().min(8, 'Password must be at least 8 characters long'),
		old_password: z.string().trim().min(8, 'Password must be at least 8 characters long')
	});
</script>

<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';
	import FieldContainer from '$comps/forms/fieldContainer.svelte';
	import Input from '$comps/forms/input.svelte';
	import Label from '$comps/forms/label.svelte';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { user } from '$lib/auth';
	import { Control, Field } from 'formsnap';
	import { defaults, setError, superForm } from 'sveltekit-superforms';
	import { zod4 } from 'sveltekit-superforms/adapters';
	import { LaptopMinimal, Smartphone, Trash } from '@lucide/svelte';
	import type { PageProps } from './$types';
	import Spinner from '$comps/spinner.svelte';
	import Button from '$comps/button.svelte';
	import FieldErrors from '$comps/forms/fieldErrors.svelte';

	let { data }: PageProps = $props();

	const form = superForm(defaults(zod4(passwordSchema)), {
		validators: zod4(passwordSchema),
		SPA: true,
		onUpdate: async ({ form: f }) => {
			if (f.valid) {
				const res = await client.POST('/v1/auth/change_password', {
					body: {
						new_password: f.data.new_password,
						old_password: f.data.old_password
					}
				});

				if (res.error?.error === ('SudoIsNotEnabled' as ApiHttpError)) {
					await goto('/sudo');
				} else if (res.error?.error === ('InvalidOldPassword' as ApiHttpError)) {
					setError(f, 'old_password', res.error.message);
				} else if (res.error?.error === ('PasswordLowStrength' as ApiHttpError)) {
					setError(f, 'new_password', res.error.message);
				} else if (res.error?.error === ('PasswordMatchesOld' as ApiHttpError)) {
					setError(f, 'new_password', res.error.message);
				}

				if (res.response.ok) {
					await goto('/settings');
				}
			}
		}
	});

	const { enhance, form: formData, delayed } = form;

	let resetPasswordEmailSent = $state(false);
	let resetPasswordEmailFailed = $state(false); // hoho dirty code
	let resetPasswordLoading = $state(false);

	async function resetPassword() {
		resetPasswordLoading = true;
		const res = await client.POST('/v1/auth/reset', {
			body: {
				email: $user?.email ?? ''
			}
		});

		if (res.error) {
			resetPasswordLoading = false;
			resetPasswordEmailFailed = true;
		}

		if (res.response.ok) {
			resetPasswordLoading = false;
			resetPasswordEmailSent = true;
		}
	}

	let loadingDeleteAllSessions = $state(false);
	async function deleteAllSessions() {
		if (loadingDeleteAllSessions) return;
		loadingDeleteAllSessions = true;
		const res = await client.DELETE('/v1/session/all');

		if (res.error) {
			loadingDeleteAllSessions = false;
			console.error(res.error);
		}

		if (res.response.ok) {
			loadingDeleteAllSessions = false;
			invalidateAll();
		}
	}

	let loadingDeleteSession: Record<string, boolean> = $state({});
	async function deleteSession(id: string) {
		if (loadingDeleteSession[id]) return;

		loadingDeleteSession[id] = true;
		const res = await client.DELETE('/v1/session/{id}', {
			params: {
				path: {
					id
				}
			}
		});

		if (res.error?.error === ('SudoIsNotEnabled' as ApiHttpError)) {
			await goto('/sudo');
		} else if (res.error) {
			loadingDeleteSession[id] = false;
			console.error(res.error);
		}

		if (res.response.ok) {
			loadingDeleteSession[id] = false;
			invalidateAll();
		}
	}
</script>

<div class="page">
	<div class="section">
		<div class="title">
			<h2>Change Password</h2>
		</div>
		<form class="form" use:enhance>
			<Field {form} name="old_password">
				<FieldContainer>
					<Control>
						{#snippet children({ props })}
							<Label>Current Password</Label>
							<Input
								disabled={$delayed}
								type="password"
								placeholder="•••••••••••••"
								big
								autocomplete="off"
								bind:value={$formData.old_password}
								{...props}
							/>
						{/snippet}
					</Control>
					<FieldErrors />
				</FieldContainer>
			</Field>
			<Field {form} name="new_password">
				<FieldContainer>
					<Control>
						{#snippet children({ props })}
							<Label>New Password</Label>
							<Input
								disabled={$delayed}
								type="password"
								placeholder="•••••••••••••"
								big
								autocomplete="off"
								bind:value={$formData.new_password}
								{...props}
							/>
						{/snippet}
					</Control>
					<FieldErrors />
				</FieldContainer>
			</Field>
			<Button big primary full_width type="submit" disabled={$delayed} loading={$delayed}>
				{#snippet icon()}
					{#if $delayed}
						<Spinner dark />
					{/if}
				{/snippet}

				Change Password
			</Button>
		</form>

		<div class="reset_password">
			<Button
				small
				onclick={resetPassword}
				disabled={resetPasswordLoading}
				loading={resetPasswordLoading}
			>
				{#snippet icon()}
					{#if resetPasswordLoading}
						<Spinner />
					{/if}
				{/snippet}
				I forgot my password
			</Button>
			{#if resetPasswordEmailSent}
				<p>
					<strong>Check your email.</strong> We've just sent you a reset link.
				</p>
			{/if}
			{#if resetPasswordEmailFailed}
				<p>Something went wrong :(</p>
			{/if}
		</div>
	</div>

	<div class="section">
		<div class="title">
			<h2>Open Sessions</h2>
		</div>

		<Button
			bad
			onclick={deleteAllSessions}
			disabled={loadingDeleteAllSessions}
			loading={loadingDeleteAllSessions}
		>
			{#snippet icon()}
				{#if loadingDeleteAllSessions}
					<Spinner />
				{/if}
			{/snippet}
			Delete all open sessions
		</Button>

		{#await data.sessions}
			<p>Loading...</p>
		{:then sessions}
			{#each sessions ?? [] as session}
				<div class="session">
					{#if session.os === 'Android'}
						<Smartphone class="icon" />
					{:else}
						<LaptopMinimal class="icon" />
					{/if}

					<div class="info">
						<span>{session.os}</span>
						{#if session.current}
							<span>-> <strong>Current session</strong></span>
						{/if}
						<span>Expires on the {new Date(session.active_expires_at).toLocaleString()}</span>
					</div>

					<div class="buttons">
						<Button
							bad
							onclick={() => deleteSession(session.id)}
							disabled={session.current || loadingDeleteSession[session.id]}
							loading={loadingDeleteSession[session.id]}
						>
							{#snippet icon()}
								<Trash class="icon" />
							{/snippet}
						</Button>
					</div>
				</div>
			{/each}
		{:catch error}
			<p>Something went wrong while loading your sessions :(</p>
			<p>{error}</p>
		{/await}
	</div>
</div>

<style lang="scss">
	.section {
		display: flex;
		gap: 1rem;
		flex-direction: column;

		.title {
			h2 {
				font-size: 24px;
				font-weight: 600;
			}

			display: flex;
			margin-bottom: 0.75rem;
			border-bottom: 1px solid var(--bg-semidark);
			padding-bottom: 0.75rem;
		}
	}

	.form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		width: 300px;
	}

	.reset_password {
		display: flex;
		align-items: center;
		gap: 1rem;

		p {
			font-size: 14px;
		}
	}

	.page {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}

	.session {
		display: flex;
		justify-content: flex-start;
		gap: 1rem;
		padding: 1rem;
		border-radius: 8px;
		border: 1px solid var(--bg-semidark);

		:global(.icon) {
			width: 24px;
			height: 24px;
			flex-shrink: 0;
		}

		.info {
			display: flex;
			flex-direction: column;
			gap: 0.5rem;
			width: 100%;
		}

		.buttons {
			display: flex;
			:global(.icon) {
				width: 20px;
				height: 20px;
				flex-shrink: 0;
			}
		}
	}
</style>
