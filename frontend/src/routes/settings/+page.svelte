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
	import { LaptopMinimal, Smartphone, Trash, X } from '@lucide/svelte';
	import type { PageProps } from './$types';
	import Spinner from '$comps/spinner.svelte';
	import Button from '$comps/button.svelte';
	import FieldErrors from '$comps/forms/fieldErrors.svelte';
	import { blur, crossfade, fade, fly, slide } from 'svelte/transition';
	import type { components } from '$lib/api/v1';
	import TotpEnabledDialog from '$comps/forms/dialogs/totpEnabledDialog.svelte';
	import EnableTotpDialog from '$comps/forms/dialogs/enableTotpDialog.svelte';
	import ViewTotpSecrets from '$comps/forms/dialogs/viewTotpSecrets.svelte';

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
				} else if (res.error) {
					console.error(res.error);
				}

				if (res.response.ok) {
					invalidateAll();
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
			invalidateAll();
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
			invalidateAll();
		}

		if (res.response.ok) {
			loadingDeleteSession[id] = false;
			invalidateAll();
		}
	}

	let enableTotpData = $state<components['schemas']['EnableResponse']>({
		recovery_codes: ['deadbeef'],
		secret: 'deadbeef'
	});
	let enableTotpDialog = $state(false);
	let totpEnabledDialog = $state(false);
	async function enableTotp() {
		const res = await client.POST('/v1/auth/totp/enable');

		if (res.error?.error === ('TOTPIsAlreadyEnabled' as ApiHttpError)) {
			console.error(res.error);
			invalidateAll();
		} else if (res.error) {
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok && res.data) {
			enableTotpData = res.data;
			enableTotpDialog = true;
		}
	}

	let disableTotpLoading = $state(false);
	async function disableTotp() {
		disableTotpLoading = true;

		const res = await client.DELETE('/v1/totp');

		if (res.error?.error === ('SudoIsNotEnabled' as ApiHttpError)) {
			await goto('/sudo');
		} else if (res.error) {
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok) {
			disableTotpLoading = false;
			invalidateAll();
		}
	}

	let seeRecoveryCodesData = $state<string[]>([]);
	let seeRecoveryCodeDialog = $state(false);
	async function viewTotpRecoveryCodes() {
		const res = await client.GET('/v1/totp/recovery');

		if (res.error?.error === ('SudoIsNotEnabled' as ApiHttpError)) {
			await goto('/sudo');
		} else if (res.error) {
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok && res.data) {
			seeRecoveryCodesData = res.data.recovery_codes;
			seeRecoveryCodeDialog = true;
		}
	}
</script>

<svelte:head>
	<title>Authentication | BeepAuth</title>
</svelte:head>

<TotpEnabledDialog bind:open={totpEnabledDialog} />
<EnableTotpDialog
	bind:open={enableTotpDialog}
	data={enableTotpData}
	bind:otherOpen={totpEnabledDialog}
/>
<ViewTotpSecrets bind:open={seeRecoveryCodeDialog} recoveryCodes={seeRecoveryCodesData} />

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
					<span transition:slide={{ axis: 'x' }}>
						<Spinner dark />
					</span>
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
					<span transition:slide={{ axis: 'x' }}>
						<Spinner />
					</span>
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
		<h2>Two-Factor Authentication</h2>
	</div>

	{#if $user?.totp_enabled}
		<p>Two-Factor Authentication is <strong>enabled</strong> for your account.</p>
		<div class="two-factor-buttons">
			<Button
				disabled={disableTotpLoading}
				loading={disableTotpLoading}
				onclick={viewTotpRecoveryCodes}>View two-factor recovery codes</Button
			>
			<Button bad onclick={disableTotp} disabled={disableTotpLoading} loading={disableTotpLoading}
				>Disable two-factor authentication</Button
			>
		</div>
	{:else}
		<p>Two-Factor Authentication is <strong>not enabled</strong> for your account.</p>
		<Button primary onclick={() => enableTotp()}>Enable two-factor authentication</Button>
	{/if}
</div>
<div class="section">
	<div class="title">
		<h2>Open Sessions</h2>
		<Button
			bad
			onclick={deleteAllSessions}
			disabled={loadingDeleteAllSessions}
			loading={loadingDeleteAllSessions}
		>
			{#snippet icon()}
				{#if loadingDeleteAllSessions}
					<span transition:slide={{ axis: 'x' }}>
						<Spinner dark />
					</span>
				{:else}
					<Trash size="16" />
				{/if}
			{/snippet}
			Delete all
		</Button>
	</div>

	{#await data.sessions}
		<div style="margin-inline: auto;">
			<Spinner />
		</div>
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
						class="desktop"
						bad
						onclick={() => deleteSession(session.id)}
						disabled={session.current || loadingDeleteSession[session.id]}
						loading={loadingDeleteSession[session.id]}
					>
						{#snippet icon()}
							{#if loadingDeleteSession[session.id]}
								<Spinner />
							{:else}
								<X class="icon" size="20" />
							{/if}
						{/snippet}

						Delete Session
					</Button>
					<Button
						bad
						onclick={() => deleteSession(session.id)}
						disabled={session.current || loadingDeleteSession[session.id]}
						loading={loadingDeleteSession[session.id]}
						class="phone"
					>
						{#snippet icon()}
							{#if loadingDeleteSession[session.id]}
								<Spinner />
							{:else}
								<X class="icon" size="20" />
							{/if}
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

<style lang="scss">
	.section {
		display: grid;
		gap: 1rem;
		flex-direction: column;

		.title {
			h2 {
				font-size: 24px;
				font-weight: 600;
			}

			display: grid;
			margin-bottom: 0.75rem;
			border-bottom: 1px solid var(--bg-semidark);
			padding-bottom: 0.75rem;
			align-items: center;
			grid-template-columns: 1fr auto;
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

	.two-factor-buttons {
		display: flex;
		gap: 0.5rem;
	}

	.session {
		display: grid;
		justify-content: flex-start;
		grid-template-columns: 24px 1fr auto;
		gap: 1rem;
		padding: 1rem;
		border-radius: 8px;
		border: 1px solid var(--bg-semidark);
		transition: border 0.1s ease-out;

		&:hover {
			border: 1px solid var(--bg-notdark);
		}

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

			:global(.desktop) {
				display: none;
			}

			@media (min-width: 768px) {
				:global(.desktop) {
					display: flex;
				}

				:global(.phone) {
					display: none;
				}
			}
		}
	}
</style>
