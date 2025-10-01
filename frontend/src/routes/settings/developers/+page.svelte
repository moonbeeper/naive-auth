<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import Spinner from '$comps/spinner.svelte';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { Hexagon, Pencil, Plus, X } from '@lucide/svelte';
	import type { PageProps } from './$types';
	import { scopeToLegible } from '$lib/oauthScopes';
	import Button from '$comps/button.svelte';
	import { slide } from 'svelte/transition';
	import CreateOauthAppDialog from '$comps/forms/dialogs/createOauthAppDialog.svelte';
	import type { components } from '$lib/api/v1';
	import SecretOauthAppDialog from '$comps/forms/dialogs/secretOauthAppDialog.svelte';
	import UpdateOauthAppDialog from '$comps/forms/dialogs/updateOauthAppDialog.svelte';

	let { data }: PageProps = $props();

	let loadingDeleteApplication: Record<string, boolean> = $state({});
	async function deleteApplication(id: string) {
		if (loadingDeleteApplication[id]) return;

		loadingDeleteApplication[id] = true;
		const res = await client.DELETE('/v1/oauth/apps/{id}', {
			params: {
				path: {
					id
				}
			}
		});

		if (res.error?.error === ('OAuthAppNotFound' as ApiHttpError)) {
			loadingDeleteApplication[id] = false;
			invalidateAll();
		} else if (res.error) {
			loadingDeleteApplication[id] = false;
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok) {
			loadingDeleteApplication[id] = false;
			invalidateAll();
		}
	}

	let showSecretDialog = $state(false);
	let showCreateDialog = $state(false);

	let creationResponse = $state<components['schemas']['CreateAppResponse']>({
		id: 'X2XKJVVLCKVM4CG25WAWAI2LINOTREAL',
		secret_key: 'EAQVMRMFCDXVTBPDR3W4VBEEP4WGEOIEEUHMIAUWNZDLDEADBEEF'
	});
	function createApp(data: components['schemas']['CreateAppResponse']) {
		showCreateDialog = false;
		creationResponse = data;
		showSecretDialog = true;
	}

	let showUpdateDialog = $state(false);
	let updateDefaultData = $state<components['schemas']['OauthApp']>({
		id: 'X2XKJVVLCKVM4CG25WAWAI2LINOTREAL',
		name: 'unknown',
		description: 'unknown',
		scopes: ['unknown'],
		callback_url: 'unknown',
		created_at: '2069-01-01T00:00:00Z'
	});

	async function updateApp(id: string) {
		const res = await client.GET('/v1/oauth/apps/{id}', {
			params: {
				path: {
					id
				}
			}
		});

		if (res.error?.error === ('OAuthAppNotFound' as ApiHttpError)) {
			invalidateAll();
		} else if (res.error) {
			loadingDeleteApplication[id] = false;
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok && res.data) {
			updateDefaultData = res.data;
			showUpdateDialog = true;
		}
	}
</script>

<CreateOauthAppDialog data={createApp} bind:open={showCreateDialog} />
<SecretOauthAppDialog bind:open={showSecretDialog} data={creationResponse} />
<UpdateOauthAppDialog bind:open={showUpdateDialog} data={updateDefaultData} />

<div class="section">
	<div class="title">
		<h2>My OAuth Apps</h2>
		<Button primary onclick={() => (showCreateDialog = true)}>
			{#snippet icon()}
				<Plus size="20" />
			{/snippet}
			Create an app
		</Button>
	</div>

	{#await data.apps}
		<div style="margin-inline: auto;">
			<Spinner />
		</div>
	{:then apps}
		{#if apps?.length === 0}
			<div
				style="margin-inline: auto; display: flex; flex-direction: column; align-items: center; gap: 1rem;"
			>
				<p>You haven't created any apps yet.</p>
				<Button onclick={() => (showCreateDialog = true)}>
					{#snippet icon()}
						<Plus size="20" />
					{/snippet}
					Create an app
				</Button>
			</div>
		{/if}
		{#each apps?.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()) ?? [] as app}
			<div class="app">
				<!-- I like how it looks :] since currently apps don't have icons because I don't have a place to store them -->
				<Hexagon />

				<div class="info">
					<span class="name">{app.name}</span>
					<span>Callback URL: <strong>{app.callback_url}</strong></span>
					<span>App Id: <strong>{app.id}</strong></span>
					<span>Created on the {new Date(app.created_at).toLocaleString()}</span>

					<div class="section">
						<div class="title">
							<h2>Available Scopes ({app.scopes.length})</h2>
						</div>
						<ul>
							{#each app.scopes ?? [] as scope}
								<li>{scopeToLegible(scope)} ({scope})</li>
							{/each}
						</ul>
					</div>
				</div>

				<div class="buttons">
					<Button class="desktop" onclick={() => updateApp(app.id)}>
						{#snippet icon()}
							{#if loadingDeleteApplication[app.id]}
								<span transition:slide={{ axis: 'x' }}>
									<Spinner />
								</span>
							{:else}
								<Pencil class="icon" size="20" />
							{/if}
						{/snippet}

						Edit app
					</Button>
					<Button
						class="desktop"
						bad
						onclick={() => deleteApplication(app.id)}
						disabled={loadingDeleteApplication[app.id]}
						loading={loadingDeleteApplication[app.id]}
					>
						{#snippet icon()}
							{#if loadingDeleteApplication[app.id]}
								<span transition:slide={{ axis: 'x' }}>
									<Spinner />
								</span>
							{:else}
								<X class="icon" size="20" />
							{/if}
						{/snippet}

						Delete app
					</Button>

					<Button onclick={() => updateApp(app.id)} class="phone">
						{#snippet icon()}
							{#if loadingDeleteApplication[app.id]}
								<span transition:slide={{ axis: 'x' }}>
									<Spinner />
								</span>
							{:else}
								<Pencil class="icon" size="20" />
							{/if}
						{/snippet}
					</Button>
					<Button
						bad
						onclick={() => deleteApplication(app.id)}
						disabled={loadingDeleteApplication[app.id]}
						loading={loadingDeleteApplication[app.id]}
						class="phone"
					>
						{#snippet icon()}
							{#if loadingDeleteApplication[app.id]}
								<span transition:slide={{ axis: 'x' }}>
									<Spinner />
								</span>
							{:else}
								<X class="icon" size="20" />
							{/if}
						{/snippet}
					</Button>
				</div>
			</div>
		{/each}
	{:catch error}
		<p>Something went wrong while loading your authorized apps :(</p>
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

	.app {
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

			.name {
				font-weight: 600;
				font-size: 18px;
			}

			.section {
				margin-top: 0.5rem;
				gap: 0;

				h2 {
					font-size: 18px;
				}

				ul {
					list-style: circle;
					padding-left: 1.25rem;
					display: flex;
					gap: 0.5rem;
					flex-direction: column;
					font-size: 0.95rem;
				}
			}
		}

		.buttons {
			display: flex;
			flex-direction: column;
			align-items: end;

			gap: 0.5rem;

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
