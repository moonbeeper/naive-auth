<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import Spinner from '$comps/spinner.svelte';
	import client, { type ApiHttpError } from '$lib/api/baseFetch';
	import { Hexagon, X } from '@lucide/svelte';
	import type { PageProps } from './$types';
	import { scopesToLegible } from '$lib/oauthScopes';
	import Button from '$comps/button.svelte';
	import { slide } from 'svelte/transition';

	let { data }: PageProps = $props();

	let loadingDeleteAuthorization: Record<string, boolean> = $state({});
	async function deleteAuthorization(id: string) {
		if (loadingDeleteAuthorization[id]) return;

		loadingDeleteAuthorization[id] = true;
		const res = await client.DELETE('/v1/oauth/authorized/{id}', {
			params: {
				path: {
					id
				}
			}
		});

		if (res.error?.error === ('OAuthAuthorizationNotFound' as ApiHttpError)) {
			loadingDeleteAuthorization[id] = false;
			invalidateAll();
		} else if (res.error) {
			loadingDeleteAuthorization[id] = false;
			console.error(res.error);
			invalidateAll();
		}

		if (res.response.ok) {
			loadingDeleteAuthorization[id] = false;
			invalidateAll();
		}
	}
</script>

<div class="section">
	<div class="title">
		<h2>Authorized Apps</h2>
	</div>

	{#await data.authorizations}
		<div style="margin-inline: auto;">
			<Spinner />
		</div>
	{:then authorizations}
		{#if authorizations?.length === 0}
			<div style="margin-inline: auto;">
				<p>You haven't authorized any apps yet.</p>
			</div>
		{/if}
		{#each authorizations?.sort((a, b) => new Date(b.last_used_at).getTime() - new Date(a.last_used_at).getTime()) ?? [] as authorization}
			<div class="authorization">
				<!-- I like how it looks :] since currently apps don't have icons because I don't have a place to store them -->
				<Hexagon />

				<div class="info">
					<span class="name">{authorization.name}</span>
					<span>Created by <strong>{authorization.created_by}</strong></span>
					<span>Last used on the {new Date(authorization.last_used_at).toLocaleString()}</span>

					<div class="section">
						<div class="title">
							<h2>Authorized Scopes ({authorization.scopes.length})</h2>
						</div>
						<ul>
							{#each scopesToLegible(authorization.scopes ?? []) ?? [] as scope}
								<li>{scope}</li>
							{/each}
						</ul>
					</div>
				</div>

				<div class="buttons">
					<Button
						class="desktop"
						bad
						onclick={() => deleteAuthorization(authorization.id)}
						disabled={loadingDeleteAuthorization[authorization.id]}
						loading={loadingDeleteAuthorization[authorization.id]}
					>
						{#snippet icon()}
							{#if loadingDeleteAuthorization[authorization.id]}
								<span transition:slide={{ axis: 'x' }}>
									<Spinner />
								</span>
							{:else}
								<X class="icon" size="20" />
							{/if}
						{/snippet}

						Revoke Access
					</Button>
					<Button
						bad
						onclick={() => deleteAuthorization(authorization.id)}
						disabled={loadingDeleteAuthorization[authorization.id]}
						loading={loadingDeleteAuthorization[authorization.id]}
						class="phone"
					>
						{#snippet icon()}
							{#if loadingDeleteAuthorization[authorization.id]}
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


	.authorization {
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
