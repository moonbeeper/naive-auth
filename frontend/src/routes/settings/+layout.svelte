<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import Button from '$comps/button.svelte';
	import Spinner from '$comps/spinner.svelte';
	import client from '$lib/api/baseFetch';
	import { user } from '$lib/auth';
	import { currentText } from '$lib/bigHeader';
	import { Blocks, LogOut, PlugZap, Shield, UserRound } from '@lucide/svelte';

	currentText.set('Settings');

	let { children } = $props();
	const pathname = $derived(page.url.pathname);

	const navItems = [
		{ href: '/settings', text: 'Authentication', icon: Shield },
		{ href: '/settings/oauth', text: 'Authorized Apps', icon: PlugZap },
		{ href: '/settings/developers', text: 'Your Apps', icon: Blocks }
	];

	async function signout() {
		try {
			await client.POST('/v1/auth/signout');
		} catch {}
		user.set(null); // clear it even if it fails lol
		await goto('/');
	}
</script>

<main>
	{#if !$user}
		<div class="wowie">
			<Spinner />
		</div>
	{:else}
		<div class="layout">
			<nav>
				<div class="user-info">
					<UserRound class="icon" />
					<div class="me">
						<span>Signed in as</span>
						<strong>{$user?.login}</strong>
					</div>
				</div>
				<div class="buttons">
					{#each navItems as item}
						<Button big full_width text_left ghost={!(pathname == item.href)} href={item.href}>
							{#snippet icon()}
								<item.icon size="16" class="icon" />
							{/snippet}
							{item.text}
						</Button>
					{/each}
				</div>
				<Button big bad full_width text_left onclick={signout}>
					{#snippet icon()}
						<LogOut size="16" class="icon" />
					{/snippet}
					Sign out
				</Button>
			</nav>
			<div class="content">
				{@render children?.()}
			</div>
		</div>
	{/if}
</main>

<style lang="scss">
	main {
		display: flex;
		flex-direction: column;
		flex: 1;
		max-width: 1280px;
		margin: 0 auto;
		padding: 0 8px;
	}

	.layout {
		--sidebar-width: 250px;
		display: grid;
		align-items: center;
		grid-template-columns: var(--sidebar-width) 1fr;
		margin-top: 16px;
		gap: 24px;
	}

	@media (max-width: 768px) {
		.layout {
			grid-template-columns: 1fr;
			grid-template-rows: auto 1fr;
		}

		nav {
			--sidebar-width: 100%;
		}
	}

	nav {
		display: flex;
		flex-direction: column;
		width: var(--sidebar-width);
		height: 100%;
		padding-bottom: 48px;
		gap: 1rem;

		.user-info {
			display: flex;
			gap: 1rem;
			padding: 8px 12px;
			border: 1px solid var(--bg-semidark);
			border-radius: 8px;
			align-items: center;

			.me {
				display: flex;
				flex-direction: column;
				overflow: hidden;
				gap: 0.25rem;

				span {
					font-size: 14px;
				}

				strong {
					white-space: nowrap;
					text-overflow: ellipsis;
					overflow: hidden;
				}
			}

			:global(.icon) {
				width: 24px;
				min-width: 24px;
				height: 24px;
				min-height: 24px;
				flex-shrink: 0;
			}
		}

		.buttons {
			display: flex;
			flex-direction: column;
			gap: 0.5rem;
		}
	}

	:global(.icon) {
		width: 16px;
		height: 16px;
		flex-shrink: 0;
	}

	.wowie {
		width: 100%;
		display: flex;
		justify-content: center;
	}
	.content {
		display: flex;
		flex-direction: column;
		height: 100%;
		width: 100%;
        padding-bottom: 1rem;
	}
</style>
