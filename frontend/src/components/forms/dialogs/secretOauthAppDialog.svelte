<script lang="ts">
	import Button from '$comps/button.svelte';
	import { ClipboardIcon, X } from '@lucide/svelte';
	import { Dialog } from 'bits-ui';
	import { fade, scale } from 'svelte/transition';
	import type { components } from '$lib/api/v1';
	import { copyText } from 'svelte-copy';
	import { invalidateAll } from '$app/navigation';

	// TODO: this should be separated into components.

	let {
		open = $bindable(),
		data
	}: { open: boolean; data: components['schemas']['CreateAppResponse'] } = $props();
</script>

<Dialog.Root
	bind:open
	onOpenChange={(e) => {
		if (!e) {
			invalidateAll();
		}
	}}
>
	<Dialog.Portal>
		<Dialog.Overlay class="dialog-overlay" forceMount>
			{#snippet child({ props, open })}
				{#if open}
					<div {...props} transition:fade={{ duration: 100 }}></div>
				{/if}
			{/snippet}
		</Dialog.Overlay>
		<Dialog.Content
			class="dialog-root-content"
			forceMount
			escapeKeydownBehavior="ignore"
			interactOutsideBehavior="ignore"
		>
			{#snippet child({ props, open })}
				{#if open}
					<div {...props} in:scale={{ duration: 200 }}>
						<div class="dialog-header">
							<Dialog.Title>App secrets</Dialog.Title>
							<Dialog.Close>
								{#snippet child({ props })}
									<Button primary {...props}>
										{#snippet icon()}
											<X size="20" />
										{/snippet}
									</Button>
								{/snippet}
							</Dialog.Close>
						</div>
						<div class="dialog-content">
							<p style="font-weight: 700; text-decoration: underline;">
								Save your app secret now!! It won't be shown again.
							</p>
							<div class="secret-container">
								<p>App ID:</p>
								<div class="secret">
									<span><strong>{data.id}</strong></span>
									<Button small onclick={() => copyText(data.id)}>
										{#snippet icon()}
											<ClipboardIcon size="20" />
										{/snippet}
									</Button>
								</div>
							</div>
							<div class="secret-container">
								<p>App Secret:</p>
								<div class="secret">
									<span><strong>{data.secret_key}</strong></span>
									<Button small onclick={() => copyText(data.secret_key)}>
										{#snippet icon()}
											<ClipboardIcon size="20" />
										{/snippet}
									</Button>
								</div>
							</div>
						</div>
					</div>
				{/if}
			{/snippet}
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>

<style lang="scss">
	:global(.dialog-overlay) {
		position: fixed;
		inset: 0;
		z-index: 968;
		background-color: rgba(0, 0, 0, 0.4);
		backdrop-filter: blur(2px);
	}

	:global(.dialog-root-content) {
		--dialog-padding: 1rem;
		z-index: 969;
		position: fixed;
		left: 50%;
		top: 50%;
		transform: translate(-50%, -50%);
		display: flex;
		flex-direction: column;
		width: 640px;
		border-radius: 16px;
		background-color: var(--bg-dark);
		border: 1px solid var(--bg-semidark);
		min-width: 300px;
		max-width: 90vw;
		max-height: 90vh;

		.dialog-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			padding: 8px;
			border-bottom: 1px solid var(--bg-semidark);

			:global([data-dialog-title]) {
				font-weight: 600;
				padding-left: 8px;
			}
		}

		.dialog-content {
			padding: var(--dialog-padding);
			display: flex;
			flex-direction: column;
			gap: 1rem;
			overflow: hidden;

			span {
				padding: 0.5rem;
				background-color: var(--bg-semidark);
				font-family: var(--font-mono);
				border-radius: 8px;
				white-space: nowrap;
				text-overflow: ellipsis;
				overflow: hidden;
			}

			.secret-container {
				display: flex;
				flex-direction: column;
				gap: 0.5rem;
			}

			.secret {
				display: flex;
				align-items: center;
				justify-content: space-between;
				gap: 0.5rem;
			}
		}
	}
</style>
