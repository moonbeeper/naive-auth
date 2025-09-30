<script lang="ts">
	import { currentText } from '$lib/bigHeader';
	import { PanelRight } from '@lucide/svelte';
	import Button from './button.svelte';

	let headerText = $derived($currentText); // i get it (not really)
</script>

<header>
	<!-- <Button>
		{#snippet icon()}
			<PanelRight size="20" />
		{/snippet}
	</Button>
	<span class="separator"></span> -->
	<h1>{headerText}</h1>
</header>

<style lang="scss">
	header {
		display: flex;
		padding: 1rem 2rem;
		min-height: 80px;
		height: 80px;
		align-items: center;
		z-index: 50;
		--title-spacing: 0em;
		gap: 1rem;
	}

	.separator {
		background-color: var(--bg-notdark); // looks better lol
		width: 1px;
		height: 80%;
	}

	h1 {
		flex: 1 0 auto; // woops, seems this makes it have the correct bounding box in the devtools
		font-weight: 700;
		font-size: 24px;
		letter-spacing: var(--title-spacing);
		white-space: nowrap;
		min-width: 0;
	}

	@media (min-width: 640px) {
		header {
			--title-spacing: var(--text-almost-tight-spacing);
		}
		h1 {
			font-size: 32px;
		}
	}

	@media (min-width: 768px) {
		header {
			--title-spacing: var(--text-almost-tight-spacing);
		}
		h1 {
			font-size: 40px;
		}
	}

	@media (min-width: 1024px) {
		header {
			--title-spacing: var(--text-tight-spacing);
		}
		h1 {
			font-size: 48px;
		}
	}

	// nav {
	// 	width: 100%;
	// 	display: flex;
	// 	flex-direction: row;
	// 	justify-content: end;
	// 	align-items: center;
	// }
</style>
