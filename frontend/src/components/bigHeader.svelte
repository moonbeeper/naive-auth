<script>
	import { get } from 'svelte/store';
	import Button from './button.svelte';
	import { currentText } from '$lib/bigHeader';

	let headerText = $state('Unknown');
	currentText.subscribe((text) => {
		headerText = text;
	});
	// let headerText = get(currentText);
</script>

<header>
	<h1>{headerText}</h1>
	<nav>
		<Button>button</Button>
	</nav>
</header>

<style lang="scss">
	header {
		display: flex;
		padding: 1rem 2rem;
		min-height: 80px;
		height: 80px;
		align-items: center;
		--title-spacing: 0em;
	}

	// 18 20 24       32 40 48
	// magic number land
	h1 {
		font-weight: 700;
		font-size: clamp(1.125rem, 0.9rem + 1.2vw, 2rem);
		letter-spacing: var(--title-spacing);
		white-space: nowrap;
		min-width: 0;
	}

	@media (min-width: 544px) {
		header {
			--title-spacing: -0.025em;
		}
		h1 {
			font-size: clamp(1.25rem, 1rem + 1.4vw, 2.5rem);
		}
	}

	@media (min-width: 768px) {
		header {
			--title-spacing: -0.05em;
		}
		h1 {
			font-size: clamp(1.5rem, 1.1rem + 1.8vw, 3rem);
		}
	}

	// @media (min-width: 544px) {
	// 	h1 {
	// 		font-size: 40px;
	// 	}
	// }

	// @media (min-width: 768px) {
	// 	h1 {
	// 		font-size: 48px;
	// 	}
	// }

	nav {
		width: 100%;
		display: flex;
		flex-direction: row;
		justify-content: end;
		align-items: center;
	}
</style>
