<script>
	import { goto } from '$app/navigation';
	import Button from '$comps/button.svelte';
	import { currentText } from '$lib/bigHeader';

	currentText.set('Reset Password');
</script>

<main>
	<div class="title">
		<h1>Password updated!</h1>
		<p>Your password has been updated! <span>All your open sessions have been logged out.</span></p>
	</div>

	<div class="buttons">
		<Button big full_width primary onclick={() => goto('/')}>Log in again</Button>
	</div>
</main>

<style lang="scss">
	.title {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;

		p {
			font-size: 1rem;
			font-weight: 450;
			text-align: center;
		}

		h1 {
			font-size: 1.5rem;
			font-weight: 600;
			letter-spacing: var(--text-tight-spacing);
			text-align: center;
		}

		span {
			text-decoration: underline;
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

	.buttons {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		min-width: 300px;
		max-width: 300px;
	}
</style>
