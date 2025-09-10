<script>
	import { currentText } from '$lib/bigHeader';
	import Button from '../../components/button.svelte';
	import Input from '../../components/forms/input.svelte';
	import Spinner from '../../components/spinner.svelte';

	currentText.set('Sign up');
</script>

<main>
	<h1>Create a new account</h1>
	<div class="container">
		<!-- <div class="test">
			<label for="">Email address</label>
			<input type="text" name="lmao" placeholder="beep@example.com" />
		</div> -->
		<Input name="email" type="text" placeholder="beep@example.com" big />
		<Input name="email" type="text" placeholder="beep@example.com" big />
		<!-- thanks cal com -->
		<Input name="password" type="password" placeholder="•••••••••••••" big />

		<p>Already have an account? <a href="/">Log in</a></p>

		<Button big primary full_width>Sign up</Button>
	</div>
	<em></em>
	<div class="container">
		<Button big full_width>Continue with Github</Button>
		<Button big full_width>Continue with Google</Button>
	</div>
</main>

<style lang="scss">
	main {
		padding: 2.5rem 0;
		// min-height: calc(100svh - 2.5rem);
		display: flex;
		align-items: center;
		flex-direction: column;
		z-index: 1;
		gap: 1.75rem;
	}

	main a {
		font-size: 14px;
	}

	main p {
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
		transition: all 0.2s ease-out;
	}

	h1 {
		font-size: 1.625rem;
		font-weight: 600;
		margin-left: auto;
		margin-right: auto;
		letter-spacing: -0.05em;
	}

	button {
		background-color: #171717;
		padding-left: 0.75rem;
		width: 100%;
		font-size: 0.875rem;
		outline: 0;
		border: var(--bg-semidark) 0.1rem solid;
		color: var(--text);
		border-radius: 10px;
		font-family: inherit;
		transition: border-color 0.1s ease-out;
		width: 300px;
		height: 40px;
		font-size: 14px;
		font-weight: 500;
		cursor: pointer;
	}
	em {
		width: 300px;
		border: #222222 1px solid;
	}
</style>
