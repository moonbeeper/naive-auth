<script>
	import { currentText } from '$lib/bigHeader';
	import { fade, fly, slide } from 'svelte/transition';
	import Button from '../../components/button.svelte';
	import Input from '../../components/input.svelte';

	currentText.set('Sign up');
</script>

<main>
	<h1>Create a new account</h1>
	<div class="container">
		<!-- <div class="test">
			<label for="">Email address</label>
			<input type="text" name="lmao" placeholder="beep@example.com" />
		</div> -->
		<Input label="Username" name="email" type="text" placeholder="beep@example.com" big />
		<Input label="Email address" name="email" type="text" placeholder="beep@example.com" big />
		<!-- thanks cal com -->
		<Input label="Password" name="password" type="password" placeholder="•••••••••••••" big />

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
		// margin-top: 2rem;
		// border: 2px solid rgba(234, 234, 234, 0.05);
		// padding: 2rem;
		// border-radius: 1rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
		align-items: center;
		min-width: 300px;
		max-width: 300px;
		transition: all 0.2s ease-out;
	}

	// a {
	// 	grid-column: span 1;
	// 	background-color: #0a0a0a;
	// 	border-radius: 0.5rem 0.5rem 0 0;
	// 	justify-content: center;
	// 	flex-direction: column;
	// 	display: flex;
	// 	font-size: 1.125rem; // seems clearer at 18px than 16px
	// 	font-weight: 600;
	// 	color: #ffd670;
	// 	cursor: pointer;
	// }

	h1 {
		font-size: 1.625rem;
		font-weight: 600;
		margin-left: auto;
		margin-right: auto;
		letter-spacing: -0.05em;
	}

	input {
		height: 40px; // 32px, 36px, 40px
		width: 300px;
	}
	.test {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		font-weight: 500;
		font-size: 14px;
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
