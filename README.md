# Naive auth

Its my try to make an authentication server that is possibly (un)secure. You can log in via password or via OTP and even have 2FA enabled on your account. It can also act as a OAuth 2 provider and has nice email notifications.

To run it you need to use docker composes to first spun up the required stuff (Redis, Postgres, Mailpit):

> Mailpit is the email stmp server that I use in development. You can access it at `http://localhost:8025/`

```sh
docker compose up -d
```

Then we generate the settings file for the server:

```sh
cargo run -- -g
```

> The settings file isn't really required, but it's nice to have in development so you don't have to set environment vars with the prefix `BEEP_` with the setting you want to change every single time.

And finally you can just run the server or you can change the settings in the `settings.toml` file... this is the command to start the server:

```sh
cargo run
```

The server will be reachable at `http://127.0.0.1:8080/` by default.

The API explorer can be found at `http://127.0.0.1:8080/swagger-ui` if you like swagger OR `http://127.0.0.1:8080/scalar` if you prefer scalar.

> The `api_explorer` setting should be set to true in the settings file or else it won't be available. (By default it's true)
