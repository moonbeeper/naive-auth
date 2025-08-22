# Naive auth

Its a pretty simple authentication server that provides login via email and password and OTP with the added bonus of TOTP and email notifications that are totally finished. It also provides support for being an OAuth2 provider.

To run it you can use the docker composes to first spun up the required stuff (Redis, Postgres, Mailpit):

```sh
docker compose up -d
```

Then we generate the settings file:

```sh
cargo run -- -g
```

> The cookie session name isn't reflected in the swagger ui, so better not change it for now. (swagger was practically rushed as the general api was built on top of the normal axum router)

Then you can just run the server with:

```sh
cargo run
```

here should go a beautiful example of how would you log in via otp, but I think its self explanatory.
