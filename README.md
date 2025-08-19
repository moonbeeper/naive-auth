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

## how to log in

Simply log in via OTP if you don't want to have the hassle of going through the whole process of registering via password and then verifying your email address to be able to login. Here's a quick example:

