# BeepAuth

> [!NOTE]
> This is a work in progress. Practically everything besides the login and oauth flows are implemented on the frontend.
> Everything else has to be done via the API.

Its my try to make an authentication server that is possibly (un)secure. You can log in via password or via OTP and even have 2FA enabled on your account. It can also act as a OAuth 2 provider and has nice email notifications.

## Development

### Backend

To run it in development you'll need to first spin up the database, Redis and Mailpit. You can do this with docker compose:

> Mailpit is the email SMTP server that we'll be using in development. You can access it at `http://localhost:8025/`

```sh
docker compose up -d
```

That will download the docker images (if not already present) and spin up the services above.

The next step is to migrate our freshly spun up database. I like to use [cargo binstall](https://github.com/cargo-bins/cargo-binstall) to install the `sqlx-cli` tool without having to compile it from source, but you can always just do `cargo install sqlx-cli` if you prefer. The `sqlx-cli` tool is necessary to apply our migrations and add new ones! So let's install it with binstall:

```sh
cargo binstall sqlx-cli
```

Then we can apply our migrations with:

```sh
cargo sqlx database setup
```

Alrighty, the next step is to generate the `settings.toml` file for the server. Why? It provides a boilerplate configuration, making it a lil' easier to see and configure the server. While you can just use environment variables (prefixed with `BEEP_`) to configure the server instead, in my non important opinion, having a settings file is nicer haha.

With that said, let's generate our settings file with:

```sh
cargo run -- -g
```

And that's it! After optional tinkering with the settings file, you can just run the server with:

```sh
cargo run
```

Give it a *momento* to connect to the database, then Redis, and finally the email server, Mailpit (which is a bit slow to connect because it checks the connection first). Once all of that is done, the server will be reachable at `http://127.0.0.1:8080/` (if you didn't change it).

You can also explore the API schema at `http://127.0.0.1:8080/swagger-ui` if you like Swagger, or `http://127.0.0.1:8080/scalar` if you prefer Scalar (I prefer Scalar :] ).

> Make sure that the `api_explorer` setting is set to `true` in the `settings.toml` file or else it won't be available. (By default it's true)

### Frontend

This is an easy one. First, you might want to do a little bit of tinkering with the `.env` file if you changed the `frontend_url` setting in the backend's `settings.toml`. You can take a look at the `.env.example` for reference (it's pretty self explanatory).

Next, you might want to have something akin to [nvm](https://github.com/nvm-sh/nvm) installed to be able to use the correct version of node. To use the correct version of node just run `nvm use`.

Now we have to install the dependencies, because without them there would be no frontend. For this we'll use [pnpm](https://pnpm.io/):

```sh
pnpm install
```

Then run the frontend in development mode:

```sh
pnpm dev --host 127.0.0.1
```

> You might wonder, Why is the `--host 127.0.0.1` needed? Well, without it the frontend defaults to `localhost` which causes CORS
> issues (if you didn't change the `frontend_url` already) with the backend. Also, cookies wouldn't be saved because of
> the different origins (cookies use the Lax mode).

What happens when you modify the backend API? Well, now the frontend's client might be out of date. It's not a big deal, thanks to the backend's OpenAPI schema updating it is pretty easy, just run:

```sh
npx openapi-typescript http://127.0.0.1:8080/api-docs/openapi.json -o ./src/lib/api/v1.d.ts
```

Make sure to replace `http://127.0.0.1:8080` with the backend URL if you changed it. This will regenerate the client types (that means that the client is now updated!).

## Deployment

This whole thing, as said on the top, is in development. That means it's is **probably not really secure for production use**... Anyways, here's how you can deploy it.

But first, I have to warn you that the server has been probably only tested on top of [Nest](https://hackclub.app/) (which is cool!!!). That's why there's a package called `beepauth-server` and a file called `docker-compose.notprod.nest.yaml`, which is primarily for Nest and secondarily to serve prebuilt docker images and a docker compose file.

BTW, the frontend is purely static, so you can just deploy it wherever you want. Like for example in Github Pages (idk). To build it, it's as easy as running: `pnpm build`. To build the server, you'll need to do a little bit of preparation first:

1. Make sure you have our docker compose stack running ([see above](#development))
2. Make sure that you have the `sqlx-cli` installed ([see also above](#development))
3. Make sure that you have ran the migrations ([see also above](#development))
4. Make sure that you have generated the **sqlx cache** with `cargo sqlx prepare` if you modified the database schema

With all of that done, you can build the server with:

```sh
SQLX_OFFLINE=true cargo build --profile dist
```

> Why the use of `SQLX_OFFLINE=true`? Well, this allows us to build the server even if the database is not available,
> thanks to having a query metadata cache saved on the .sqlx folder. If you did modify the database schema, make sure to
> upload it to the repo!! Also, it isn't really needed for testing in development, but it's a nice thing to have.

And that's it! The typical Rust build output will be in `target/dist/beepauth`.

## License

HEY! This project is licensed! For details on the license for each part of the project, check their respective `LICENSE` file. (nasty license)
