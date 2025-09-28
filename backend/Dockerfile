
FROM debian:bookworm-slim
WORKDIR /app

# you must have built the binary before building this image.
# just run `cargo sqlx prepare` and then `cargo build --profile dist` (if on windows, use wsl)
RUN --mount=source=target/dist/beepauth,target=/mount/beepauth \
    cp /mount/beepauth /app/server && \
    apt update && \
    apt install -y ca-certificates dumb-init && \
    rm -rf /var/lib/apt/lists/*

# chmod +x /app/server

LABEL org.opencontainers.image.title="beepauth server"
LABEL org.opencontainers.image.description="BeepAuth server image"
LABEL org.opencontainers.image.source=https://github.com/moonbeeper/naive-auth
LABEL org.opencontainers.image.licenses=AGPL-3.0-only

# USER 1000 ; sadly it needs to be root to be able to log in into the public postgres instance of nest. or am doing
# something really really reallllly wrong here... i should probably ask for help but meh. it works for now

ENTRYPOINT [ "dumb-init", "--" ]
CMD [ "/app/server" ]