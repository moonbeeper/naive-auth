pub mod models;

use std::net::SocketAddr;

use anyhow::Context as _;
use fred::{
    prelude::{ClientLike as _, Config, Pool, Server, ServerConfig},
    types::{Builder, RespVersion},
};

use crate::settings::RedisSettings;

pub struct RedisDatabase;

// lol
struct Socket(SocketAddr);

impl From<&SocketAddr> for Socket {
    fn from(value: &SocketAddr) -> Self {
        Self(*value)
    }
}

impl From<Socket> for Server {
    fn from(value: Socket) -> Self {
        Self::new(value.0.ip().to_string(), value.0.port())
    }
}

impl RedisDatabase {
    pub async fn new(settings: &RedisSettings) -> anyhow::Result<Pool> {
        tracing::info!("Connecting to Redis server");

        let redis_config = Config {
            server: ServerConfig::Centralized {
                server: Socket::from(&settings.server).into(),
            },
            database: settings.database,
            password: settings.password.clone(),
            username: settings.username.clone(),
            version: RespVersion::RESP3,

            ..Default::default()
        };

        let pool = Builder::from_config(redis_config)
            .build_pool(settings.max_connections)
            .context("Failed to create Redis pool")?;
        pool.init().await?;

        tracing::info!("Connected!");
        Ok(pool)
    }
}
