use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::settings::DatabaseSettings;

pub mod models;
pub mod redis;
pub mod ulid;

type DatabaseError<T> = Result<T, sqlx::Error>;

pub struct PostgresDB;

impl PostgresDB {
    pub async fn new(settings: &DatabaseSettings) -> Result<PgPool, sqlx::Error> {
        tracing::info!("Connecting to the Postgres database...");
        let pool = PgPoolOptions::new()
            .min_connections(settings.min_connections)
            .max_connections(settings.max_connections)
            .connect(&settings.uri)
            .await?;

        tracing::info!("Connected!");
        Ok(pool)
    }
}
