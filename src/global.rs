use crate::database::PostgresDB;

#[derive(Debug)]
pub struct GlobalState {
    pub database: sqlx::PgPool,
}

impl GlobalState {
    pub async fn new() -> anyhow::Result<Self> {
        let database = PostgresDB::new().await?;
        Ok(Self { database })
    }
}
