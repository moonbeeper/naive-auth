use crate::{database::PostgresDB, settings};

#[derive(Debug)]
pub struct GlobalState {
    pub database: sqlx::PgPool,
    pub settings: settings::Settings,
}

impl GlobalState {
    pub async fn new(settings: settings::Settings) -> anyhow::Result<Self> {
        let database = PostgresDB::new(&settings.database).await?;

        Ok(Self { database, settings })
    }
}
