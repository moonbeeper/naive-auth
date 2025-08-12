use crate::{database::PostgresDB, email::EmailMan, settings};

#[derive(Debug)]
pub struct GlobalState {
    pub database: sqlx::PgPool,
    pub mailer: EmailMan,
    pub settings: settings::Settings,
}

impl GlobalState {
    pub async fn new(settings: settings::Settings) -> anyhow::Result<Self> {
        let database = PostgresDB::new(&settings.database).await?;
        let mailer = EmailMan::new(&settings.email).await;

        Ok(Self {
            database,
            mailer,
            settings,
        })
    }
}
