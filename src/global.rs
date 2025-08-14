use crate::{
    database::{PostgresDB, redis::RedisDatabase},
    email::EmailMan,
    settings,
};

#[derive(Debug)]
pub struct GlobalState {
    pub database: sqlx::PgPool,
    pub redis: fred::clients::Pool,
    pub mailer: EmailMan,
    pub settings: settings::Settings,
}

impl GlobalState {
    pub async fn new(settings: settings::Settings) -> anyhow::Result<Self> {
        let database = PostgresDB::new(&settings.database).await?;
        let redis = RedisDatabase::new(&settings.redis).await?;
        let mailer = EmailMan::new(&settings.email).await;

        Ok(Self {
            database,
            redis,
            mailer,
            settings,
        })
    }
}
