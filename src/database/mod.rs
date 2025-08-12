use sqlx::PgPool;

pub mod models;
pub mod ulid;

type DatabaseError<T> = Result<T, sqlx::Error>;

pub struct PostgresDB;

impl PostgresDB {
    pub async fn new() -> Result<PgPool, sqlx::Error> {
        let pool = PgPool::connect("postgres://beep:beep@localhost:5432/beep_auth").await?;
        Ok(pool)
    }
}
