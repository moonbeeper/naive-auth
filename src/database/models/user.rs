use sqlx::{PgExecutor, PgTransaction};

use crate::database::{DatabaseError, ulid::Ulid};

pub type UserId = Ulid;

pub struct User {
    pub id: UserId,
    pub login: String,
    pub display_name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub password_hash: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl User {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            insert into
                users (id, login, display_name, email, email_verified, password_hash)
            values
                ($1, $2, $3, $4, $5, $6)
            ",
            self.id as UserId,
            self.login,
            self.display_name,
            self.email,
            self.email_verified,
            self.password_hash.as_ref().map(String::as_str),
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn get_by_login<'a, E>(login: &str, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(User, "select * from users where login = $1", login)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn get_by_email<'a, E>(email: &str, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(User, "select * from users where email = $1", email)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn get<'a, E>(id: UserId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(User, "select * from users where id = $1", id as UserId)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }
}
