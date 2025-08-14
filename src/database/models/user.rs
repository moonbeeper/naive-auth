use sqlx::{PgExecutor, PgTransaction};
use typed_builder::TypedBuilder;

use crate::database::{DatabaseError, ulid::Ulid};

pub type UserId = Ulid;

#[derive(Debug, Clone, TypedBuilder)]
pub struct User {
    #[builder(default = UserId::new())]
    pub id: UserId,
    pub login: String,
    #[builder(default, setter(strip_option))]
    pub display_name: Option<String>,
    pub email: String,
    #[builder(default)]
    pub email_verified: bool,
    #[builder(default, setter(strip_option))]
    pub password_hash: Option<String>,
    #[builder(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
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

    pub async fn get_login_by_email<'a, E>(email: &str, executor: E) -> DatabaseError<String>
    where
        E: PgExecutor<'a> + Copy,
    {
        let prefix = email.split('@').next().unwrap_or("user");
        let parsed = any_ascii::any_ascii(prefix);

        let mut login = parsed.clone();
        let mut counter = 0;
        while Self::get_by_email(email, executor).await?.is_some() {
            counter += 1;
            login = format!("{parsed}_{counter}");
        }

        Ok(login)
    }
}
