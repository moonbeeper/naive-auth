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
    #[builder(default, setter(strip_option))]
    pub totp_secret: Option<String>,
    #[builder(default, setter(strip_option))]
    pub totp_recovery_secret: Option<String>,
    #[builder(default)]
    pub totp_recovery_codes: i32,
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
                users (
                    id,
                    login,
                    display_name,
                    email,
                    email_verified,
                    password_hash,
                    totp_secret,
                    totp_recovery_secret,
                    totp_recovery_codes,
                    updated_at,
                    created_at
                )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now())
            ",
            self.id as UserId,
            self.login,
            self.display_name,
            self.email,
            self.email_verified,
            self.password_hash.as_ref(),
            self.totp_secret.as_ref(),
            self.totp_recovery_secret.as_ref(),
            self.totp_recovery_codes
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn update(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            update users
                set
                    display_name = $1,
                    email = $2,
                    password_hash = $3,
                    totp_secret = $4,
                    totp_recovery_secret = $5,
                    totp_recovery_codes = $6,
                    updated_at = now()
            where id = $7
            ",
            self.display_name.as_ref(),
            self.email,
            self.password_hash.as_ref(),
            self.totp_secret.as_ref(),
            self.totp_recovery_secret.as_ref(),
            self.totp_recovery_codes,
            self.id as UserId,
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

    pub async fn get_by_email_or_login<'a, E>(
        email: &str,
        login: &str,
        executor: E,
    ) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a> + Copy,
    {
        let email = Self::get_by_email(email, executor).await?;
        let login = Self::get_by_login(login, executor).await?;

        if email.is_some() {
            return Ok(email);
        } else if login.is_some() {
            return Ok(login);
        }

        Ok(None)
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

    pub const fn is_recovery_code_used(&self, n: usize) -> bool {
        ((1 << n) & self.totp_recovery_codes) != 0
    }

    pub const fn mark_recovery_code_used(&mut self, n: usize) {
        self.totp_recovery_codes |= 1 << n;
    }

    pub const fn remaining_recovery_codes(&self) -> u32 {
        16 - self.totp_recovery_codes.count_ones()
    }
}
