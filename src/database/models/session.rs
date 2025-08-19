use sqlx::{PgExecutor, PgTransaction};
use typed_builder::TypedBuilder;

use crate::database::{DatabaseError, models::user::UserId, ulid::Ulid};

const SUDO_EXPIRES: chrono::Duration = chrono::Duration::minutes(5);

pub type SessionId = Ulid;

#[derive(Debug, Clone, TypedBuilder)]
pub struct Session {
    #[builder(default = SessionId::new())]
    pub id: SessionId,
    pub user_id: UserId,
    pub name: String,
    pub active_expires_at: chrono::DateTime<chrono::Utc>,
    pub inactive_expires_at: chrono::DateTime<chrono::Utc>,
    pub os: String,
    pub browser: String,
    #[builder(default, setter(strip_option))]
    pub sudo_enabled_at: Option<chrono::DateTime<chrono::Utc>>,
    // omg the builder default messes somehow with the fields when fetching from the database, making it return the
    // default value instead of the actual value.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> anyhow::Result<()> {
        sqlx::query!(
            "
            insert into
                sessions (id, user_id, name, active_expires_at, inactive_expires_at, os, browser, updated_at, created_at)
            values
                ($1, $2, $3, $4, $5, $6, $7, now(), now())
            ",
            self.id as SessionId,
            self.user_id as UserId,
            self.name,
            self.active_expires_at,
            self.inactive_expires_at,
            self.os,
            self.browser,
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn get<'a, E>(id: SessionId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let session = sqlx::query_as!(
            Session,
            "select * from sessions where id = $1",
            id as SessionId
        )
        .fetch_optional(executor)
        .await?;
        Ok(session)
    }

    pub async fn update(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        sqlx::query!(
            "
            update sessions
                set
                    user_id = $1,
                    name = $2,
                    active_expires_at = $3,
                    inactive_expires_at = $4,
                    os = $5,
                    browser = $6,
                    sudo_enabled_at = $7,
                    updated_at = now()
            where id = $8
            ",
            self.user_id as UserId,
            self.name,
            self.active_expires_at,
            self.inactive_expires_at,
            self.os,
            self.browser,
            self.sudo_enabled_at.as_ref(),
            self.id as SessionId,
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    // always returns Ok even if the requested session does not exist
    pub async fn delete(id: SessionId, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        let session = Self::get(id, &mut **transaction).await?;
        if let Some(session) = session {
            sqlx::query!(
                "delete from sessions where id = $1",
                session.id as SessionId
            )
            .execute(&mut **transaction)
            .await?;
        }

        Ok(())
    }

    pub async fn list_user_sessions<'a, E>(id: UserId, executor: E) -> DatabaseError<Vec<Self>>
    where
        E: PgExecutor<'a>,
    {
        // why does the update and created at fields just return the default time!?
        let sessions = sqlx::query_as!(
            Session,
            "
            select
                id,
                user_id,
                name,
                active_expires_at,
                inactive_expires_at,
                os,
                browser,
                sudo_enabled_at,
                created_at,
                updated_at
            from sessions
            where user_id = $1
            order by created_at desc
            limit 100
            ",
            id as UserId
        )
        .fetch_all(executor)
        .await?;

        println!("sessions: {sessions:?}");

        Ok(sessions)
    }

    pub fn is_expired(&self) -> bool {
        self.inactive_expires_at <= chrono::Utc::now()
    }

    pub fn is_active(&self) -> bool {
        chrono::Utc::now() <= self.active_expires_at
    }

    pub async fn enable_sudo(&self, transaction: &mut PgTransaction<'_>) -> DatabaseError<()> {
        if self.is_sudo_enabled() {
            return Ok(());
        }

        let now = chrono::Utc::now();
        sqlx::query!(
            "update sessions set sudo_enabled_at = $1, updated_at = now() where id = $2",
            now,
            self.id as SessionId
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub fn is_sudo_enabled(&self) -> bool {
        let Some(sudo_enabled_at) = self.sudo_enabled_at else {
            return false;
        };

        let time = sudo_enabled_at + SUDO_EXPIRES;

        time > chrono::Utc::now()
    }

    pub async fn get_by_id_and_user<'a, E>(
        id: SessionId,
        user_id: UserId,
        executor: E,
    ) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let session = sqlx::query_as!(
            Session,
            "select * from sessions where id = $1 and user_id = $2",
            id as SessionId,
            user_id as UserId
        )
        .fetch_optional(executor)
        .await?;
        Ok(session)
    }
}
