use sqlx::{PgExecutor, PgTransaction};

use crate::database::{DatabaseError, models::user::UserId, ulid::Ulid};

pub type SessionId = Ulid;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub name: String,
    pub active_expires_at: chrono::DateTime<chrono::Utc>,
    pub inactive_expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> anyhow::Result<()> {
        sqlx::query!(
            "
            insert into
                sessions (id, user_id, name, active_expires_at, inactive_expires_at, updated_at, created_at)
            values
                ($1, $2, $3, $4, $5, now(), now())
            ",
            self.id as SessionId,
            self.user_id as UserId,
            self.name,
            self.active_expires_at,
            self.inactive_expires_at
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }

    pub async fn get<'a, E>(id: SessionId, executor: E) -> DatabaseError<Option<Self>>
    where
        E: PgExecutor<'a>,
    {
        let user = sqlx::query_as!(
            Session,
            "select * from sessions where id = $1",
            id as SessionId
        )
        .fetch_optional(executor)
        .await?;
        Ok(user)
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
                    updated_at = now()
            where id = $5
            ",
            self.user_id as UserId,
            self.name,
            self.active_expires_at,
            self.inactive_expires_at,
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

    pub fn is_expired(&self) -> bool {
        self.inactive_expires_at <= chrono::Utc::now()
    }

    pub fn is_active(&self) -> bool {
        chrono::Utc::now() <= self.active_expires_at
    }
}
