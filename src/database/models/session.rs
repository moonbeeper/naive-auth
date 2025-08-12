use sqlx::PgTransaction;

use crate::database::{models::user::UserId, ulid::Ulid};

type SessionId = Ulid;

pub struct Session {
    id: SessionId,
    user_id: UserId,
    name: String,
    active_expires: chrono::DateTime<chrono::Utc>,
    inactive_expires: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    pub async fn insert(&self, transaction: &mut PgTransaction<'_>) -> anyhow::Result<()> {
        sqlx::query!(
            "
            insert into
                sessions (id, user_id, name, active_expires_at, inactive_expires_at)
            values
                ($1, $2, $3, $4, $5)
            ",
            self.id as SessionId,
            self.user_id as UserId,
            self.name,
            self.active_expires,
            self.inactive_expires
        )
        .execute(&mut **transaction)
        .await?;

        Ok(())
    }
}
