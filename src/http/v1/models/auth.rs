use crate::database::{self, ulid::Ulid};

#[derive(Debug, serde::Serialize)]
pub struct Session {
    pub id: Ulid,
    pub name: String,
    pub active_expires_at: chrono::DateTime<chrono::Utc>,
    pub inactive_expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<database::models::session::Session> for Session {
    fn from(value: database::models::session::Session) -> Self {
        println!("value: {value:?}");
        Self {
            id: value.id,
            name: value.name,
            active_expires_at: value.active_expires_at,
            inactive_expires_at: value.inactive_expires_at,
            created_at: value.created_at,
        }
    }
}
