use crate::database::{
    self,
    models::{session::SessionId, user::UserId},
};

#[derive(Debug, serde::Serialize)]
pub struct Session {
    pub id: SessionId,
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

#[derive(Debug, serde::Serialize)]
pub struct User {
    pub id: UserId,
    pub login: String,
    pub display_name: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub totp_enabled: bool,
}

impl From<database::models::user::User> for User {
    fn from(value: database::models::user::User) -> Self {
        Self {
            id: value.id,
            login: value.login,
            display_name: value.display_name,
            email: value.email,
            email_verified: value.email_verified,
            totp_enabled: value.totp_secret.is_some(),
        }
    }
}
