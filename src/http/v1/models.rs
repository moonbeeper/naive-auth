use crate::{
    auth::oauth::scopes::OauthScope,
    database::{
        self,
        models::{
            oauth::{OauthAppId, OauthAuthorizedId},
            session::SessionId,
            user::UserId,
        },
    },
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    pub totp_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<database::models::user::User> for User {
    fn from(value: database::models::user::User) -> Self {
        Self {
            id: value.id,
            login: value.login,
            display_name: value.display_name,
            email: Some(value.email),
            email_verified: value.email_verified,
            totp_enabled: value.totp_secret.is_some(),
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl User {
    pub fn remove_user(self, yes: bool) -> Self {
        let mut user = self;
        if yes {
            user.email = None;
        }
        user
    }
}

#[derive(Debug, serde::Serialize)]
pub struct OauthApp {
    id: OauthAppId,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    scopes: Vec<String>,
    callback_url: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<database::models::oauth::OauthApp> for OauthApp {
    fn from(value: database::models::oauth::OauthApp) -> Self {
        Self {
            id: value.id,
            name: value.name,
            description: value.description,
            scopes: OauthScope::from(value.scopes)
                .to_string()
                .split(',')
                .map(String::from)
                .collect(),
            callback_url: value.callback_url,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct OauthAuthorized {
    pub id: OauthAuthorizedId,
    pub app: OauthAppId,
    pub user_id: UserId,
    pub scopes: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<database::models::oauth::OauthAuthorized> for OauthAuthorized {
    fn from(value: database::models::oauth::OauthAuthorized) -> Self {
        Self {
            id: value.id,
            app: value.app,
            user_id: value.user_id,
            scopes: OauthScope::from(value.scopes)
                .to_string()
                .split(',')
                .map(String::from)
                .collect(),
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}
