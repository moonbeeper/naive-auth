use std::sync::Arc;

use anyhow::anyhow;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    database::models::{
        session::{Session, SessionId},
        user::UserId,
    },
    global::GlobalState,
};

#[derive(Debug)]
pub struct AuthTicket {
    pub user_id: UserId, // subject
    pub expiration: chrono::DateTime<chrono::Utc>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub session_id: SessionId, // token id
}

impl From<&Session> for AuthTicket {
    fn from(session: &Session) -> Self {
        let now = chrono::Utc::now();
        Self {
            user_id: session.user_id,
            expiration: session.inactive_expires_at,
            issued_at: now,
            session_id: session.id,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    jti: String,
    exp: i64,
    iat: i64,
    iss: String,
    nbf: i64,
    sub: String,
}

impl AuthTicket {
    pub fn generate(&self, global: &Arc<GlobalState>) -> anyhow::Result<String> {
        let claims = Claims {
            sub: self.user_id.to_string(),
            iat: self.issued_at.timestamp(),
            nbf: self.issued_at.timestamp(),
            exp: self.expiration.timestamp(),
            iss: global
                .settings
                .session
                .jwt
                .issuer
                .clone()
                .unwrap_or_else(|| global.settings.http.origin.clone()),
            jti: self.session_id.to_string(),
        };

        let key = EncodingKey::from_secret(global.settings.session.jwt.secret.as_bytes());
        Ok(encode(&Header::new(Algorithm::HS256), &claims, &key)?)
    }

    pub fn validate(token: &str, global: &Arc<GlobalState>) -> anyhow::Result<Self> {
        let decoding_key = DecodingKey::from_secret(global.settings.session.jwt.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[global
            .settings
            .session
            .jwt
            .issuer
            .clone()
            .unwrap_or_else(|| global.settings.http.origin.clone())]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        let user_id = claims.sub.parse()?;

        let session_id = claims.jti.parse()?;

        Ok(Self {
            user_id,
            session_id,
            issued_at: chrono::DateTime::from_timestamp(claims.iat, 0)
                .ok_or_else(|| anyhow!("Invalid issued at timestamp"))?,
            expiration: chrono::DateTime::from_timestamp(claims.exp, 0)
                .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?,
        })
    }
}
