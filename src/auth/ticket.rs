use std::sync::Arc;

use anyhow::{anyhow, bail};
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
    exp: usize,
    iat: usize,
    iss: String,
    nbf: usize,
    sub: String,
}

impl AuthTicket {
    pub fn generate(&self, _global: &Arc<GlobalState>) -> anyhow::Result<String> {
        let claims = Claims {
            sub: self.user_id.to_string(),
            iat: self.issued_at.timestamp() as usize,
            nbf: self.issued_at.timestamp() as usize,
            exp: self.expiration.timestamp() as usize,
            iss: "hardcoded.localhost".to_string(),
            jti: self.session_id.to_string(),
        };

        let secret = "this is still hardcoded".as_bytes();
        let key = EncodingKey::from_secret(secret);
        Ok(encode(&Header::new(Algorithm::HS256), &claims, &key)?)
    }

    pub fn validate(token: &str, _global: &Arc<GlobalState>) -> anyhow::Result<Self> {
        let secret = "this is still hardcoded".as_bytes();
        let decoding_key = DecodingKey::from_secret(secret);

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["hardcoded.localhost"]);

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        let claims = token_data.claims;

        let user_id = claims.sub.parse()?;

        let session_id = claims.jti.parse()?;

        Ok(Self {
            user_id,
            session_id,
            issued_at: chrono::DateTime::from_timestamp(claims.iat as i64, 0)
                .ok_or(anyhow!("Invalid issued at timestamp"))?,
            expiration: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                .ok_or(anyhow!("Invalid expiration timestamp"))?,
        })
    }
}
