use std::sync::OnceLock;

use anyhow::anyhow;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    database::{
        models::{
            session::{Session, SessionId},
            user::UserId,
        },
        redis::models::FlowId,
    },
    settings::Settings,
};

// Encoding and decoding keys can be initialized once an be reused
static SESSION_ENCODING_KEY: OnceLock<EncodingKey> = OnceLock::new();
static SESSION_DECODING_KEY: OnceLock<DecodingKey> = OnceLock::new();
static OAUTH_ENCODING_KEY: OnceLock<EncodingKey> = OnceLock::new();
static OAUTH_DECODING_KEY: OnceLock<DecodingKey> = OnceLock::new();

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    jti: String, // id
    sub: String, // who
    iss: String, // me
    iat: i64,    // when
    nbf: i64,    // not before
    exp: i64,    // expire
    typ: TicketType,
}

#[derive(Debug)]
pub struct SessionTicket {
    pub user_id: UserId,       // subject
    pub session_id: SessionId, // token id
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expiration: chrono::DateTime<chrono::Utc>,
}

impl From<&Session> for SessionTicket {
    fn from(session: &Session) -> Self {
        let now = chrono::Utc::now();
        Self {
            user_id: session.user_id,
            session_id: session.id,
            issued_at: now,
            expiration: session.inactive_expires_at,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum TicketType {
    Session,
    Oauth,
}

impl SessionTicket {
    pub fn generate(&self, settings: &Settings) -> anyhow::Result<String> {
        let claims = Claims {
            jti: self.session_id.to_string(),
            sub: self.user_id.to_string(),
            iss: settings
                .session
                .jwt
                .issuer
                .clone()
                .unwrap_or_else(|| settings.http.origin.clone()),
            iat: self.issued_at.timestamp(),
            nbf: self.issued_at.timestamp(),
            exp: self.expiration.timestamp(),
            typ: TicketType::Session,
        };

        let key = SESSION_ENCODING_KEY
            .get_or_init(|| EncodingKey::from_secret(settings.session.jwt.secret.as_bytes()));

        Ok(encode(&Header::new(Algorithm::HS256), &claims, key)?)
    }

    pub fn validate(token: &str, settings: &Settings) -> anyhow::Result<Self> {
        let decoding_key = SESSION_DECODING_KEY
            .get_or_init(|| DecodingKey::from_secret(settings.oauth.jwt.secret.as_bytes()));

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[settings
            .session
            .jwt
            .issuer
            .as_ref()
            .unwrap_or(&settings.http.origin)]);

        let token_data = decode::<Claims>(token, decoding_key, &validation)?;
        let claims = token_data.claims;

        if claims.typ != TicketType::Session {
            return Err(anyhow!("Gotten invalid token type for this ticket"));
        }

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

#[derive(Debug)]
pub struct OauthTicket {
    pub user_id: UserId,
    pub flow_id: FlowId,
    // pub scopes: OauthScope,
    pub expiration: chrono::DateTime<chrono::Utc>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

impl OauthTicket {
    pub fn new(user_id: UserId, flow_id: FlowId, expire_after: chrono::Duration) -> Self {
        let now = chrono::Utc::now();

        Self {
            user_id,
            flow_id,
            expiration: now + expire_after,
            issued_at: now,
        }
    }
    pub fn generate(&self, settings: &Settings) -> anyhow::Result<String> {
        let claims = Claims {
            jti: self.flow_id.to_string(),
            sub: self.user_id.to_string(),
            iss: settings
                .session
                .jwt
                .issuer
                .clone()
                .unwrap_or_else(|| settings.http.origin.clone()),
            iat: self.issued_at.timestamp(),
            nbf: self.issued_at.timestamp(),
            exp: self.expiration.timestamp(),
            typ: TicketType::Oauth,
        };

        let key = OAUTH_ENCODING_KEY
            .get_or_init(|| EncodingKey::from_secret(settings.oauth.jwt.secret.as_bytes()));
        Ok(encode(&Header::new(Algorithm::HS256), &claims, key)?)
    }

    pub fn validate(token: &str, settings: &Settings) -> anyhow::Result<Self> {
        let decoding_key = OAUTH_DECODING_KEY
            .get_or_init(|| DecodingKey::from_secret(settings.oauth.jwt.secret.as_bytes()));

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[settings
            .oauth
            .jwt
            .issuer
            .as_ref()
            .unwrap_or(&settings.http.origin)]);

        let token_data = decode::<Claims>(token, decoding_key, &validation)?;
        let claims = token_data.claims;

        if claims.typ != TicketType::Oauth {
            return Err(anyhow!("Gotten invalid token type for this ticket"));
        }

        let user_id = claims.sub.parse()?;
        let flow_id = claims.jti.parse()?;

        Ok(Self {
            user_id,
            flow_id,
            issued_at: chrono::DateTime::from_timestamp(claims.iat, 0)
                .ok_or_else(|| anyhow!("Invalid issued at timestamp"))?,
            expiration: chrono::DateTime::from_timestamp(claims.exp, 0)
                .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?,
        })
    }
}
