use anyhow::anyhow;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{
    database::models::{
        session::{Session, SessionId},
        user::UserId,
    },
    settings::Settings,
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
    jti: String, // id
    sub: String, // who
    iss: String, // me
    iat: i64,    // when
    nbf: i64,    // not before
    exp: i64,    // expire
}

impl AuthTicket {
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
        };

        let key = EncodingKey::from_secret(settings.session.jwt.secret.as_bytes());
        Ok(encode(&Header::new(Algorithm::HS256), &claims, &key)?)
    }

    pub fn validate(token: &str, settings: &Settings) -> anyhow::Result<Self> {
        let decoding_key = DecodingKey::from_secret(settings.session.jwt.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[settings
            .session
            .jwt
            .issuer
            .clone()
            .unwrap_or_else(|| settings.http.origin.clone())]);

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

// #[derive(Debug)] maybe not. url params might solve this better
// pub struct OtpTicket {
//     pub user_id: UserId,
//     pub flow_id: FlowId,
//     pub expiration: chrono::DateTime<chrono::Utc>,
//     pub issued_at: chrono::DateTime<chrono::Utc>,
// }

// impl OtpTicket {
//     pub fn new(user_id: UserId, flow_id: FlowId, expire_time: chrono::Duration) -> Self {
//         let now = chrono::Utc::now();

//         Self {
//             user_id,
//             flow_id,
//             expiration: now + expire_time,
//             issued_at: now,
//         }
//     }
//     pub fn generate(&self, settings: &Settings) -> anyhow::Result<String> {
//         let claims = Claims {
//             jti: self.flow_id.to_string(),
//             sub: self.user_id.to_string(),
//             iss: settings
//                 .session
//                 .jwt
//                 .issuer
//                 .clone()
//                 .unwrap_or_else(|| settings.http.origin.clone()),
//             iat: self.issued_at.timestamp(),
//             nbf: self.issued_at.timestamp(),
//             exp: self.expiration.timestamp(),
//         };

//         // todo: separate secret from the session one
//         let key = EncodingKey::from_secret(settings.session.jwt.secret.as_bytes());
//         Ok(encode(&Header::new(Algorithm::HS256), &claims, &key)?)
//     }

//     pub fn validate(token: &str, settings: &Settings) -> anyhow::Result<Self> {
//         let decoding_key = DecodingKey::from_secret(settings.session.jwt.secret.as_bytes());

//         let mut validation = Validation::new(Algorithm::HS256);
//         validation.set_issuer(&[settings
//             .session
//             .jwt
//             .issuer
//             .clone()
//             .unwrap_or_else(|| settings.http.origin.clone())]);

//         let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
//         let claims = token_data.claims;

//         let user_id = claims.sub.parse()?;
//         let flow_id = claims.jti.parse()?;

//         Ok(Self {
//             user_id,
//             flow_id,
//             issued_at: chrono::DateTime::from_timestamp(claims.iat, 0)
//                 .ok_or_else(|| anyhow!("Invalid issued at timestamp"))?,
//             expiration: chrono::DateTime::from_timestamp(claims.exp, 0)
//                 .ok_or_else(|| anyhow!("Invalid expiration timestamp"))?,
//         })
//     }
// }
