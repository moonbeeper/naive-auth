use std::sync::Arc;

use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng as _},
};
use tower_cookies::{Cookie, Cookies};
use utoipa::ToSchema;

use crate::{
    auth::{self, middleware::AuthContext, oauth::middleware::OauthContext, ticket::AuthTicket},
    database::{
        models::{
            session::Session,
            user::{User, UserId},
        },
        redis::models::{
            FlowId, RedisError,
            auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
        },
    },
    global::GlobalState,
    http::error::ApiError,
    settings::Settings,
};

pub async fn remove_session(
    auth_context: AuthContext,
    cookie_jar: &Cookies,
    global: &Arc<GlobalState>,
) -> anyhow::Result<()> {
    match auth_context {
        AuthContext::Authenticated { session_id, .. } => {
            let mut tx = global.database.begin().await?;
            Session::delete(session_id, &mut tx).await?;
            tx.commit().await?;

            let cookie_name = global.settings.session.cookie_name.clone();
            cookie_jar.remove(cookie_name.into());

            Ok(())
        }
        AuthContext::NotAuthenticated => Ok(()),
    }
}

pub fn totp_secret() -> totp_rs::Secret {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut secret: [u8; 20] = Default::default();
    rng.fill_bytes(&mut secret[..]);
    totp_rs::Secret::Raw(secret.to_vec())
}

pub fn get_totp_client(secret: &totp_rs::Secret) -> totp_rs::TOTP {
    totp_rs::TOTP {
        algorithm: totp_rs::Algorithm::SHA1,
        digits: 6,
        skew: 1,
        step: 30,
        secret: secret.to_bytes().unwrap(),
    }
}

// simple thing to hold the built session and cookie. less boilerplate lol
pub struct CreateSession {
    pub session: Session,
    pub cookie: Cookie<'static>,
}

pub fn create_session(
    name: String,
    user: &User,
    settings: &Settings,
) -> anyhow::Result<CreateSession> {
    let session = Session::builder()
        .user_id(user.id)
        .name(name)
        .active_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(settings.session.active_age),
        )
        .inactive_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(settings.session.inactive_age),
        )
        .created_at(chrono::Utc::now())
        .updated_at(chrono::Utc::now())
        .build();

    let ticket = AuthTicket::from(&session).generate(settings)?;
    let cookie = build_cookie(
        settings.session.cookie_name.clone(),
        settings.session.inactive_age,
        settings.http.domain.clone(),
        ticket,
    );

    Ok(CreateSession { session, cookie })
}

pub fn build_cookie(
    cookie_name: String,
    max_age: i64,
    domain: String,
    data: String,
) -> Cookie<'static> {
    Cookie::build((cookie_name, data))
        .path("/")
        .http_only(true)
        .domain(domain)
        .max_age(tower_cookies::cookie::time::Duration::seconds(max_age))
        .into()
}

// todo: hack. Its a copy of the HttpError with the added link_id
// should this even be imported by the routes? i mean like there's no other way to return it otherwise
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct TotpResponse<'a> {
    pub error: &'a str,
    pub message: String,
    pub link_id: FlowId,
}

pub async fn create_totp_exchange(
    user: &User,
    redis: &fred::clients::Pool,
) -> Result<TotpResponse<'static>, RedisError> {
    let flow_id = FlowId::new();
    AuthFlow::TotpExchange {
        user_id: user.id,
        secret: user.totp_secret.clone().unwrap(),
    }
    .store(
        AuthFlowNamespace::TotpExchange,
        AuthFlowKey::FlowId(flow_id),
        redis,
    )
    .await?;

    Ok(TotpResponse {
        error: ApiError::TotpIsRequired.into(),
        message: ApiError::TotpIsRequired.to_string(),
        link_id: flow_id,
    })
}

// this would give something like "1beef-birb1"
fn generate_totp_recovery_code(secret: &str, n: usize) -> String {
    let hash = format!("{secret}:{n}");

    blake3::hash(hash.as_bytes())
        .to_hex()
        .chars()
        .take(10)
        .collect()
}

pub fn get_totp_recovery_codes(secret: &str) -> Vec<String> {
    (0..16)
        .map(|n| generate_totp_recovery_code(secret, n))
        .map(|code| {
            format!(
                "{}-{}",
                code.chars().take(5).collect::<String>().to_uppercase(),
                code.chars().skip(5).collect::<String>().to_uppercase()
            )
        })
        .collect()
}

pub const fn get_user_id(auth_context: &AuthContext, oauth_context: &OauthContext) -> UserId {
    if oauth_context.is_some() {
        oauth_context.user_id()
    } else {
        auth_context.user_id()
    }
}
