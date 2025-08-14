use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng as _},
};
use tower_cookies::{Cookie, Cookies};

use crate::{
    auth::{middleware::AuthContext, ticket::AuthTicket},
    database::models::{session::Session, user::User},
    global::GlobalState,
    settings::Settings,
};

pub async fn remove_session(
    session: AuthContext,
    cookie_jar: &Cookies,
    global: &GlobalState,
) -> anyhow::Result<()> {
    match session {
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
