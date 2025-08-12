use std::{str::FromStr as _, sync::Arc};

use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{Extension, Json, Router, extract::State, routing::post};
use axum_valid::Valid;
use lettre::message::Mailbox;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    auth::{self, middleware::AuthContext, ops::remove_session, ticket::AuthTicket},
    database::models::{session::Session, user::User},
    email::resources::AuthEmails,
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
}

#[derive(Debug, serde::Deserialize, Validate)]
struct LoginPassword {
    #[serde(rename = "login")]
    login_or_email: String,
    #[validate(length(min = 9))]
    password: String,
}

async fn login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Json(request): Json<LoginPassword>,
) -> HttpResult<Json<models::auth::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout

    let user =
        if let Some(user) = User::get_by_login(&request.login_or_email, &global.database).await? {
            user
        } else {
            let user = User::get_by_email(&request.login_or_email, &global.database).await?;
            if user.is_none() {
                return Err(ApiError::InvalidLogin);
            }
            user.unwrap()
        };

    // todo: user email man to send the typical email alerts and verification before allowing login. (redis)
    global
        .mailer
        .send(
            Mailbox::from_str(&user.email.unwrap())?,
            AuthEmails::TestEmail,
        )
        .await?;

    if user.password_hash.is_none() {
        Err(ApiError::InvalidLogin)?;
    }

    let argon2 = Argon2::default();
    argon2
        .verify_password(
            request.password.as_bytes(),
            &PasswordHash::new(user.password_hash.as_ref().unwrap())?,
        )
        .map_err(|_| ApiError::InvalidLogin)?;

    let session = Session::builder()
        .user_id(user.id)
        .name("temporary".into())
        .active_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(global.settings.session.active_age),
        )
        .inactive_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(global.settings.session.inactive_age),
        )
        .build();

    let mut tx = global.database.begin().await?;
    session.insert(&mut tx).await?;
    tx.commit().await?;

    let ticket = AuthTicket::from(&session).generate(&global)?;
    let cookie = auth::build_cookie(
        global.settings.session.cookie_name.clone(),
        global.settings.session.inactive_age,
        global.settings.http.domain.clone(),
        ticket,
    );
    cookies.add(cookie);

    Ok(Json(models::auth::Session::from(session)))
}

#[derive(Debug, serde::Deserialize, Validate)]
struct RegisterPassword {
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    login: String,
    #[validate(length(min = 9))]
    password: String,
}

async fn register(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<RegisterPassword>>,
) -> HttpResult<Json<models::auth::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout

    if User::get_by_email(&request.email, &global.database)
        .await?
        .is_some()
    {
        return Err(ApiError::UserAlreadyExists);
    }

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let password_hash = argon2
        .hash_password(request.password.as_bytes(), &salt)?
        .to_string();

    let user = User::builder()
        .login(request.login.clone())
        .email(request.email.clone())
        .email_verified(false)
        .password_hash(password_hash)
        .build();

    let session = Session::builder()
        .user_id(user.id)
        .name("temporary".into())
        .active_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(global.settings.session.active_age),
        )
        .inactive_expires_at(
            chrono::Utc::now() + chrono::Duration::seconds(global.settings.session.inactive_age),
        )
        .build();

    let mut tx = global.database.begin().await?;
    user.insert(&mut tx).await?;
    session.insert(&mut tx).await?;
    tx.commit().await?;

    let ticket = AuthTicket::from(&session).generate(&global)?;
    let cookie = auth::build_cookie(
        global.settings.session.cookie_name.clone(),
        global.settings.session.inactive_age,
        global.settings.http.domain.clone(),
        ticket,
    );
    cookies.add(cookie);

    Ok(Json(models::auth::Session::from(session)))
}
