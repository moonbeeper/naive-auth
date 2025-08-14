use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{Extension, Json, Router, extract::State, routing::post};
use axum_valid::Valid;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{create_session, remove_session},
    },
    database::models::user::User,
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
    Valid(Json(request)): Valid<Json<LoginPassword>>,
) -> HttpResult<Json<models::auth::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let login = any_ascii::any_ascii(&request.login_or_email);

    let user = if let Some(user) = User::get_by_login(&login, &global.database).await? {
        user
    } else if let Some(user) = User::get_by_email(&request.login_or_email, &global.database).await?
    {
        user
    } else {
        return Err(ApiError::InvalidLogin);
    };

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

    let sess = create_session("temporary".into(), &user, &global.settings)?;

    let mut tx = global.database.begin().await?;
    sess.session.insert(&mut tx).await?;
    tx.commit().await?;

    cookies.add(sess.cookie);
    global
        .mailer
        .send(&user.email, AuthEmails::NewLogin { login })
        .await?;

    Ok(Json(models::auth::Session::from(sess.session)))
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

    let login = any_ascii::any_ascii(&request.login);

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let password_hash = argon2
        .hash_password(request.password.as_bytes(), &salt)?
        .to_string();

    let user = User::builder()
        .login(login)
        .email(request.email.clone())
        .email_verified(false)
        .password_hash(password_hash)
        .build();

    let sess = create_session("temporary".into(), &user, &global.settings)?;

    let mut tx = global.database.begin().await?;
    user.insert(&mut tx).await?;
    sess.session.insert(&mut tx).await?;
    tx.commit().await?;

    cookies.add(sess.cookie);
    Ok(Json(models::auth::Session::from(sess.session)))
}
