use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{Extension, Json, Router, extract::State, routing::post};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;

use crate::{
    auth::{self, middleware::AuthContext, ops::remove_session, ticket::AuthTicket},
    database::models::{
        session::{Session, SessionId},
        user::{User, UserId},
    },
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
}

#[derive(Debug, serde::Deserialize)]
struct LoginPassword {
    #[serde(rename = "login")]
    login_or_email: String,
    password: String,
}

async fn login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Json(request): Json<LoginPassword>,
) -> HttpResult<&'static str> {
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

    Ok("alright you are logged into the mainframe")
}

#[derive(Debug, serde::Deserialize)]
struct RegisterPassword {
    email: String,
    password: String,
}

async fn register(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Json(request): Json<RegisterPassword>,
) -> HttpResult<&'static str> {
    remove_session(session, &cookies, &global).await?; // force logout

    if User::get_by_email(&request.email, &global.database)
        .await?
        .is_some()
    {
        return Err(ApiError::UserAlreadyExists);
    }

    let login = request
        .email
        .split('@')
        .next()
        .unwrap_or(&request.email)
        .to_string();

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let password_hash = argon2
        .hash_password(request.password.as_bytes(), &salt)?
        .to_string();

    // todo: Create builders
    let user = User {
        id: UserId::new(),
        login,
        display_name: String::new(),
        email: Some(request.email.clone()),
        email_verified: false,
        password_hash: Some(password_hash),
        updated_at: chrono::Utc::now(),
        created_at: chrono::Utc::now(),
    };

    let session = Session {
        id: SessionId::new(),
        user_id: user.id,
        name: "temporary".to_string(),
        active_expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        inactive_expires_at: chrono::Utc::now() + chrono::Duration::days(30),
        updated_at: chrono::Utc::now(),
        created_at: chrono::Utc::now(),
    };

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

    Ok("alright you are now registered into the mainframe")
}
