use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Extension, Json, Router,
    extract::State,
    routing::{get, post},
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tower_cookies::Cookies;

use crate::{
    auth::{self, middleware::AuthContext, ticket::AuthTicket},
    database::models::{
        session::{Session, SessionId},
        user::{User, UserId},
    },
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/test", get(test))
}

async fn index() -> &'static str {
    "Hello, World!"
}

#[derive(Debug, serde::Deserialize)]
struct LoginPassword {
    #[serde(rename = "login")]
    login_or_email: String,
    password: String,
}

async fn login(
    State(global): State<Arc<GlobalState>>,
    Json(request): Json<LoginPassword>,
) -> HttpResult<&'static str> {
    let user =
        if let Some(user) = User::get_by_login(&request.login_or_email, &global.database).await? {
            user
        } else {
            let user = User::get_by_email(&request.login_or_email, &global.database).await?;
            if user.is_none() {
                return Err(ApiError::InvalidUser);
            }
            user.unwrap()
        };

    if user.password_hash.is_none() {
        unimplemented!()
    }

    let argon2 = Argon2::default();
    argon2
        .verify_password(
            request.password.as_bytes(),
            &PasswordHash::new(user.password_hash.as_ref().unwrap())?,
        )
        .map_err(|_| ApiError::InvalidUser)?;

    Ok("alright you are logged into the mainframe")
}

#[derive(Debug, serde::Deserialize)]
struct RegisterPassword {
    email: String,
    password: String,
}

async fn register(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Json(request): Json<RegisterPassword>,
) -> HttpResult<&'static str> {
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
        .hash_password(&request.password.as_bytes(), &salt)?
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
    let cookie = auth::build_cookie(ticket);
    cookies.add(cookie);

    Ok("alright you are now registered into the mainframe")
}

async fn test(
    State(_global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> String {
    match auth_context {
        AuthContext::Authenticated {
            user_id,
            session_id,
        } => {
            format!("user_id: {user_id}, session_id: {session_id}")
        }
        AuthContext::NotAuthenticated => "not authenticated".to_string(),
    }
}
