use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::State,
    routing::{get, post},
};
use axum_valid::Valid;
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    auth::{middleware::AuthContext, ops::remove_session},
    database::{
        models::{session::Session, user::User},
        redis::models::auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

mod otp;
mod password;
mod totp;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/", get(index))
        .merge(password::routes())
        .nest("/otp", otp::routes())
        .nest("/totp", totp::routes())
        .route("/current", get(current_session))
        .route("/sessions", get(list_sessions))
        .route("/verify", post(verify_email))
        .route("/recovery-options", get(get_recovery_options))
}

async fn index() -> &'static str {
    "Hello, World!"
}

async fn current_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<models::Session>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    Ok(Json(models::Session::from(session)))
}

async fn list_sessions(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<Vec<models::Session>>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let sessions = Session::list_user_sessions(auth_context.user_id(), &global.database).await?;

    if sessions.is_empty() {
        return Ok(Json(vec![]));
    }

    let sessions: Vec<models::Session> = sessions.into_iter().map(models::Session::from).collect();

    Ok(Json(sessions))
}

#[derive(Debug, serde::Deserialize, Validate)]
struct VerifyEmail {
    #[validate(email)]
    email: String,
    #[validate(length(equal = 6))]
    code: String,
}

async fn verify_email(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Json(request)): Valid<Json<VerifyEmail>>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if user.email_verified {
        return Err(ApiError::EmailIsAlreadyVerified);
    }

    let flow = AuthFlow::get(
        AuthFlowNamespace::VerifyEmail,
        AuthFlowKey::UserId(user.id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::VerifyEmail { code }) = flow {
        if code != request.code {
            return Err(ApiError::InvalidEmailVerification);
        }
        let mut tx = global.database.begin().await?;
        let mut mut_user = user.clone();
        mut_user.email_verified = true;

        mut_user.update(&mut tx).await?;
        tx.commit().await?;

        let mail = AuthEmails::EmailVerified { login: user.login };
        global.mailer.send(&user.email, mail).await?;
        return Ok(());
    }
    Err(ApiError::InvalidEmailVerification)
}

#[derive(Debug, serde::Serialize)]

struct RecoveryOptions {
    otp: bool,
    totp: bool,
}

async fn get_recovery_options(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<RecoveryOptions>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let options = RecoveryOptions {
        otp: true,
        totp: user.totp_secret.is_some(),
    };

    Ok(Json(options))
}
