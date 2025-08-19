use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use axum_valid::Valid;
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{middleware::AuthContext, ops::remove_session},
    database::{
        models::user::User,
        redis::models::auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

pub mod oauth;
pub mod otp;
pub mod password;
pub mod totp;

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .merge(password::routes())
        .nest("/otp", otp::routes())
        .nest("/totp", totp::routes())
        .nest("/oauth", oauth::routes())
        .routes(routes!(verify_email))
        .routes(routes!(get_recovery_options))
        .routes(routes!(signout))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct VerifyEmail {
    #[validate(email)]
    email: String,
    #[validate(length(equal = 6))]
    code: String,
}

/// Verify the user's email to be able to login with email or user login and password
#[utoipa::path(
    post,
    path = "/verify",
    request_body = VerifyEmail,
    responses(
        (status = 200, description = "Email verified"),
        (status = 400, description = "Invalid code"),
        (status = 401, description = "Not authenticated")
    ),
    tag = "password"
)]
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

#[derive(Debug, serde::Serialize, ToSchema)]

pub struct CurrentActiveOptions {
    pub otp: bool,
    pub totp: bool,
}

/// Get the available recovery options for an user. (placeholder?)
#[utoipa::path(
    get,
    path = "/recovery-options",
    responses(
        (status = 200, description = "Recovery options", body = CurrentActiveOptions),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "auth"
)]
async fn get_recovery_options(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<CurrentActiveOptions>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let options = CurrentActiveOptions {
        otp: true,
        totp: user.totp_secret.is_some(),
    };

    Ok(Json(options))
}

/// Sign out of this current session
#[utoipa::path(
    post,
    path = "/signout",
    responses(
        (status = 200, description = "Signed out"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "auth"
)]
async fn signout(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    remove_session(auth_context, &cookies, &global).await?; // love this method
    Ok(())
}
