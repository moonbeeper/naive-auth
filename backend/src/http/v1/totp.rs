use std::sync::Arc;

use axum::{Extension, extract::State};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{get_totp_recovery_codes, remove_session},
    },
    database::models::{session::Session, user::User},
    email::resources::AuthEmails,
    global::GlobalState,
    http::{
        HttpResult, TOTP_TAG,
        error::{ApiError, ApiHttpError},
        validation::Json,
    },
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(get_totp_recovery))
        .routes(routes!(disable))
}

#[derive(Debug, serde::Serialize, ToSchema)]
struct TotpRecoveryResponse {
    recovery_codes: Vec<String>,
}

/// Get your TOTP recovery codes
///
/// This will return your TOTP recovery codes IF you have TOTP enabled
#[utoipa::path(
    get,
    path = "/recovery",
    responses(
        (status = 200, description = "TOTP Recovery codes", body = TotpRecoveryResponse),
        (status = 401, description = "Not authenticated or Sudo is not enabled", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
    ),
    tag = TOTP_TAG
)]
async fn get_totp_recovery(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<TotpRecoveryResponse>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if !session.is_sudo_enabled() {
        return Err(ApiError::SudoIsNotEnabled); // should be frontend's job to start the sudo flow
    }

    if user.totp_secret.is_none() {
        return Err(ApiError::TOTPIsNotEnabled);
    }

    let recovery_codes: Vec<String> =
        get_totp_recovery_codes(user.totp_recovery_secret.as_ref().unwrap());

    let mail = AuthEmails::TotpRecoveryViewed { login: user.login };
    global.mailer.send(&user.email, mail).await?;

    Ok(Json(TotpRecoveryResponse { recovery_codes }))
}

/// Disable TOTP from this account
///
/// This will disable TOTP from your account IF you have TOTP enabled
#[utoipa::path(
    delete,
    path = "/",
    responses(
        (status = 200, description = "TOTP disabled successfully"),
        (status = 401, description = "Not authenticated or Sudo is not enabled", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
    ),
    tag = TOTP_TAG
)]
async fn disable(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
    cookies: Cookies,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(mut user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if !session.is_sudo_enabled() {
        return Err(ApiError::SudoIsNotEnabled); // should be frontend's job to start the sudo flow
    }

    if user.totp_secret.is_none() {
        return Err(ApiError::TOTPIsNotEnabled);
    }

    user.totp_secret = None;
    user.totp_recovery_secret = None;
    user.totp_recovery_codes = 0;

    let mut tx = global.database.begin().await?;
    user.update(&mut tx).await?;
    tx.commit().await?;

    let mail = AuthEmails::TotpDisabled { login: user.login };
    global.mailer.send(&user.email, mail).await?;

    Ok(())
}
