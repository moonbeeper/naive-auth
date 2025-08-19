use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{remove_session, totp_secret},
    },
    database::{
        models::{session::Session, user::User},
        redis::models::{
            FlowId,
            auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
        },
    },
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::auth::CurrentActiveOptions},
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(enable_sudo))
        .routes(routes!(get_sudo_options))
        .routes(routes!(get_sudo_status))
}

#[derive(Debug, serde::Deserialize, serde::Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SudoEnableOption {
    Otp,
    Totp,
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct SudoEnableRequest {
    option: SudoEnableOption,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct SudoEnableResponse {
    option: SudoEnableOption,
    link_id: FlowId,
}
/// Start the requested flow for enabling sudo for the current session
#[utoipa::path(
    post,
    path = "/",
    responses(
        (status = 200, description = "Sudo enabled", body = SudoEnableResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "sudo"
)]
async fn enable_sudo(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Json(request): Json<SudoEnableRequest>,
) -> HttpResult<Json<SudoEnableResponse>> {
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

    if session.is_sudo_enabled() {
        return Err(ApiError::SudoIsAlreadyEnabled);
    }

    if (request.option == SudoEnableOption::Otp && user.totp_secret.is_some())
        || (request.option == SudoEnableOption::Totp && user.totp_secret.is_none())
    {
        return Err(ApiError::SudoCannotBeEnabled);
    }

    match request.option {
        SudoEnableOption::Otp => {
            let flow_id = FlowId::new();
            let secret = totp_secret().to_encoded().to_string();

            AuthFlow::OtpExchange { secret }
                .store(
                    AuthFlowNamespace::OtpExchange,
                    AuthFlowKey::UserFlow {
                        flow_id,
                        user_id: user.id,
                    },
                    &global.redis,
                )
                .await?;

            Ok(Json(SudoEnableResponse {
                option: request.option,
                link_id: flow_id,
            }))
        }
        SudoEnableOption::Totp => {
            let flow_id = FlowId::new();
            let secret = totp_secret().to_encoded().to_string();

            AuthFlow::TotpExchange {
                user_id: user.id,
                secret,
            }
            .store(
                AuthFlowNamespace::OtpExchange,
                AuthFlowKey::UserFlow {
                    flow_id,
                    user_id: user.id,
                },
                &global.redis,
            )
            .await?;

            Ok(Json(SudoEnableResponse {
                option: request.option,
                link_id: flow_id,
            }))
        }
    }
}

/// Get the options for enabling sudo
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Sudo enable options", body = CurrentActiveOptions),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "sudo"
)]
async fn get_sudo_options(
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
        otp: user.totp_secret.is_none(),
        totp: user.totp_secret.is_some(),
    };

    Ok(Json(options))
}

#[derive(Debug, serde::Serialize, ToSchema)]
struct SudoStatus {
    // just to make it look cristal clear
    enabled: bool,
}

/// Get the current sudo status of the session
#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "Sudo status", body = SudoStatus),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "sudo"
)]
async fn get_sudo_status(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<SudoStatus>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    Ok(Json(SudoStatus {
        enabled: session.is_sudo_enabled(),
    }))
}
