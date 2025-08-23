use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::HeaderMap};
use axum_valid::Valid;
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{
            DeviceMetadata, TOTP_CODE_REGEX, create_session, get_totp_client,
            get_totp_recovery_codes, remove_session, totp_secret,
        },
    },
    database::{
        models::{session::Session, user::User},
        redis::models::{
            FlowId,
            auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
        },
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::{
        HttpResult, TOTP_TAG,
        error::ApiError,
        v1::{models, string_trim},
    },
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(exchange_login))
        .routes(routes!(enable))
        .routes(routes!(enable_exchange))
        .routes(routes!(exchange))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct Exchange {
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(equal = 6))]
    code_or_recovery: String,
}

/// Exchange a Link ID to finalize a TOTP login request
#[utoipa::path(
    post,
    path = "/exchange-login",
    request_body = Exchange,
    responses(
        (status = 200, description = "Successful TOTP exchange", body = models::Session),
        (status = 401, description = "Not authenticated"),
        (status = 400, description = "Validation or parsing error"),
        (status = 422, description = "Missing required fields"),
        (status = 404, description = "The TOTP exchange flow was not found"),
    ),
    tag = TOTP_TAG
)]
async fn exchange_login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<Exchange>>,
) -> HttpResult<Json<models::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let flow_id = request.link_id;

    let flow = AuthFlow::get(
        AuthFlowNamespace::TotpLoginExchange,
        AuthFlowKey::FlowId(flow_id),
        &global.redis,
    )
    .await?;

    let metadata = DeviceMetadata::from_headers(&headers);

    if let Some(AuthFlow::TotpExchange {
        user_id, secret, ..
    }) = flow
    {
        let Some(mut user) = User::get(user_id, &global.database).await? else {
            return Err(ApiError::InvalidLogin);
        };

        if user.totp_secret.is_none() {
            return Err(ApiError::InvalidLogin); // yup. extra check just so there's a bug in another place
        }

        if TOTP_CODE_REGEX.is_match(&request.code_or_recovery) {
            let totp = get_totp_client(&totp_rs::Secret::Encoded(secret));

            if !totp.check_current(&request.code_or_recovery)? {
                return Err(ApiError::InvalidTOTPCode(request.code_or_recovery));
            }
        } else {
            let recovery_codes =
                get_totp_recovery_codes(user.totp_recovery_secret.as_ref().unwrap());

            if let Some(idx) = recovery_codes
                .iter()
                .position(|code| code == &request.code_or_recovery.to_uppercase())
            {
                if user.is_recovery_code_used(idx) {
                    return Err(ApiError::UsedRecoveryCode(request.code_or_recovery));
                } else if user.remaining_recovery_codes() == 0 {
                    return Err(ApiError::UsedRecoveryCode(request.code_or_recovery)); // womp womp
                }

                user.mark_recovery_code_used(idx);
            } else {
                return Err(ApiError::InvalidRecoveryCode(request.code_or_recovery));
            }

            let mut tx = global.database.begin().await?;
            user.update(&mut tx).await?;
            tx.commit().await?;

            let mail = AuthEmails::TOTPRecoverUsed {
                login: user.login.clone(),
            };
            global.mailer.send(&user.email, mail).await?;
        }

        AuthFlow::remove(
            AuthFlowNamespace::TotpExchange,
            AuthFlowKey::FlowId(flow_id),
            &global.redis,
        )
        .await?;

        let sess = create_session("temporary".into(), &user, &metadata, &global.settings)?;

        let mut tx = global.database.begin().await?;
        sess.session.insert(&mut tx).await?;
        tx.commit().await?;

        cookies.add(sess.cookie);
        global
            .mailer
            .send(
                &user.email,
                AuthEmails::NewLogin {
                    login: user.login,
                    metadata,
                },
            )
            .await?;

        return Ok(Json(models::Session::from(sess.session)));
    }
    // I don't really know what to return here. A error describing that the TOTP flow wasn't found or just this generic one
    Err(ApiError::InvalidLogin)
}

/// Exchange a Link ID to finalize a TOTP request flow
// TODO: this shouldn't really be focused on enabling sudo.
#[utoipa::path(
    post,
    path = "/exchange",
    request_body = Exchange,
    responses(
        (status = 200, description = "Successful TOTP exchange"),
        (status = 401, description = "Not authenticated"),
        (status = 400, description = "Validation or parsing error"),
        (status = 422, description = "Missing required fields"),
        (status = 404, description = "The TOTP exchange flow was not found"),
    ),
    tag = TOTP_TAG
)]
async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<Exchange>>,
) -> HttpResult<()> {
    if !session.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(mut user) = User::get(session.user_id(), &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

    if user.totp_secret.is_none() {
        return Err(ApiError::InvalidLogin); // yup. extra check just so there's a bug in another place
    }

    let flow_id = request.link_id;

    let flow = AuthFlow::get(
        AuthFlowNamespace::TotpExchange,
        AuthFlowKey::UserFlow {
            flow_id,
            user_id: user.id,
        },
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::TotpExchange { secret, .. }) = flow {
        if TOTP_CODE_REGEX.is_match(&request.code_or_recovery) {
            let totp = get_totp_client(&totp_rs::Secret::Encoded(secret));

            if !totp.check_current(&request.code_or_recovery)? {
                return Err(ApiError::InvalidTOTPCode(request.code_or_recovery));
            }
        } else {
            let recovery_codes =
                get_totp_recovery_codes(user.totp_recovery_secret.as_ref().unwrap());

            if let Some(idx) = recovery_codes
                .iter()
                .position(|code| code == &request.code_or_recovery.to_uppercase())
            {
                if user.is_recovery_code_used(idx) {
                    return Err(ApiError::UsedRecoveryCode(request.code_or_recovery));
                } else if user.remaining_recovery_codes() == 0 {
                    return Err(ApiError::UsedRecoveryCode(request.code_or_recovery)); // womp womp
                }

                user.mark_recovery_code_used(idx);
            } else {
                return Err(ApiError::InvalidRecoveryCode(request.code_or_recovery));
            }
        }

        AuthFlow::remove(
            AuthFlowNamespace::TotpExchange,
            AuthFlowKey::UserFlow {
                flow_id,
                user_id: user.id,
            },
            &global.redis,
        )
        .await?;

        let Some(session) = Session::get(session.session_id(), &global.database).await? else {
            remove_session(session, &cookies, &global).await?;
            return Err(ApiError::InvalidLogin);
        };

        if session.is_sudo_enabled() {
            return Ok(());
        }

        // should work alright because sudo only uses this lol
        let mut tx = global.database.begin().await?;
        session.enable_sudo(&mut tx).await?;
        tx.commit().await?;

        return Ok(());
    }

    // I don't really know what to return here. A error describing that the TOTP flow wasn't found or just this generic one
    Err(ApiError::TOTPExchangeNotFound(flow_id.to_string()))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct EnableResponse {
    secret: String,
    recovery_codes: Vec<String>,
}

/// Start the TOTP enable flow
#[utoipa::path(
    post,
    path = "/enable",
    responses(
        (status = 200, description = "Enable TOTP response", body = EnableResponse),
        (status = 400, description = "Validation or parsing error"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = TOTP_TAG
)]
async fn enable(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(session): Extension<AuthContext>,
) -> HttpResult<Json<EnableResponse>> {
    if !session.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(session.user_id(), &global.database).await? else {
        remove_session(session, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if user.totp_secret.is_some() {
        return Err(ApiError::TOTPIsAlreadyEnabled);
    }

    let flow = AuthFlow::get(
        AuthFlowNamespace::TotpEnable,
        AuthFlowKey::UserId(user.id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::TotpEnableRequest {
        secret,
        recovery_secret,
    }) = flow
    {
        let recovery_codes = get_totp_recovery_codes(&recovery_secret);

        return Ok(Json(EnableResponse {
            secret,
            recovery_codes,
        }));
    }

    let secret = totp_secret().to_encoded().to_string(); // lol
    let recovery_secret = totp_secret().to_encoded().to_string();
    let recovery_codes = get_totp_recovery_codes(&recovery_secret);

    AuthFlow::TotpEnableRequest {
        secret: secret.clone(),
        recovery_secret,
    }
    .store(
        AuthFlowNamespace::TotpEnable,
        AuthFlowKey::UserId(user.id),
        &global.redis,
    )
    .await?;

    Ok(Json(EnableResponse {
        secret,
        recovery_codes,
    }))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct EnableExchange {
    #[validate(length(equal = 6))]
    code: String,
}

/// Exchange the Link ID to finalize enabling TOTP
#[utoipa::path(
    post,
    path = "/enable/exchange",
    request_body = EnableExchange,
    responses(
        (status = 200, description = "TOTP enabled successfully"),
        (status = 401, description = "Not authenticated"),
        (status = 400, description = "Validation or parsing error"),
        (status = 422, description = "Missing required fields"),
        (status = 404, description = "The TOTP enable flow was not found"),
    ),
    tag = TOTP_TAG
)]
async fn enable_exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<EnableExchange>>,
) -> HttpResult<()> {
    if !session.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(mut user) = User::get(session.user_id(), &global.database).await? else {
        remove_session(session, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if user.totp_secret.is_some() {
        return Err(ApiError::TOTPIsAlreadyEnabled);
    }

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidTOTPCode(request.code));
    }

    let flow = AuthFlow::get(
        AuthFlowNamespace::TotpEnable,
        AuthFlowKey::UserId(user.id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::TotpEnableRequest {
        secret,
        recovery_secret,
    }) = flow
    {
        AuthFlow::remove(
            AuthFlowNamespace::TotpEnable,
            AuthFlowKey::UserId(user.id),
            &global.redis,
        )
        .await?;

        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));

        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidTOTPCode(request.code));
        }

        let mut tx = global.database.begin().await?;
        user.totp_secret = Some(secret);
        user.totp_recovery_secret = Some(recovery_secret);
        user.totp_recovery_codes = 16;
        user.update(&mut tx).await?;
        Session::delete_all_by_user(user.id, &mut tx).await?;
        tx.commit().await?;

        global
            .mailer
            .send(&user.email, AuthEmails::TOTPAdded { login: user.login })
            .await?;

        return Ok(());
    }

    Err(ApiError::TOTPFlowNotFound)
}
