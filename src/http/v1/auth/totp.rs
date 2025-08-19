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
            DeviceMetadata, create_session, get_totp_client, get_totp_recovery_codes,
            remove_session, totp_secret,
        },
    },
    database::{
        models::user::User,
        redis::models::{
            FlowId,
            auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
        },
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(exchange))
        .routes(routes!(enable))
        .routes(routes!(enable_exchange))
        .routes(routes!(recover_account))
        .routes(routes!(disable))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct Exchange {
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[validate(length(equal = 6))]
    code: String,
}

/// Exchange a Link ID to finalize a TOTP request
#[utoipa::path(
    post,
    path = "/exchange",
    request_body = Exchange,
    responses(
        (status = 200, description = "Successful TOTP exchange", body = models::Session),
        (status = 400, description = "Invalid TOTP code or flow"),
        (status = 401, description = "Not logged in"),
    ),
    tag = "totp"
)]
async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<Exchange>>,
) -> HttpResult<Json<models::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let flow_id = request.link_id;

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidTOTPCode(request.code));
    }

    let flow = AuthFlow::get(
        AuthFlowNamespace::TotpExchange,
        AuthFlowKey::FlowId(flow_id),
        &global.redis,
    )
    .await?;

    let metadata = DeviceMetadata::from_headers(&headers);

    if let Some(AuthFlow::TotpExchange {
        user_id, secret, ..
    }) = flow
    {
        let Some(user) = User::get(user_id, &global.database).await? else {
            return Err(ApiError::InvalidLogin);
        };

        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret));

        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidTOTPCode(request.code));
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

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct EnableResponse {
    secret: String,
    recovery_codes: Vec<String>,
}

/// The first step to enable TOTP for an account
#[utoipa::path(
    post,
    path = "/enable",
    responses(
        (status = 200, description = "Enable TOTP response", body = EnableResponse),
        (status = 400, description = "TOTP already enabled or invalid login"),
        (status = 401, description = "Not logged in")
    ),
    tag = "totp"
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
        return Err(ApiError::TotpIsAlreadyEnabled);
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

/// The final step to enable TOTP for an account
#[utoipa::path(
    post,
    path = "/enable/exchange",
    request_body = EnableExchange,
    responses(
        (status = 200, description = "TOTP enabled successfully"),
        (status = 400, description = "Invalid code or flow"),
        (status = 401, description = "Not logged in")
    ),
    tag = "totp"
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

    let Some(user) = User::get(session.user_id(), &global.database).await? else {
        remove_session(session, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if user.totp_secret.is_some() {
        return Err(ApiError::TotpIsAlreadyEnabled);
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
        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));

        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidTOTPCode(request.code));
        }

        let mut tx = global.database.begin().await?;
        let mut user = user;
        user.totp_secret = Some(secret);
        user.totp_recovery_secret = Some(recovery_secret);
        user.totp_recovery_codes = 16;
        user.update(&mut tx).await?;
        tx.commit().await?;

        AuthFlow::remove(
            AuthFlowNamespace::TotpEnable,
            AuthFlowKey::UserId(user.id),
            &global.redis,
        )
        .await?;

        global
            .mailer
            .send(&user.email, AuthEmails::TOTPAdded { login: user.login })
            .await?;

        return Ok(());
    }

    Err(ApiError::TotpFlowNotFound)
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct RecoverAccount {
    #[validate(email)]
    email: String,
    #[validate(length(equal = 11))]
    recovery_code: String,
}

/// Recover an account via its TOTP recovery codes if the user has TOTP enabled
#[utoipa::path(
    post,
    path = "/recovery",
    request_body = RecoverAccount,
    responses(
        (status = 200, description = "Session after recovery", body = models::Session),
        (status = 400, description = "Invalid code or login"),
        (status = 401, description = "Not logged in")
    ),
    tag = "totp"
)]
async fn recover_account(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<RecoverAccount>>,
) -> HttpResult<Json<models::Session>> {
    remove_session(session, &cookies, &global).await?;
    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

    if user.totp_secret.is_none() {
        return Err(ApiError::InvalidLogin);
    }
    let metadata = DeviceMetadata::from_headers(&headers);

    let mut mut_user = user.clone();
    let recovery_codes = get_totp_recovery_codes(user.totp_recovery_secret.as_ref().unwrap());

    if let Some(idx) = recovery_codes
        .iter()
        .position(|code| code == &request.recovery_code.to_uppercase())
    {
        if mut_user.is_recovery_code_used(idx) {
            return Err(ApiError::UsedRecoveryCode(request.recovery_code));
        } else if mut_user.remaining_recovery_codes() == 0 {
            return Err(ApiError::UsedRecoveryCode(request.recovery_code)); // womp womp
        }

        mut_user.mark_recovery_code_used(idx);
    } else {
        return Err(ApiError::InvalidRecoveryCode(request.recovery_code));
    }

    let sess = create_session("temporary".into(), &user, &metadata, &global.settings)?;
    let mut tx = global.database.begin().await?;
    mut_user.update(&mut tx).await?;
    sess.session.insert(&mut tx).await?;
    tx.commit().await?;

    cookies.add(sess.cookie);

    let mail = AuthEmails::TOTPRecoverUsed { login: user.login };

    global.mailer.send(&user.email, mail).await?;
    Ok(Json(models::Session::from(sess.session)))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct Disable {
    #[validate(length(equal = 6))]
    code: String,
}

/// Disable TOTP from this account
#[utoipa::path(
    post,
    path = "/disable",
    request_body = Disable,
    responses(
        (status = 200, description = "TOTP disabled successfully"),
        (status = 400, description = "Invalid code or TOTP not enabled"),
        (status = 401, description = "Not logged in")
    ),
    tag = "totp"
)]
async fn disable(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<Disable>>,
) -> HttpResult<()> {
    if !session.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(session.user_id(), &global.database).await? else {
        remove_session(session, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };
    let mut mut_user = user.clone();

    let Some(secret) = user.totp_secret else {
        return Err(ApiError::TotpIsNotEnabled);
    };

    let totp = get_totp_client(&totp_rs::Secret::Encoded(secret));
    if !totp.check_current(&request.code)? {
        return Err(ApiError::InvalidTOTPCode(request.code));
    }

    mut_user.totp_secret = None;
    mut_user.totp_recovery_secret = None;
    mut_user.totp_recovery_codes = 0;

    let mut tx = global.database.begin().await?;
    mut_user.update(&mut tx).await?;
    tx.commit().await?;

    Ok(())
}
