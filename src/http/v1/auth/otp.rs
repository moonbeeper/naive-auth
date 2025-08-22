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
            DeviceMetadata, TotpResponse, create_session, create_totp_login_exchange,
            get_totp_client, remove_session, totp_secret,
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
        HttpResult,
        error::ApiError,
        v1::{JsonEither, models},
    },
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(exchange_login))
        .routes(routes!(exchange))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct Login {
    #[validate(email)]
    email: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AuthResponse {
    link_id: FlowId,
}

/// Login or register via a code! (If the account isn't found, it will start the register flow)
#[utoipa::path(
    post,
    path = "/login",
    request_body = Login,
    responses(
        (status = 200, description = "Login flow started", body = AuthResponse),
        (status = 400, description = "Invalid login, email not verified, etc."),
    ),
    tag = "otp",
    operation_id = "authOtpLogin"
)]
async fn login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<Login>>,
) -> HttpResult<Json<AuthResponse>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        return register(global, request.email).await;
    };

    let flow_id = FlowId::new();
    let secret = totp_secret().to_encoded();

    let flow = AuthFlow::OtpLoginRequest {
        secret: secret.to_string(),
    };
    flow.store(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::FlowEmail {
            flow_id,
            email: user.email.clone(),
        },
        &global.redis,
    )
    .await?;

    let code = get_totp_client(&secret).generate_current()?;
    let email = AuthEmails::OtpLoginRequest {
        login: user.login,
        code: code.to_string(),
    };

    global.mailer.send(&user.email, email).await?;
    Ok(Json(AuthResponse { link_id: flow_id }))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct RegisterPassword {
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    login: String,
    #[validate(length(min = 9))]
    password: String,
}

async fn register(global: Arc<GlobalState>, email: String) -> HttpResult<Json<AuthResponse>> {
    let flow_id = FlowId::new();
    let secret = totp_secret().to_encoded();

    let flow = AuthFlow::OtpRegisterRequest {
        secret: secret.to_string(),
    };
    flow.store(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::FlowEmail {
            flow_id,
            email: email.clone(),
        },
        &global.redis,
    )
    .await?;

    let code = get_totp_client(&secret).generate_current()?;

    let mailer_email = AuthEmails::OtpRegisterRequest {
        email: email.clone(),
        code: code.to_string(),
    };

    global.mailer.send(&email, mailer_email).await?;
    Ok(Json(AuthResponse { link_id: flow_id }))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct AuthExchange {
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[validate(email)]
    email: String,
    #[validate(length(equal = 6))]
    code: String,
}

/// Exchange the OTP code sent to the user's email for a session
#[allow(clippy::too_many_lines)] // leave me alone please
#[utoipa::path(
    post,
    path = "/exchange-login",
    request_body = AuthExchange,
    responses(
        (status = 200, description = "Exchanged for session or TOTP challenge", body = JsonEither<models::Session, TotpResponse>),
        (status = 400, description = "Invalid code or login"),
    ),
    tag = "otp",
    operation_id = "authOtpExchangeLogin"
)]
async fn exchange_login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<AuthExchange>>,
) -> HttpResult<JsonEither<models::Session, TotpResponse<'static>>> {
    remove_session(session, &cookies, &global).await?; // force logout

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let flow: Option<AuthFlow> = AuthFlow::get(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::FlowEmail {
            flow_id: request.link_id,
            email: request.email.clone(),
        },
        &global.redis,
    )
    .await?;
    let metadata = DeviceMetadata::from_headers(&headers);

    if let Some(AuthFlow::OtpLoginRequest { secret }) = flow {
        let Some(mut user) = User::get_by_email(&request.email, &global.database).await? else {
            return Err(ApiError::InvalidLogin);
        };

        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));
        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id: request.link_id,
                email: request.email.clone(),
            },
            &global.redis,
        )
        .await?;

        if !user.email_verified {
            user.email_verified = true;
            let mut tx = global.database.begin().await?;
            user.update(&mut tx).await?;
            tx.commit().await?;
        }

        if user.totp_secret.is_some() {
            let response = create_totp_login_exchange(&user, &global.redis).await?;
            return Ok(JsonEither::Right(response));
        }

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

        return Ok(JsonEither::Left(models::Session::from(sess.session)));
    } else if let Some(AuthFlow::OtpRegisterRequest { secret }) = flow {
        if (User::get_by_email(&request.email, &global.database).await?).is_some() {
            return Err(ApiError::InvalidLogin);
        }
        let login = User::get_login_by_email(&request.email, &global.database).await?;

        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));
        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id: request.link_id,
                email: request.email.clone(),
            },
            &global.redis,
        )
        .await?;

        let user = User::builder()
            .login(login.clone())
            .email(request.email.clone())
            .email_verified(true)
            .build();

        let sess = create_session("temporary".into(), &user, &metadata, &global.settings)?;

        let mut tx = global.database.begin().await?;
        user.insert(&mut tx).await?;
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

        return Ok(JsonEither::Left(models::Session::from(sess.session)));
    }

    Err(ApiError::InvalidLogin)
}

/// Exchange the OTP code sent to the user's email to finish a otp exchange flow
// TODO: this should really be focused on enabling sudo.
#[utoipa::path(
    post,
    path = "/exchange",
    request_body = AuthExchange,
    responses(
        (status = 200, description = "Successful OTP exchange"),
        (status = 400, description = "Invalid code or login"),
    ),
    tag = "otp",
    operation_id = "authOtpExchange"
)]
async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<AuthExchange>>,
) -> HttpResult<()> {
    if !session.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(session.user_id(), &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let flow = AuthFlow::get(
        AuthFlowNamespace::OtpExchange,
        AuthFlowKey::UserFlow {
            flow_id: request.link_id,
            user_id: user.id,
        },
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::OtpExchange { secret }) = flow {
        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));
        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlowNamespace::OtpExchange,
            AuthFlowKey::UserFlow {
                flow_id: request.link_id,
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

    Err(ApiError::OTPExchangeNotFound(request.link_id.to_string()))
}
