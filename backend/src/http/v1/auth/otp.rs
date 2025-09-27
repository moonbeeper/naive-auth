use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{Extension, extract::State, http::HeaderMap};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{
            DeviceMetadata, create_session, create_totp_login_exchange, get_totp_client,
            remove_session, totp_secret,
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
        HttpResult, OTP_TAG,
        error::{ApiError, ApiHttpError},
        v1::models,
        validation::{Json, Valid},
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

/// Login or register
///
/// This will send a code to the provided email address to either login or register
#[utoipa::path(
    post,
    path = "/login",
    request_body = Login,
    responses(
        (status = 200, description = "Login flow started", body = AuthResponse),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OTP_TAG,
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
    let code = get_totp_client(&secret).generate_current()?;

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let secret = argon2.hash_password(code.as_bytes(), &salt)?.to_string();

    AuthFlow::OtpLoginRequest { secret }
        .store(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id,
                email: user.email.clone(),
            },
            &global.redis,
        )
        .await?;

    let email = AuthEmails::OtpRequest {
        identifier: user.login,
        code,
        is_login: true,
    };

    global.mailer.send(&user.email, email).await?;
    Ok(Json(AuthResponse { link_id: flow_id }))
}

async fn register(global: Arc<GlobalState>, email: String) -> HttpResult<Json<AuthResponse>> {
    let flow_id = FlowId::new();
    let secret = totp_secret().to_encoded();
    let code = get_totp_client(&secret).generate_current()?;

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let secret = argon2.hash_password(code.as_bytes(), &salt)?.to_string();

    AuthFlow::OtpRegisterRequest { secret }
        .store(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id,
                email: email.clone(),
            },
            &global.redis,
        )
        .await?;

    let mailer_email = AuthEmails::OtpRequest {
        identifier: email.clone(),
        code: code.to_string(),
        is_login: false,
    };

    global.mailer.send(&email, mailer_email).await?;
    Ok(Json(AuthResponse { link_id: flow_id }))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct AuthExchange {
    /// The link ID of the OTP flow
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[validate(email)]
    email: String,
    /// The code that was sent to the email address
    #[validate(length(equal = 6))]
    code: String,
}

// TODO: Store the OTP code instead of the secret
// We are NOT storing the code. Making so the totp code is being rotated every 30 seconds which is not cool.
/// Exchange the code sent to the user's email for a session
#[allow(clippy::too_many_lines)] // leave me alone please
#[utoipa::path(
    post,
    path = "/exchange-login",
    request_body = AuthExchange,
    responses(
        (status = 200, description = "Exchanged for a new session", body = models::Session),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 403, description = "TOTP challenge required", body = ApiHttpError),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OTP_TAG,
    operation_id = "authOtpExchangeLogin"
)]
// #[axum::debug_handler]
async fn exchange_login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<AuthExchange>>,
) -> HttpResult<Json<models::Session>> {
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

        let argon2 = Argon2::default();
        argon2
            .verify_password(request.code.as_bytes(), &PasswordHash::new(&secret)?)
            .map_err(|_| ApiError::InvalidOTPCode(request.code))?;

        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id: request.link_id,
                email: request.email.clone(),
            },
            &global.redis,
        )
        .await?;

        // when the user uses OTP to login, we can assume that their email is verified because they just used our code
        if !user.email_verified {
            user.email_verified = true;
            let mut tx = global.database.begin().await?;
            user.update(&mut tx).await?;
            tx.commit().await?;
        }

        if user.totp_secret.is_some() {
            create_totp_login_exchange(&user, &global.redis).await?;
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

        return Ok(Json(models::Session::from(sess.session)));
    } else if let Some(AuthFlow::OtpRegisterRequest { secret }) = flow {
        if (User::get_by_email(&request.email, &global.database).await?).is_some() {
            return Err(ApiError::InvalidLogin);
        }

        let argon2 = Argon2::default();
        argon2
            .verify_password(request.code.as_bytes(), &PasswordHash::new(&secret)?)
            .map_err(|_| ApiError::InvalidOTPCode(request.code))?;

        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowEmail {
                flow_id: request.link_id,
                email: request.email.clone(),
            },
            &global.redis,
        )
        .await?;

        let login = User::get_login_by_email(&request.email, &global.database).await?;
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

        return Ok(Json(models::Session::from(sess.session)));
    }

    Err(ApiError::InvalidLogin)
}

/// Exchange the OTP code sent to the user's email to finish a flow
// TODO: this shouldn't really be focused on enabling sudo.
#[utoipa::path(
    post,
    path = "/exchange",
    request_body = AuthExchange,
    responses(
        (status = 200, description = "Successful OTP exchange"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "OTP exchange flow not found", body = ApiHttpError),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OTP_TAG,
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

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let Some(user) = User::get(session.user_id(), &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

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
        let argon2 = Argon2::default();
        argon2
            .verify_password(request.code.as_bytes(), &PasswordHash::new(&secret)?)
            .map_err(|_| ApiError::InvalidOTPCode(request.code))?;

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
