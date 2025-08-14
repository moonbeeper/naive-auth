use std::sync::Arc;

use axum::{Extension, Json, Router, extract::State, routing::post};
use axum_valid::Valid;
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{
            TotpResponse, create_session, create_totp_exchange, get_totp_client, remove_session,
            totp_secret,
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

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/login", post(login))
        .route("/exchange", post(exchange))
        .route("/recover", post(recover_account))
        .route("/recover/exchange", post(recover_account_exchange))
}

#[derive(Debug, serde::Deserialize, Validate)]
struct Login {
    #[validate(email)]
    email: String,
}

#[derive(Debug, serde::Serialize)]
struct AuthResponse {
    link_id: FlowId,
}

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

    if !user.email_verified {
        let code = get_totp_client(&totp_secret().to_encoded()).generate_current()?;
        AuthFlow::VerifyEmail { code: code.clone() }
            .store(
                AuthFlowNamespace::VerifyEmail,
                AuthFlowKey::UserId(user.id),
                &global.redis,
            )
            .await?;

        let mail = AuthEmails::VerifyEmail {
            login: user.login,
            code,
        };

        global.mailer.send(&user.email, mail).await?;
        return Err(ApiError::EmailIsNotVerified);
    }

    let flow_id = FlowId::new();
    let secret = totp_secret().to_encoded();

    let flow = AuthFlow::OtpLoginRequest {
        secret: secret.to_string(),
    };
    flow.store(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::OtpAuth {
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

#[derive(Debug, serde::Deserialize, Validate)]
struct RegisterPassword {
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
        AuthFlowKey::OtpAuth {
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

#[derive(Debug, serde::Deserialize, Validate)]
struct AuthExchange {
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[validate(email)]
    email: String,
    #[validate(length(equal = 6))]
    code: String,
}

async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<AuthExchange>>,
) -> HttpResult<Json<either::Either<models::Session, TotpResponse<'static>>>> {
    remove_session(session, &cookies, &global).await?; // force logout

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let flow: Option<AuthFlow> = AuthFlow::get(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::OtpAuth {
            flow_id: request.link_id,
            email: request.email.clone(),
        },
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::OtpLoginRequest { secret }) = flow {
        let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
            return Err(ApiError::InvalidLogin);
        };

        let totp = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));
        if !totp.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::OtpAuth {
                flow_id: request.link_id,
                email: request.email.clone(),
            },
            &global.redis,
        )
        .await?;

        if user.totp_secret.is_some() {
            let response = create_totp_exchange(&user, &global.redis).await?;
            return Ok(Json(either::Right(response)));
        }

        let sess = create_session("temporary".into(), &user, &global.settings)?;

        let mut tx = global.database.begin().await?;
        sess.session.insert(&mut tx).await?;
        tx.commit().await?;

        cookies.add(sess.cookie);
        global
            .mailer
            .send(&user.email, AuthEmails::NewLogin { login: user.login })
            .await?;

        return Ok(Json(either::Left(models::Session::from(sess.session))));
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
            AuthFlowKey::OtpAuth {
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

        let sess = create_session("temporary".into(), &user, &global.settings)?;

        let mut tx = global.database.begin().await?;
        user.insert(&mut tx).await?;
        sess.session.insert(&mut tx).await?;
        tx.commit().await?;

        cookies.add(sess.cookie);
        global
            .mailer
            .send(&user.email, AuthEmails::NewLogin { login: user.login })
            .await?;

        return Ok(Json(either::Left(models::Session::from(sess.session))));
    }

    Err(ApiError::InvalidLogin)
}

#[derive(Debug, serde::Deserialize, Validate)]
struct RecoverAccount {
    #[validate(email)]
    email: String,
}

async fn recover_account(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<RecoverAccount>>,
) -> HttpResult<Json<AuthResponse>> {
    remove_session(session, &cookies, &global).await?; // force logout

    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

    if !user.email_verified {
        let code = get_totp_client(&totp_secret().to_encoded()).generate_current()?;
        AuthFlow::VerifyEmail { code }
            .store(
                AuthFlowNamespace::VerifyEmail,
                AuthFlowKey::UserId(user.id),
                &global.redis,
            )
            .await?;

        return Err(ApiError::EmailIsNotVerified);
    }

    let secret = totp_secret().to_encoded();
    let code = get_totp_client(&secret).generate_current()?;

    let flow_id = FlowId::new();
    AuthFlow::OtpRecoverRequest { code: code.clone() }
        .store(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowId(flow_id),
            &global.redis,
        )
        .await?;

    let mail = AuthEmails::OtpRecoverRequest {
        login: user.login,
        code,
    };
    global.mailer.send(&user.email, mail).await?;

    Ok(Json(AuthResponse { link_id: flow_id }))
}

#[derive(Debug, serde::Deserialize, Validate)]
struct RecoverAccountExchange {
    #[validate(email)]
    email: String,
    #[validate(length(equal = 26))]
    link_id: FlowId,
    #[validate(length(equal = 6))]
    code: String,
}

async fn recover_account_exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<RecoverAccountExchange>>,
) -> HttpResult<Json<models::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        return Err(ApiError::InvalidLogin);
    };

    let flow = AuthFlow::get(
        AuthFlowNamespace::OtpAuth,
        AuthFlowKey::FlowId(request.link_id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::OtpRecoverRequest { code }) = flow {
        if code != request.code {
            return Err(ApiError::InvalidRecoveryCode(request.code));
        }
        AuthFlow::remove(
            AuthFlowNamespace::OtpAuth,
            AuthFlowKey::FlowId(request.link_id),
            &global.redis,
        )
        .await?;
        let sess = create_session("temporary".into(), &user, &global.settings)?;

        let mut tx = global.database.begin().await?;
        sess.session.insert(&mut tx).await?;
        tx.commit().await?;

        cookies.add(sess.cookie);
        global
            .mailer
            .send(&user.email, AuthEmails::NewLogin { login: user.login })
            .await?;

        return Ok(Json(models::Session::from(sess.session)));
    }

    Err(ApiError::OTPRecoveryFlowNotFound)
}
