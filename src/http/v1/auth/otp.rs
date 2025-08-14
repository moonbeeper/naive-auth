use std::sync::Arc;

use axum::{Extension, Json, Router, extract::State, routing::post};
use axum_valid::Valid;
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        ops::{create_session, get_totp_client, remove_session, totp_secret},
    },
    database::{
        models::user::User,
        redis::models::{
            FlowId,
            auth::{AuthFlow, AuthFlowKey},
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

    let flow_id = FlowId::new();
    let secret = totp_secret().to_encoded();

    let flow = AuthFlow::OtpLoginRequest {
        secret: secret.to_string(),
    };
    flow.store(
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
) -> HttpResult<Json<models::auth::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let flow_id = request.link_id;

    if request.code.trim().is_empty() {
        return Err(ApiError::InvalidOTPCode(request.code));
    }

    // yeah its pretty bad a separated enum would do better in this case so it doesn't become a wordful mess
    let flow = AuthFlow::get(
        AuthFlow::OtpLoginRequest {
            secret: String::new(),
        },
        AuthFlowKey::OtpAuth {
            flow_id,
            email: request.email.clone(),
        },
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::OtpLoginRequest { secret }) = flow {
        let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
            return Err(ApiError::InvalidLogin);
        };

        let code = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));

        if !code.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlow::OtpLoginRequest {
                secret: String::new(),
            },
            AuthFlowKey::OtpAuth {
                flow_id,
                email: request.email.clone(),
            },
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

        return Ok(Json(models::auth::Session::from(sess.session)));
    } else if let Some(AuthFlow::OtpRegisterRequest { secret }) = flow {
        if (User::get_by_email(&request.email, &global.database).await?).is_some() {
            return Err(ApiError::InvalidLogin);
        }
        let login = User::get_login_by_email(&request.email, &global.database).await?;

        let code = get_totp_client(&totp_rs::Secret::Encoded(secret.clone()));

        if !code.check_current(&request.code)? {
            return Err(ApiError::InvalidOTPCode(request.code));
        }

        AuthFlow::remove(
            AuthFlow::OtpLoginRequest {
                secret: String::new(),
            },
            AuthFlowKey::OtpAuth {
                flow_id,
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

        return Ok(Json(models::auth::Session::from(sess.session)));
    }

    Err(ApiError::InvalidLogin)
}
