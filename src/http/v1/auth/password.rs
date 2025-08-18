use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{Extension, Json, extract::State};
use axum_valid::Valid;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
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
        redis::models::auth::{AuthFlow, AuthFlowKey, AuthFlowNamespace},
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
        .routes(routes!(register))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct LoginPassword {
    #[serde(rename = "login")]
    login_or_email: String,
    #[validate(length(min = 9))]
    password: String,
}

/// Login via user login or email and password. If you have TOTP enabled, a TOTP exchange Link ID will be returned
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginPassword,
    responses(
        (status = 200, description = "Successful login, session or TOTP challenge", body = JsonEither<models::Session, TotpResponse<'static>>),
        (status = 400, description = "Bad request (invalid login, email not verified, etc)"),
    ),
    tag = "password"
)]
async fn login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<LoginPassword>>,
) -> HttpResult<JsonEither<models::Session, TotpResponse<'static>>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let login = any_ascii::any_ascii(&request.login_or_email);

    let user = if let Some(user) = User::get_by_login(&login, &global.database).await? {
        user
    } else if let Some(user) = User::get_by_email(&request.login_or_email, &global.database).await?
    {
        user
    } else {
        return Err(ApiError::InvalidLogin);
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

    if user.password_hash.is_none() {
        Err(ApiError::InvalidLogin)?;
    }

    let argon2 = Argon2::default();
    argon2
        .verify_password(
            request.password.as_bytes(),
            &PasswordHash::new(user.password_hash.as_ref().unwrap())?,
        )
        .map_err(|_| ApiError::InvalidLogin)?;

    if user.totp_secret.is_some() {
        let response = create_totp_exchange(&user, &global.redis).await?;
        return Ok(JsonEither::Right(response));
    }

    let sess = create_session("temporary".into(), &user, &global.settings)?;

    let mut tx = global.database.begin().await?;
    sess.session.insert(&mut tx).await?;
    tx.commit().await?;

    cookies.add(sess.cookie);
    global
        .mailer
        .send(&user.email, AuthEmails::NewLogin { login })
        .await?;

    Ok(JsonEither::Left(models::Session::from(sess.session)))
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

/// Register via email, login and password
#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterPassword,
    responses(
        (status = 200, description = "Account registered, session returned", body = models::Session),
        (status = 400, description = "Invalid input or already exists"),
    ),
    tag = "password"
)]
async fn register(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<RegisterPassword>>,
) -> HttpResult<Json<models::Session>> {
    remove_session(session, &cookies, &global).await?; // force logout

    if User::get_by_email(&request.email, &global.database)
        .await?
        .is_some()
    {
        return Err(ApiError::UserAlreadyExists);
    }

    let login = any_ascii::any_ascii(&request.login);

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let password_hash = argon2
        .hash_password(request.password.as_bytes(), &salt)?
        .to_string();

    let user = User::builder()
        .login(login)
        .email(request.email.clone())
        .email_verified(false)
        .password_hash(password_hash)
        .build();

    let sess = create_session("temporary".into(), &user, &global.settings)?;

    let mut tx = global.database.begin().await?;
    user.insert(&mut tx).await?;
    sess.session.insert(&mut tx).await?;
    tx.commit().await?;

    cookies.add(sess.cookie);
    Ok(Json(models::Session::from(sess.session)))
}
