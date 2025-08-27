use std::sync::Arc;

use argon2::{
    Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::HeaderMap,
};
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
            DeviceMetadata, TOTP_CODE_REGEX, TotpResponse, create_session,
            create_totp_login_exchange, get_totp_client, get_totp_recovery_codes, remove_session,
            totp_secret,
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
        HttpResult, PASSWORD_TAG,
        error::ApiError,
        v1::{JsonEither, models, string_trim},
    },
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(register))
        .routes(routes!(reset_password))
        .routes(routes!(reset_password_status))
        .routes(routes!(reset_password_check))
        .routes(routes!(reset_password_set))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct LoginPassword {
    #[serde(rename = "login")]
    login_or_email: String,
    #[validate(length(min = 8))]
    password: String,
}

/// Login via user login or email and password
///
/// Simple login with password. If the user has TOTP enabled, you'll get a TOTP challenge instead of a session.
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginPassword,
    responses(
        (status = 200, description = "Successful login, session or TOTP challenge", body = JsonEither<models::Session, TotpResponse<'static>>),
        (status = 400, description = "Bad request (invalid login, email not verified, etc)"),
    ),
    tag = PASSWORD_TAG,
    operation_id = "authPasswordLogin"
)]
async fn login(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    headers: HeaderMap,
    Valid(Json(request)): Valid<Json<LoginPassword>>,
) -> HttpResult<JsonEither<models::Session, TotpResponse<'static>>> {
    remove_session(session, &cookies, &global).await?; // force logout
    let login = any_ascii::any_ascii(&request.login_or_email);

    // this is working currently, but should be using a regex instead of doing two queries lol
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

    let metadata = DeviceMetadata::from_headers(&headers);

    let argon2 = Argon2::default();
    argon2
        .verify_password(
            request.password.as_bytes(),
            &PasswordHash::new(user.password_hash.as_ref().unwrap())?,
        )
        .map_err(|_| ApiError::InvalidLogin)?;

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
        .send(&user.email, AuthEmails::NewLogin { login, metadata })
        .await?;

    Ok(JsonEither::Left(models::Session::from(sess.session)))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct RegisterPassword {
    #[validate(email)]
    email: String,
    #[validate(length(min = 6))]
    login: String,
    #[validate(length(min = 8))]
    password: String,
}

/// Register via email and password
///
/// Register a new user with the provided email, password and login. You'll need to verify your email after registering.
#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterPassword,
    responses(
        (status = 200, description = "Account registered, verify your email lol"),
        (status = 400, description = "Invalid input or already exists"),
    ),
    tag = PASSWORD_TAG
)]
async fn register(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<RegisterPassword>>,
) -> HttpResult<()> {
    remove_session(session, &cookies, &global).await?; // force logout

    let login = any_ascii::any_ascii(&request.login);

    // early checks before doing costly, waiting time ops (db query)
    let strength = zxcvbn::zxcvbn(&request.password, &[&login, &request.email]).score();
    if strength < zxcvbn::Score::Three {
        return Err(ApiError::PasswordLowStrength);
    }

    if User::get_by_email_or_login(&request.email, &request.login, &global.database)
        .await?
        .is_some()
    {
        return Err(ApiError::UserAlreadyExists);
    }

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

    let mut tx = global.database.begin().await?;
    user.insert(&mut tx).await?;
    tx.commit().await?;

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

    Ok(())
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ResetPassword {
    #[validate(email)]
    email: String,
}

// this is practically a duplicate of the otp flow but focused on resetting a password.
/// Start the password reset flow
///
/// This will send a password reset link to the user's email to begin the password reset flow
#[utoipa::path(
    post,
    path = "/reset",
    request_body = ResetPassword,
    responses(
        (status = 200, description = "Started the password reset flow, check your email"),
    ),
    tag = PASSWORD_TAG
)]
async fn reset_password(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<ResetPassword>>,
) -> HttpResult<()> {
    remove_session(session, &cookies, &global).await?; // force logout
    let Some(user) = User::get_by_email(&request.email, &global.database).await? else {
        // fail silently by just returning ok
        return Ok(());
    };

    let flow_id = FlowId::new();

    let flow = AuthFlow::PasswordReset {
        user_id: user.id,
        has_totp: user.totp_secret.is_some(),
        totp_verified: false,
    };
    flow.store(
        AuthFlowNamespace::PasswordReset,
        AuthFlowKey::FlowId(flow_id),
        &global.redis,
    )
    .await?;

    let reset_url = format!("{}/reset/{flow_id}", global.settings.http.frontend_url); // frontend should handle this
    let email = AuthEmails::PasswordReset {
        reset_url,
        raw_code: flow_id.to_string(),
    };
    global.mailer.send(&user.email, email).await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ResetPasswordPath {
    #[validate(length(equal = 26))]
    id: FlowId,
}

#[derive(Debug, serde::Serialize, ToSchema)]
#[serde(rename_all = "lowercase")] // I really don't know if I should return it like this
enum ResetStatus {
    Ready,
    Totp,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ResetPasswordStatus {
    status: ResetStatus,
}
// useless in an aspect, but useful in the other. or that's what i think haha
/// Get the available options to reset the password.
#[utoipa::path(
    get,
    path = "/reset/{id}",
    params(
        ("id" = FlowId, description = "The ID of the reset password flow")
    ),
    responses(
        (status = 200, description = "The current status of the reset password flow", body = ResetPasswordStatus),
        (status = 400, description = "Validation or parsing error"),
        (status = 404, description = "The reset password flow was not found"),
    ),
    tag = PASSWORD_TAG
)]
async fn reset_password_status(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Path(request)): Valid<Path<ResetPasswordPath>>,
) -> HttpResult<Json<ResetPasswordStatus>> {
    remove_session(session, &cookies, &global).await?; // force logout

    let flow = AuthFlow::get(
        AuthFlowNamespace::PasswordReset,
        AuthFlowKey::FlowId(request.id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::PasswordReset { has_totp, .. }) = flow {
        if has_totp {
            return Ok(Json(ResetPasswordStatus {
                status: ResetStatus::Totp,
            }));
        }

        return Ok(Json(ResetPasswordStatus {
            status: ResetStatus::Ready,
        }));
    }

    Err(ApiError::RecoveryLinkNotFound)
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ResetPasswordCheck {
    #[serde(deserialize_with = "string_trim")]
    #[validate(length(min = 6, max = 11))]
    code_or_recovery: String,
}

/// Verify the TOTP code or recovery code to continue the password reset flow.
///
/// If the user doesn't have TOTP enabled, it will just return OK lol
#[utoipa::path(
    post,
    path = "/reset/{id}/verify",
    request_body = ResetPasswordCheck,
    params(
        ("id" = FlowId, description = "The ID of the reset password flow")
    ),
    responses(
        (status = 200, description = "Successfully verified the recovery flow"),
        (status = 400, description = "Validation or parsing error"),
        (status = 422, description = "Missing required fields"),
        (status = 404, description = "The reset password flow was not found"),
    ),
    tag = PASSWORD_TAG
)]
async fn reset_password_check(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Path(path)): Valid<Path<ResetPasswordPath>>,
    Valid(Json(request)): Valid<Json<ResetPasswordCheck>>,
) -> HttpResult<()> {
    remove_session(session, &cookies, &global).await?; // force logout
    let flow = AuthFlow::get(
        AuthFlowNamespace::PasswordReset,
        AuthFlowKey::FlowId(path.id),
        &global.redis,
    )
    .await?;

    if let Some(
        this @ AuthFlow::PasswordReset {
            has_totp, user_id, ..
        },
    ) = flow
    {
        if !has_totp {
            return Ok(());
        }

        let Some(mut user) = User::get(user_id, &global.database).await? else {
            return Err(ApiError::RecoveryLinkNotFound);
        };

        if user.totp_secret.is_none() {
            return Err(ApiError::RecoveryLinkNotFound); // yup. extra check just so there's a bug in another place
        }

        if TOTP_CODE_REGEX.is_match(&request.code_or_recovery) {
            let totp =
                get_totp_client(&totp_rs::Secret::Encoded(user.totp_secret.clone().unwrap()));

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

            let mail = AuthEmails::TOTPRecoverUsed { login: user.login };
            global.mailer.send(&user.email, mail).await?;
        }

        let new = AuthFlow::PasswordReset {
            user_id,
            has_totp: true,
            totp_verified: true,
        };

        this.mutate(
            new,
            AuthFlowNamespace::PasswordReset,
            AuthFlowKey::FlowId(path.id),
            true,
            &global.redis,
        )
        .await?;

        return Ok(());
    }

    Err(ApiError::RecoveryLinkNotFound)
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ResetPasswordExchange {
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    password_confirm: String,
}

/// Set the new password for the user
///
/// If the user has TOTP enabled, you'll need to run through the TOTP flow first or else the flow will be deleted.
#[utoipa::path(
    put,
    path = "/reset/{id}/set",
    request_body = ResetPasswordExchange,
    params(
        ("id" = FlowId, description = "The ID of the reset password flow")
    ),
    responses(
        (status = 200, description = "Successfully set the new password"),
        (status = 400, description = "Validation or parsing error"),
        (status = 422, description = "Missing required fields"),
        (status = 404, description = "The reset password flow was not found"),
    ),
    tag = PASSWORD_TAG
)]
async fn reset_password_set(
    State(global): State<Arc<GlobalState>>,
    Extension(session): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Path(path)): Valid<Path<ResetPasswordPath>>,
    Valid(Json(request)): Valid<Json<ResetPasswordExchange>>,
) -> HttpResult<()> {
    remove_session(session, &cookies, &global).await?; // force logout

    let flow = AuthFlow::get(
        AuthFlowNamespace::PasswordReset,
        AuthFlowKey::FlowId(path.id),
        &global.redis,
    )
    .await?;

    if let Some(AuthFlow::PasswordReset {
        has_totp,
        user_id,
        totp_verified,
    }) = flow
    {
        if has_totp && !totp_verified {
            // kill it. no second chance
            AuthFlow::remove(
                AuthFlowNamespace::PasswordReset,
                AuthFlowKey::FlowId(path.id),
                &global.redis,
            )
            .await?;

            return Err(ApiError::RecoveryLinkNotFound);
        }

        if request.password != request.password_confirm {
            return Err(ApiError::PasswordDoesNotMatch);
        }

        let Some(mut user) = User::get(user_id, &global.database).await? else {
            return Err(ApiError::RecoveryLinkNotFound);
        };

        let strength = zxcvbn::zxcvbn(&request.password, &[&user.login, &user.email]).score();
        if strength < zxcvbn::Score::Three {
            return Err(ApiError::PasswordLowStrength);
        }

        AuthFlow::remove(
            AuthFlowNamespace::PasswordReset,
            AuthFlowKey::FlowId(path.id),
            &global.redis,
        )
        .await?;

        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
        let password_hash = argon2
            .hash_password(request.password.as_bytes(), &salt)?
            .to_string();

        user.email_verified = true; // user has gone through practically OTP login lol
        user.password_hash = Some(password_hash);

        let mut tx = global.database.begin().await?;
        Session::delete_all_by_user(user.id, &mut tx).await?;
        user.update(&mut tx).await?;
        tx.commit().await?;

        return Ok(());
    }

    Err(ApiError::RecoveryLinkNotFound)
}
