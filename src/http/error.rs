use axum::{Json, response::IntoResponse};

use crate::database::redis::models::RedisError;

#[derive(Debug, serde::Serialize)]
struct HttpError<'a> {
    pub error: &'a str,
    pub message: String,
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum ApiError {
    #[error("Unexpected Database Error: {0}")]
    Database(#[from] sqlx::Error),
    // #[error("bleh")]
    // Test,
    #[error("Invalid login or password")]
    InvalidLogin,
    #[error("Something went wrong while hashing the password: {0}")]
    PasswordHashing(#[from] argon2::password_hash::Error),
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Unknown error: {0}")]
    Unknown(String),
    #[error("Unknown error: {0}")]
    UnknownAlt(#[from] anyhow::Error),
    #[error("Failed to send email because of: {0}")]
    EmailError(#[from] lettre::address::AddressError),
    #[error("Woops, something its wrong with Redis: {0}")]
    RedisError(#[from] RedisError),
    #[error("We think we broke time. {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("Seems like {0} is not really a valid OTP code")]
    InvalidOTPCode(String),
    #[error("Seems like {0} is not really a valid TOTP code")] // its just a copy of the otp err
    InvalidTOTPCode(String),
    #[error("2FA is enabled for this account")]
    TotpIsRequired,
    #[error("hi there, I am a teapot")]
    Teapot,
    #[error("2FA is already enabled on your account!")]
    TotpIsAlreadyEnabled,
    #[error("To do this you need to be logged in")]
    YouAreNotLoggedIn,
    #[error("The recovery code you provided is not valid: {0}")]
    InvalidRecoveryCode(String),
    #[error("You already used this recovery code: {0}")]
    UsedRecoveryCode(String),
    #[error("You need to enable 2FA first before you can disable it")]
    TotpIsNotEnabled,
    #[error("Seems like the OTP recovery flow has expired or is invalid. Please retry again")]
    OTPRecoveryFlowNotFound,
    #[error("The TOTP flow wasn't found. Are you sure you invoked it?")]
    TotpFlowNotFound,
    #[error("Your email seems to not be verified. Check your inbox for the code!")]
    EmailIsNotVerified,
    #[error("Your email is already verified")]
    EmailIsAlreadyVerified,
    #[error("The email verification code you provided is invalid")]
    InvalidEmailVerification,
    #[error("The method you are trying to use isn't really working out. Try again later")]
    InvalidAuthentication,
    #[error(
        "Sadly we failed to parse the scopes. It might be malformed or contain invalid values: {0}"
    )]
    FailedParsingScopes(#[from] bitflags::parser::ParseError), // TODO: fix error
    #[error("The OAuth application with ID {0} was not found")]
    OAuthAppNotFound(String),
    #[error("You are not the owner of the OAuth application with ID {0}")]
    OAuthAppNotOwned(String),
    #[error("You cannot create or update an OAuth application with no scopes")]
    OAuthAppEmptyScopes,
    #[error("The OAuth authorization with ID {0} was not found")]
    OAuthAuthorizationNotFound(String),
}

impl ApiError {
    #[allow(clippy::match_same_arms)]
    pub const fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::Database(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            // ApiError::Test => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidLogin => axum::http::StatusCode::UNAUTHORIZED,
            Self::PasswordHashing(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserAlreadyExists => axum::http::StatusCode::BAD_REQUEST,
            Self::UnknownAlt(_) | Self::Unknown(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::EmailError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::RedisError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::SystemTimeError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidOTPCode(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidTOTPCode(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::TotpIsRequired => axum::http::StatusCode::UNAUTHORIZED,
            Self::Teapot => axum::http::StatusCode::IM_A_TEAPOT,
            Self::TotpIsAlreadyEnabled => axum::http::StatusCode::BAD_REQUEST,
            Self::YouAreNotLoggedIn => axum::http::StatusCode::UNAUTHORIZED,
            Self::InvalidRecoveryCode(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::UsedRecoveryCode(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::TotpIsNotEnabled => axum::http::StatusCode::BAD_REQUEST,
            Self::OTPRecoveryFlowNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::TotpFlowNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::EmailIsNotVerified => axum::http::StatusCode::UNAUTHORIZED,
            Self::EmailIsAlreadyVerified => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidEmailVerification => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidAuthentication => axum::http::StatusCode::UNAUTHORIZED,
            Self::FailedParsingScopes(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::OAuthAppNotFound(_) => axum::http::StatusCode::NOT_FOUND,
            Self::OAuthAppNotOwned(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::OAuthAppEmptyScopes => axum::http::StatusCode::BAD_REQUEST,
            Self::OAuthAuthorizationNotFound(_) => axum::http::StatusCode::NOT_FOUND,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        tracing::error!("HTTP Error was thrown: {:?}", self);
        let error = HttpError {
            message: self.to_string(),
            error: self.into(),
        };

        (status, Json(error)).into_response()
    }
}
