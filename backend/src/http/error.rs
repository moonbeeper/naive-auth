use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::database::redis::models::RedisError;

// TODO: maybe making this in a proc macro so it would use ApiErrorFlattened?
// that way we could still use this struct for the actual responses, meanwhile the generated one only for the schema
/// An alias to the actual `HttpError`
pub type ApiHttpError = HttpError<'static>;

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct HttpError<'a> {
    pub error: &'a str,
    pub message: String,
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr, beepauth_macros::FlattenEnum)]
#[flatten_enum(utoipa_name = "ApiHttpError")]
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
    TOTPIsRequired,
    #[error("hi there, I am a teapot")]
    Teapot,
    #[error("2FA is already enabled on your account!")]
    TOTPIsAlreadyEnabled,
    #[error("To do this you need to be logged in")]
    YouAreNotLoggedIn,
    #[error("The recovery code you provided is not valid: {0}")]
    InvalidRecoveryCode(String),
    #[error("You already used this recovery code: {0}")]
    UsedRecoveryCode(String),
    #[error("You need to enable 2FA first before you can disable it")]
    TOTPIsNotEnabled,
    #[error("Seems like the OTP recovery flow has expired or is invalid. Please retry again")]
    OTPRecoveryFlowNotFound,
    #[error("The TOTP flow wasn't found. Are you sure you invoked it?")]
    TOTPFlowNotFound,
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
    #[error("Sudo is currently not enabled in this session")]
    SudoIsNotEnabled,
    #[error("Sudo is already enabled in this session")]
    SudoIsAlreadyEnabled,
    #[error("You cannot enable sudo with this option")]
    SudoCannotBeEnabled,
    #[error("The TOTP exchange flow with ID {0} was not found")]
    TOTPExchangeNotFound(String),
    #[error("The TOTP exchange flow with ID {0} was not found")]
    OTPExchangeNotFound(String),
    #[error("Are you sure that a session with ID {0} exists?")]
    SessionDoesNotExist(String),
    #[error("Somehow we failed to parse a URL: {0}")]
    FailedParsingURL(#[from] url::ParseError),
    #[error(
        "The OAuth callback URL is invalid. Are you sure it doesn't contain a fragment in it (#)?"
    )]
    OAuthInvalidUri,
    #[error("The passwords do not match. Are you sure you typed them correctly?")]
    PasswordDoesNotMatch,
    #[error("The password you provided is too weak. May you consider using a stronger password?")]
    PasswordLowStrength,
    #[error("The recovery link you provided was not found or has expired")]
    RecoveryLinkNotFound,
    #[error("{0}")]
    ValidationError(String),
    #[error("{0}")]
    JsonSyntaxError(String),
    #[error("{0}")]
    JsonDataError(String),
    #[error("Expected request with `Content-Type: application/json`")]
    MissingJsonContentType,
    #[error("Failed to buffer the request body")]
    FailedToBufferContent,
    #[error("The path parameters couldn't be deserialized because of: {0}")]
    FailedToDeserializePathParams(String),
    #[error("No paths parameters found for matched route")]
    MissingPathParams,
    #[error("The query parameters couldn't be deserialized because of: {0}")]
    FailedToDeserializeQuery(String),
}

// todo: go through all errors and make sure they have proper status codes
impl ApiError {
    #[allow(clippy::match_same_arms)]
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // ApiError::Test => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidLogin => StatusCode::UNAUTHORIZED,
            Self::PasswordHashing(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserAlreadyExists => StatusCode::BAD_REQUEST,
            Self::UnknownAlt(_) | Self::Unknown(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::EmailError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::RedisError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::SystemTimeError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidOTPCode(_) => StatusCode::BAD_REQUEST,
            Self::InvalidTOTPCode(_) => StatusCode::BAD_REQUEST,
            Self::TOTPIsRequired => StatusCode::UNAUTHORIZED,
            Self::Teapot => StatusCode::IM_A_TEAPOT,
            Self::TOTPIsAlreadyEnabled => StatusCode::BAD_REQUEST,
            Self::YouAreNotLoggedIn => StatusCode::UNAUTHORIZED,
            Self::InvalidRecoveryCode(_) => StatusCode::BAD_REQUEST,
            Self::UsedRecoveryCode(_) => StatusCode::BAD_REQUEST,
            Self::TOTPIsNotEnabled => StatusCode::BAD_REQUEST,
            Self::OTPRecoveryFlowNotFound => StatusCode::NOT_FOUND,
            Self::TOTPFlowNotFound => StatusCode::NOT_FOUND,
            Self::EmailIsNotVerified => StatusCode::UNAUTHORIZED,
            Self::EmailIsAlreadyVerified => StatusCode::CONFLICT,
            Self::InvalidEmailVerification => StatusCode::BAD_REQUEST,
            Self::InvalidAuthentication => StatusCode::UNAUTHORIZED,
            Self::FailedParsingScopes(_) => StatusCode::BAD_REQUEST,
            Self::OAuthAppNotFound(_) => StatusCode::NOT_FOUND,
            Self::OAuthAppNotOwned(_) => StatusCode::FORBIDDEN,
            Self::OAuthAppEmptyScopes => StatusCode::BAD_REQUEST,
            Self::OAuthAuthorizationNotFound(_) => StatusCode::NOT_FOUND,
            Self::SudoIsNotEnabled => StatusCode::UNAUTHORIZED,
            Self::SudoIsAlreadyEnabled => StatusCode::BAD_REQUEST,
            Self::SudoCannotBeEnabled => StatusCode::FORBIDDEN,
            Self::TOTPExchangeNotFound(_) => StatusCode::NOT_FOUND,
            Self::OTPExchangeNotFound(_) => StatusCode::NOT_FOUND,
            Self::SessionDoesNotExist(_) => StatusCode::NOT_FOUND,
            Self::FailedParsingURL(_) => StatusCode::BAD_REQUEST,
            Self::OAuthInvalidUri => StatusCode::BAD_REQUEST,
            Self::PasswordDoesNotMatch => StatusCode::BAD_REQUEST,
            Self::PasswordLowStrength => StatusCode::BAD_REQUEST,
            Self::RecoveryLinkNotFound => StatusCode::NOT_FOUND,
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
            Self::JsonDataError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::MissingJsonContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::FailedToBufferContent => StatusCode::INTERNAL_SERVER_ERROR,
            Self::FailedToDeserializePathParams(_) => StatusCode::BAD_REQUEST,
            Self::MissingPathParams => StatusCode::INTERNAL_SERVER_ERROR,
            Self::FailedToDeserializeQuery(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        tracing::error!("HTTP Error was thrown: {:?}", self);
        let error = HttpError {
            message: self.to_string(),
            error: self.into(),
        };

        (status, Json(error)).into_response()
    }
}
