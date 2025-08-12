use axum::{Json, response::IntoResponse};
use sqlx::any;

#[derive(Debug, serde::Serialize)]
struct HttpError<'a> {
    pub error: &'a str,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Unexpected Database Error: {0}")]
    Database(#[from] sqlx::Error),
    // #[error("bleh")]
    // Test,
    #[error("Invalid login or password")]
    InvalidUser,
    #[error("Something went wrong while hashing the password: {0}")]
    PasswordHashing(#[from] argon2::password_hash::Error),
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

impl ApiError {
    fn error(&self) -> &'static str {
        match self {
            ApiError::Database(_) => "Database error",
            // ApiError::Test => "test",
            ApiError::InvalidUser => "Invalid login",
            ApiError::PasswordHashing(_) => "Password hashing error",
            ApiError::UserAlreadyExists => "User already exists",
            ApiError::Unknown(_) => "Unknown error",
        }
    }
    fn status_code(&self) -> axum::http::StatusCode {
        match self {
            ApiError::Database(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            // ApiError::Test => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::InvalidUser => axum::http::StatusCode::UNAUTHORIZED,
            ApiError::PasswordHashing(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::UserAlreadyExists => axum::http::StatusCode::BAD_REQUEST,
            ApiError::Unknown(_) => axum::http::StatusCode::IM_A_TEAPOT,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let error = HttpError {
            error: self.error(),
            message: self.to_string(),
        };
        tracing::error!("HTTP Error was thrown: {:?}", self);
        (self.status_code(), Json(error)).into_response()
    }
}
