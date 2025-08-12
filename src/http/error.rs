use axum::{Json, response::IntoResponse};

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
    Unknown(#[from] anyhow::Error),
}

impl ApiError {
    #[allow(clippy::match_same_arms)]
    const fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::Database(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            // ApiError::Test => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidLogin => axum::http::StatusCode::UNAUTHORIZED,
            Self::PasswordHashing(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserAlreadyExists => axum::http::StatusCode::BAD_REQUEST,
            Self::Unknown(_) => axum::http::StatusCode::IM_A_TEAPOT,
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
