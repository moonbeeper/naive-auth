use axum::{
    Json,
    http::Uri,
    response::{IntoResponse, Redirect},
};

use crate::http::error::ApiError;

pub mod middleware;
pub mod ops;
pub mod scopes;

pub type OauthHttpResult<T> = Result<T, OauthError>;

#[derive(Debug, serde::Serialize)]
pub struct OauthHttpError<'a> {
    pub error: &'a str,
    pub error_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OauthErrorKind {
    #[error(
        "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed"
    )]
    InvalidRequest,
    #[error("We sadly have denied your request")]
    AccessDenied,
    // #[error("please change me")]
    // UnauthorizedClient, // unused. maybe useful for disabled clients?
    #[error("The requested scope is invalid, unknown, or malformed")]
    InvalidScope,
    #[error("We do not support obtaining an authorization code using this method")]
    UnsupportedResponseType,
    #[error("The Client ID and/or Secret provided are invalid")]
    InvalidClient,
    #[error(
        "The provided authorization grant is invalid, expired, revoked, or was issued to another client."
    )]
    InvalidGrant,
    #[error("We do not support this grant type")]
    UnsupportedGrantType,
    #[error(transparent)]
    ApiErrorTransparent(#[from] ApiError),
    #[error(
        "Sadly we failed to parse the scopes. It might be malformed or contain invalid values: {0}"
    )]
    FailedParsingScopes(#[from] bitflags::parser::ParseError),
    #[error("The Exchange ID provided is invalid or does not exist on our papers")]
    InvalidExchangeId,
    #[error(
        "Seems like the app's redirect URI has been updated. Your provided one does not match the current one"
    )]
    InvalidRedirectUri,
    #[error("Failed to make a valid URL from the redirect URI")]
    FailedMakingUrl,
    #[error("The Authorize ID provided is invalid or does not exist on our papers")]
    InvalidAuthorizeId,
    #[error("We do not support that code challenge using this method")]
    UnsupportedCodeChallengeMethod,
}

pub struct OauthError {
    kind: OauthErrorKind,
    state: Option<String>,
    redirect_uri: Option<String>,
    // iss: Option<String> I really can't figure out how to give it the issuer in the responses. Its optional tho
}

impl OauthError {
    pub fn with_state(mut self, state: String) -> Self {
        self.state = Some(state);
        self
    }

    pub fn with_redirect(mut self, redirect_uri: String) -> Self {
        self.redirect_uri = Some(redirect_uri);
        self
    }

    // pub fn attach_iss(mut self, iss: String) -> Self {
    //     self.iss = Some(iss);
    // }
}

impl OauthErrorKind {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::AccessDenied => "access_denied",
            // Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidScope | Self::FailedParsingScopes(_) => "invalid_scope",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ApiErrorTransparent(e) => e.into(),
            Self::InvalidExchangeId
            | Self::InvalidRequest
            | Self::InvalidRedirectUri
            | Self::FailedMakingUrl
            | Self::InvalidAuthorizeId
            | Self::UnsupportedCodeChallengeMethod => "invalid_request",
        }
    }

    pub const fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::AccessDenied => axum::http::StatusCode::UNAUTHORIZED,
            // Self::UnauthorizedClient => axum::http::StatusCode::UNAUTHORIZED,
            Self::InvalidScope
            | Self::UnsupportedResponseType
            | Self::InvalidClient
            | Self::UnsupportedGrantType
            | Self::InvalidExchangeId
            | Self::InvalidRequest
            | Self::InvalidRedirectUri
            | Self::FailedMakingUrl
            | Self::InvalidAuthorizeId
            | Self::FailedParsingScopes(_)
            | Self::UnsupportedCodeChallengeMethod
            | Self::InvalidGrant => axum::http::StatusCode::BAD_REQUEST, // dunno if these should be all 400
            Self::ApiErrorTransparent(e) => e.status_code(),
        }
    }

    pub fn error(&self) -> &str {
        match self {
            Self::ApiErrorTransparent(err) => err.into(),
            e => e.error_code(),
        }
    }

    pub fn message(&self) -> String {
        match &self {
            Self::ApiErrorTransparent(err) => err.to_string(),
            e => e.to_string(),
        }
    }

    pub const fn status(&self) -> axum::http::StatusCode {
        match &self {
            Self::ApiErrorTransparent(err) => err.status_code(),
            e => e.status_code(),
        }
    }

    pub const fn with_state(self, state: Option<String>) -> OauthError {
        OauthError {
            kind: self,
            state,
            redirect_uri: None,
        }
    }

    pub const fn with_redirect(
        self,
        state: Option<String>,
        redirect_uri: Option<String>,
    ) -> OauthError {
        OauthError {
            kind: self,
            state,
            redirect_uri,
        }
    }
}

impl From<ApiError> for OauthError {
    fn from(value: ApiError) -> Self {
        Self {
            kind: OauthErrorKind::ApiErrorTransparent(value),
            state: None,
            redirect_uri: None,
        }
    }
}

impl From<OauthErrorKind> for OauthError {
    fn from(value: OauthErrorKind) -> Self {
        Self {
            kind: value,
            state: None,
            redirect_uri: None,
        }
    }
}

impl IntoResponse for OauthError {
    fn into_response(self) -> axum::response::Response {
        if let Some(uri) = self.redirect_uri {
            let mut params = vec![
                ("error", self.kind.error().to_string()),
                ("error_description", self.kind.message()),
            ];
            if let Some(state) = &self.state {
                params.push(("state", state.clone()));
            }
            let query: String = serde_urlencoded::to_string(params).unwrap_or_default();

            let redirect_url = if uri.contains('?') {
                format!("{uri}&{query}")
            } else {
                format!("{uri}?{query}")
            };
            if let Ok(uri) = Uri::try_from(redirect_url) {
                // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#name-http-307-redirect
                return Redirect::to(uri.to_string().as_str()).into_response();
            }
        }
        let status = self.kind.status();
        let message = self.kind.message();
        let error = self.kind.error();

        let error = OauthHttpError {
            error,
            error_description: message,
            state: self.state,
        };
        (status, Json(error)).into_response()
    }
}

// i hate you
impl From<sqlx::Error> for OauthError {
    fn from(value: sqlx::Error) -> Self {
        ApiError::from(value).into()
    }
}

impl From<crate::database::redis::models::RedisError> for OauthError {
    fn from(value: crate::database::redis::models::RedisError) -> Self {
        ApiError::from(value).into()
    }
}

impl From<argon2::password_hash::Error> for OauthError {
    fn from(value: argon2::password_hash::Error) -> Self {
        ApiError::from(value).into()
    }
}

impl From<anyhow::Error> for OauthError {
    fn from(value: anyhow::Error) -> Self {
        ApiError::from(value).into()
    }
}
