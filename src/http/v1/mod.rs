#![allow(clippy::option_if_let_else)]

use std::sync::Arc;

use axum::{Extension, Json, extract::State, response::IntoResponse};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    auth::{
        middleware::AuthContext,
        oauth::{
            middleware::OauthContext,
            ops::{OauthRequirement, must_oauth},
            scopes::OauthScope,
        },
        ops::{get_user_id, remove_session},
    },
    database::models::user::User,
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

pub mod auth;
pub mod models;
pub mod oauth;
mod session;
mod sudo;
mod totp;

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .nest("/auth", auth::routes())
        .nest("/oauth", oauth::routes())
        .nest("/totp", totp::routes())
        .nest("/session", session::routes())
        .nest("/sudo", sudo::routes())
        .routes(routes!(get_user))
}

/// Get info about the current user authenticated by a session or via a oauth2 token
#[utoipa::path(
    get,
    path = "/user",
    responses(
        (status = 200, description = "User info", body = models::User),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request or login")
    ),
)]
async fn get_user(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Extension(oauth_context): Extension<OauthContext>,
) -> HttpResult<Json<models::User>> {
    let oauth = must_oauth(
        OauthRequirement::Scoped(vec![OauthScope::USER]),
        &oauth_context,
    )?;

    if !oauth && !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let user_id = get_user_id(&auth_context, &oauth_context);
    let Some(user) = User::get(user_id, &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    Ok(Json(models::User::from(user).remove_user(
        !auth_context.is_authenticated()
            && !oauth_context.has_scopes(&vec![OauthScope::USER_EMAIL]),
    )))
}

#[derive(Debug, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(untagged)]
pub enum JsonEither<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> IntoResponse for JsonEither<L, R>
where
    L: serde::Serialize,
    R: serde::Serialize,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Left(l) => Json(l).into_response(),
            Self::Right(r) => Json(r).into_response(),
        }
    }
}

// todo: this really shouldn't be here
pub fn string_trim<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let string = String::deserialize(d)?;
    Ok(string.trim().to_string())
}
