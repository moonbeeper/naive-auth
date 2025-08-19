use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{middleware::AuthContext, ops::remove_session},
    database::models::session::{Session, SessionId},
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(current_session))
        .routes(routes!(list_sessions))
        .routes(routes!(delete_session))
        .routes(routes!(get_session))
}

/// Get the current session
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Your current session", body = models::Session),
        (status = 401, description = "Not authenticated"),
        (status = 400, description = "Invalid login or session")
    ),
    tag = "session"
)]
async fn current_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<models::Session>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    Ok(Json(models::Session::from(session)))
}

/// Get all your open sessions
#[utoipa::path(
    get,
    path = "/list",
    responses(
        (status = 200, description = "List of your open sessions", body = Vec<models::Session>),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "session"
)]
async fn list_sessions(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<Vec<models::TinySession>>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let sessions = Session::list_user_sessions(auth_context.user_id(), &global.database).await?;

    if sessions.is_empty() {
        return Ok(Json(vec![]));
    }

    let sessions: Vec<models::TinySession> = sessions
        .into_iter()
        .map(models::TinySession::from)
        .collect();

    Ok(Json(sessions))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct SessionIdParam {
    #[validate(length(equal = 26))]
    id: SessionId,
}

/// Delete one of your sessions by its ID
#[utoipa::path(
    delete,
    path = "/{id}",
    params(
        ("id" = SessionId, description = "The ID of the Session to delete")
    ),
    responses(
        (status = 200, description = "Successfully deleted the session"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "session"
)]
async fn delete_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Path(request): Path<SessionIdParam>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if !session.is_sudo_enabled() {
        return Err(ApiError::SudoIsNotEnabled); // should be frontend's job to start the sudo flow
    }

    let Some(session) =
        Session::get_by_id_and_user(request.id, auth_context.user_id(), &global.database).await?
    else {
        return Err(ApiError::SessionDoesNotExist(request.id.to_string()));
    };

    let mut tx = global.database.begin().await?;
    Session::delete(session.id, &mut tx).await?;
    tx.commit().await?;

    Ok(())
}

/// Get one of your sessions by its ID
#[utoipa::path(
    get,
    path = "/{id}",
    params(
        ("id" = SessionId, description = "The ID of the Session to get info about")
    ),
    responses(
        (status = 200, description = "The session info", body = Vec<models::TinySession>),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "session"
)]
async fn get_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Path(request): Path<SessionIdParam>,
) -> HttpResult<Json<models::Session>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(session) = Session::get(auth_context.session_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if !session.is_sudo_enabled() {
        return Err(ApiError::SudoIsNotEnabled); // should be frontend's job to start the sudo flow
    }

    let Some(session) =
        Session::get_by_id_and_user(request.id, auth_context.user_id(), &global.database).await?
    else {
        return Err(ApiError::SessionDoesNotExist(request.id.to_string()));
    };

    Ok(Json(models::Session::from(session)))
}
