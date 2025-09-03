use std::sync::Arc;

use axum::{Extension, extract::State};
use tower_cookies::Cookies;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{middleware::AuthContext, ops::remove_session},
    database::models::session::{Session, SessionId},
    global::GlobalState,
    http::{
        HttpResult, SESSION_TAG,
        error::{ApiError, ApiHttpError},
        v1::models,
        validation::{Json, Path, Valid},
    },
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(current_session))
        .routes(routes!(list_sessions))
        .routes(routes!(delete_session))
        .routes(routes!(get_session))
        .routes(routes!(delete_all_sessions))
}

/// Get the current session
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Your current session", body = models::Session),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
    ),
    tag = SESSION_TAG
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
        (status = 200, description = "A list of the your open sessions", body = Vec<models::Session>),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
    ),
    tag = SESSION_TAG
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

/// Delete one of your sessions
#[utoipa::path(
    delete,
    path = "/{id}",
    params(
        ("id" = SessionId, description = "The ID of the Session to delete")
    ),
    responses(
        (status = 200, description = "Successfully deleted the session"),
        (status = 401, description = "Not authenticated or Sudo is not enabled", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "Session not found", body = ApiHttpError),
    ),
    tag = SESSION_TAG
)]
async fn delete_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<SessionIdParam>>,
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

/// Get info about one of your open sessions
#[utoipa::path(
    get,
    path = "/{id}",
    params(
        ("id" = SessionId, description = "The ID of the Session to get info about")
    ),
    responses(
        (status = 200, description = "The session info", body = Vec<models::TinySession>),
        (status = 401, description = "Not authenticated or Sudo is not enabled", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "Session not found", body = ApiHttpError),
    ),
    tag = SESSION_TAG
)]
async fn get_session(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<SessionIdParam>>,
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

// TODO: maybe add sudo check here?
// I was thinking to make it require Sudo. I'll think about it.
/// Delete all your open sessions
#[utoipa::path(
    delete,
    path = "/all",
    responses(
        (status = 200, description = "Deleted all open sessions"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
    ),
    tag = SESSION_TAG
)]
async fn delete_all_sessions(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let mut tx = global.database.begin().await?;
    Session::delete_all_by_user(auth_context.user_id(), &mut tx).await?;
    tx.commit().await?;

    Ok(())
}
