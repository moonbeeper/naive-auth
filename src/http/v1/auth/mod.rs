use std::sync::Arc;

use axum::{Extension, Json, Router, extract::State, routing::get};

use crate::{
    auth::middleware::AuthContext,
    database::models::session::Session,
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

mod password;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/", get(index))
        .merge(password::routes())
        .route("/current", get(current_session))
        .route("/sessions", get(list_sessions))
}

async fn index() -> &'static str {
    "Hello, World!"
}

async fn current_session(Extension(auth_context): Extension<AuthContext>) -> String {
    match auth_context {
        AuthContext::Authenticated {
            user_id,
            session_id,
        } => {
            format!("user_id: {user_id}, session_id: {session_id}")
        }
        AuthContext::NotAuthenticated => "not authenticated".to_string(),
    }
}

async fn list_sessions(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<Vec<models::auth::Session>>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::InvalidLogin);
    }

    let sessions =
        Session::list_user_sessions(auth_context.user_id().unwrap(), &global.database).await?;

    if sessions.is_empty() {
        return Ok(Json(vec![]));
    }

    let sessions: Vec<models::auth::Session> = sessions
        .into_iter()
        .map(models::auth::Session::from)
        .collect();

    Ok(Json(sessions))
}
