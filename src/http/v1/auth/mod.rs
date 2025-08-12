use std::sync::Arc;

use axum::{Extension, Router, extract::State, routing::get};

use crate::{auth::middleware::AuthContext, global::GlobalState};

mod password;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .route("/", get(index))
        .merge(password::routes())
        .route("/test", get(test))
}

async fn index() -> &'static str {
    "Hello, World!"
}

async fn test(
    State(_global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
) -> String {
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
