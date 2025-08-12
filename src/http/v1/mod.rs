use std::sync::Arc;

use axum::Router;

use crate::global::GlobalState;

mod auth;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new().nest("/auth", auth::routes())
}
