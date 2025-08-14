use std::sync::Arc;

use axum::{Extension, Json, Router, extract::State, routing::get};
use tower_cookies::Cookies;

use crate::{
    auth::{middleware::AuthContext, ops::remove_session},
    database::models::user::User,
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

mod auth;
pub mod models;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .nest("/auth", auth::routes())
        .route("/user", get(get_user))
}

async fn get_user(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<models::User>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    Ok(Json(models::User::from(user)))
}
