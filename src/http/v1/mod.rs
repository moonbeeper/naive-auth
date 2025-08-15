use std::sync::Arc;

use axum::{Extension, Json, Router, extract::State, response::IntoResponse, routing::get};
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

// I don't know where to put this lol
struct JsonEither<L, R>(either::Either<Json<L>, Json<R>>);

impl<L, R> IntoResponse for JsonEither<L, R>
where
    Json<L>: IntoResponse,
    Json<R>: IntoResponse,
{
    fn into_response(self) -> axum::response::Response {
        match self.0 {
            either::Either::Left(data) => data.into_response(),
            either::Either::Right(data) => data.into_response(),
        }
    }
}

impl<L, R> JsonEither<L, R> {
    pub const fn left(data: L) -> Self {
        Self(either::Either::Left(Json(data)))
    }
    pub const fn right(data: R) -> Self {
        Self(either::Either::Right(Json(data)))
    }
}
