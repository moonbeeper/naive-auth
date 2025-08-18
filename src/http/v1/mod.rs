use std::sync::Arc;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    middleware,
    response::IntoResponse,
    routing::get,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use tower_http::add_extension::AddExtensionLayer;

use crate::{
    auth::{
        middleware::AuthContext,
        oauth::{
            middleware::OauthContext,
            ops::{OauthRequirement, create_token, must_oauth},
            scopes::OauthScope,
        },
        ops::{get_user_id, remove_session},
    },
    database::models::{oauth::OauthApp, user::User},
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

mod auth;
pub mod models;
mod oauth;

pub fn routes() -> Router<Arc<GlobalState>> {
    Router::new()
        .nest("/auth", auth::routes())
        .nest("/oauth", oauth::routes())
        .route("/user", get(get_user))
}

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
    // let token = create_token();
    // println!("aa: {:?}", token);

    // let argon2 = Argon2::default();
    // let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    // let password_hash = argon2.hash_password(token.as_bytes(), &salt)?.to_string();

    // println!("hased: {:?}", password_hash);
    let Some(user) = User::get(user_id, &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    // let mut tx = global.database.begin().await?;
    // OauthApp::builder()
    //     .name("Test App".to_string())
    //     .created_by(user.id)
    //     .description("wawa".to_string())
    //     .key(password_hash)
    //     .callback_url("http://localhost:8080/oauth/callback".to_string())
    //     .scopes(OauthScope::USER.bits())
    //     .build()
    //     .insert(&mut tx)
    //     .await?;
    // tx.commit().await?;
    Ok(Json(models::User::from(user).remove_user(
        !auth_context.is_authenticated()
            && !oauth_context.has_scopes(&vec![OauthScope::USER_EMAIL]),
    )))
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
