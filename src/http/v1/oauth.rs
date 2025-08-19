use std::{str::FromStr, sync::Arc};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{
    Extension, Json,
    extract::{Path, State},
};
use axum_valid::Valid;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
use tower_cookies::Cookies;
use url::Url;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        oauth::{ops::create_token, scopes::OauthScope},
        ops::remove_session,
    },
    database::{
        models::{
            oauth::{OauthApp, OauthAppId, OauthAuthorized, OauthAuthorizedId},
            user::User,
        },
        string_id::StringId,
    },
    global::GlobalState,
    http::{HttpResult, error::ApiError, v1::models},
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    // i hate this
    OpenApiRouter::new()
        .routes(routes!(create_app))
        .routes(routes!(delete_app))
        .routes(routes!(update_app))
        .routes(routes!(get_app))
        .routes(routes!(list_apps))
        .routes(routes!(list_authorized))
        .routes(routes!(remove_authorized))
        .routes(routes!(get_authorized))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
struct CreateApp {
    #[schema(example = "My App")]
    #[validate(length(min = 6, max = 32))]
    name: String,
    #[schema(example = "A description for the oauth app")]
    #[validate(length(max = 256))] // dunno
    description: String,
    scopes: Vec<String>,
    #[schema(example = "https://oauthdebugger.com/debug")]
    #[validate(url)]
    callback_url: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
struct CreateAppResponse {
    id: StringId,
    secret_key: String,
}

/// Create a new OAuth app
#[utoipa::path(
    post,
    path = "/apps",
    request_body = CreateApp,
    responses(
        (status = 200, description = "App created", body = CreateAppResponse),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn create_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Json(request)): Valid<Json<CreateApp>>,
) -> HttpResult<Json<CreateAppResponse>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    if request.scopes.is_empty() {
        return Err(ApiError::OAuthAppEmptyScopes);
    }

    let scopes = OauthScope::from_str(&request.scopes.join(","))?;
    if scopes.bits() == 0 {
        return Err(ApiError::OAuthAppEmptyScopes);
    }

    let token = create_token();
    let id = StringId::new();
    let uri = Url::parse(&request.callback_url)?;
    if uri.fragment().is_some() {
        return Err(ApiError::OAuthInvalidUri);
    }

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut ChaCha20Rng::from_entropy());
    let token_hash = argon2.hash_password(token.as_bytes(), &salt)?.to_string();

    let mut tx = global.database.begin().await?;
    OauthApp::builder()
        .id(id.clone())
        .name(request.name)
        .created_by(user.id)
        .description(request.description)
        .key(token_hash.clone())
        .callback_url(request.callback_url)
        .scopes(scopes.bits())
        .build()
        .insert(&mut tx)
        .await?;
    tx.commit().await?;

    Ok(Json(CreateAppResponse {
        id,
        secret_key: token,
    }))
}

// i love axum_valid. i dont need to manually do validations haha
#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
struct AppParam {
    #[validate(length(equal = 32))]
    id: OauthAppId,
}

/// Delete an OAuth app by its ID
#[utoipa::path(
    delete,
    path = "/apps/{id}",
    params(
        ("id" = OauthAppId, description = "The ID of the OAuth app to delete")
    ),
    responses(
        (status = 200, description = "App deleted"),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn delete_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Path(request): Path<AppParam>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(app) = OauthApp::get(&request.id, &global.database).await? else {
        return Err(ApiError::OAuthAppNotFound(request.id.to_string()));
    };

    if app.created_by != user.id {
        return Err(ApiError::OAuthAppNotOwned(request.id.to_string()));
    }

    let mut tx = global.database.begin().await?;
    OauthApp::delete(&request.id, &mut tx).await?;
    tx.commit().await?;

    Ok(())
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
struct UpdateApp {
    // #[validate(length(equal = 32))]
    // id: OauthAppId,
    #[validate(length(min = 6, max = 32))]
    name: Option<String>,
    #[validate(length(max = 256))] // dunno
    description: Option<String>,
    scopes: Option<Vec<String>>,
    #[validate(url)]
    callback_url: Option<String>,
}

/// Update an OAuth app by its ID
#[utoipa::path(
    put,
    path = "/apps/{id}",
    params(
        ("id" = OauthAppId, description = "The ID of the OAuth app to update")
    ),
    responses(
        (status = 200, description = "App updated"),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn update_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Path(param): Path<AppParam>,
    Valid(Json(request)): Valid<Json<UpdateApp>>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(mut app) = OauthApp::get(&param.id, &global.database).await? else {
        return Err(ApiError::OAuthAppNotFound(param.id.to_string()));
    };

    if app.created_by != user.id {
        return Err(ApiError::OAuthAppNotOwned(param.id.to_string()));
    }

    if let Some(name) = request.name {
        app.name = name;
    }
    if let Some(description) = request.description {
        app.description = Some(description);
    }
    if let Some(scopes) = request.scopes {
        if scopes.is_empty() {
            return Err(ApiError::OAuthAppEmptyScopes);
        }

        let scopes = OauthScope::from_str(&scopes.join(","))?;
        if scopes.bits() == 0 {
            return Err(ApiError::OAuthAppEmptyScopes);
        }

        app.scopes = scopes.bits();
    }
    if let Some(callback_url) = request.callback_url {
        app.callback_url = callback_url;
    }
    let mut tx = global.database.begin().await?;
    OauthApp::delete(&param.id, &mut tx).await?;
    tx.commit().await?;

    Ok(())
}

/// List current user created OAuth apps
#[utoipa::path(
    get,
    path = "/apps",
    responses(
        (status = 200, description = "List user created oauth apps", body = [models::OauthApp]),
        (status = 401, description = "Not logged in")
    ),
    tag = "oauth"
)]
async fn list_apps(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<Vec<models::OauthApp>>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let apps = OauthApp::get_many_by_userid(user.id, &global.database).await?;
    let apps: Vec<_> = apps.into_iter().map(models::OauthApp::from).collect();

    Ok(Json(apps))
}

/// List current user authorized OAuth apps
#[utoipa::path(
    get,
    path = "/authorized",
    responses(
        (status = 200, description = "List user's authorized oauth apps", body = [models::OauthAuthorized]),
        (status = 401, description = "Not logged in")
    ),
    tag = "oauth"
)]
async fn list_authorized(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> HttpResult<Json<Vec<models::OauthAuthorized>>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let apps = OauthAuthorized::get_many_by_userid(user.id, &global.database).await?;
    let apps: Vec<_> = apps
        .into_iter()
        .map(models::OauthAuthorized::from)
        .collect();

    Ok(Json(apps))
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
struct AuthorizedParam {
    #[validate(length(equal = 26))]
    id: OauthAuthorizedId,
}

/// Delete an authorized OAuth app by its id
#[utoipa::path(
    delete,
    path = "/authorized/{id}",
    params(
        ("id" = OauthAuthorizedId, description = "The ID of the authorized OAuth app to delete")
    ),
    responses(
        (status = 200, description = "Authorization removed"),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn remove_authorized(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<AuthorizedParam>>,
) -> HttpResult<()> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(app) = OauthAuthorized::get(request.id, &global.database).await? else {
        return Err(ApiError::OAuthAuthorizationNotFound(request.id.to_string()));
    };

    if app.user_id != user.id {
        return Err(ApiError::OAuthAuthorizationNotFound(request.id.to_string()));
    }

    let mut tx = global.database.begin().await?;
    OauthAuthorized::delete(request.id, &mut tx).await?;
    tx.commit().await?;

    Ok(())
}

/// Get info about an authorized OAuth app
#[utoipa::path(
    get,
    path = "/authorized/{id}",
    params(
        ("id" = OauthAuthorizedId, description = "The ID of the authorized OAuth app to get")
    ),
    responses(
        (status = 200, description = "Get authorized app", body = models::OauthAuthorized),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn get_authorized(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<AuthorizedParam>>,
) -> HttpResult<Json<models::OauthAuthorized>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(app) = OauthAuthorized::get(request.id, &global.database).await? else {
        return Err(ApiError::OAuthAuthorizationNotFound(request.id.to_string()));
    };

    if app.user_id != user.id {
        return Err(ApiError::OAuthAuthorizationNotFound(request.id.to_string()));
    }

    Ok(Json(models::OauthAuthorized::from(app)))
}

/// Get info about an OAuth app you created
#[utoipa::path(
    get,
    path = "/apps/{id}",
    params(
        ("id" = OauthAppId, description = "The ID of the OAuth app to retrieve")
    ),
    responses(
        (status = 200, description = "Get authorized app", body = models::OauthApp),
        (status = 401, description = "Not logged in"),
        (status = 400, description = "Validation or other error")
    ),
    tag = "oauth"
)]
async fn get_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Path(id): Path<OauthAppId>,
) -> HttpResult<Json<models::OauthApp>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }
    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin);
    };

    let Some(app) = OauthApp::get(&id, &global.database).await? else {
        return Err(ApiError::OAuthAppNotFound(id.to_string()));
    };

    if app.created_by != user.id {
        return Err(ApiError::OAuthAppNotFound(id.to_string()));
    }

    Ok(Json(models::OauthApp::from(app)))
}
