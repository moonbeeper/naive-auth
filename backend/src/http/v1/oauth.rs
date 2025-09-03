use std::{str::FromStr, sync::Arc};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{Extension, extract::State};
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
    http::{
        HttpResult, OAUTH_TAG,
        error::{ApiError, ApiHttpError},
        v1::models,
        validation::{Json, Path, Valid},
    },
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
    /// The name of the OAuth app
    #[schema(example = "My App")]
    #[validate(length(min = 6, max = 32))]
    name: String,
    /// The description of the OAuth app
    #[schema(example = "A description for the oauth app")]
    #[validate(length(max = 256))] // dunno
    description: String,
    /// The scopes the OAuth app can request
    scopes: Vec<String>,
    /// The callback URL for the OAuth app
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
        (status = 200, description = "OAuth app created", body = CreateAppResponse),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OAUTH_TAG,
)]
#[axum::debug_handler]
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
        (status = 200, description = "OAuth app deleted"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "OAuth app not found", body = ApiHttpError),
        (status = 403, description = "OAuth app not owned by the user", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn delete_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<AppParam>>,
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
    /// The new name of the OAuth app
    #[schema(example = "My new OAuth app name")]
    #[validate(length(min = 6, max = 32))]
    name: Option<String>,
    /// The new description of the OAuth app
    #[schema(example = "My new OAuth app description")]
    #[validate(length(max = 256))] // dunno
    description: Option<String>,
    /// The new scopes the OAuth app can request
    scopes: Option<Vec<String>>,
    /// The new callback URL for the OAuth app
    #[schema(example = "https://oauthdebugger.com/debug")]
    #[validate(url)]
    callback_url: Option<String>,
}

/// Update an OAuth app
#[utoipa::path(
    put,
    path = "/apps/{id}",
    request_body = UpdateApp, // seems like utoipa already knows that it should use this struct. but just in case lol
    params(
        ("id" = OauthAppId, description = "The ID of the OAuth app to update")
    ),
    responses(
        (status = 200, description = "OAuth app updated"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "OAuth app not found", body = ApiHttpError),
        (status = 403, description = "OAuth app not owned by the user", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn update_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(param)): Valid<Path<AppParam>>,
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
        (status = 200, description = "A list of the user created OAuth apps", body = [models::OauthApp]),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
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
        (status = 200, description = "A list of the authorized OAuth apps", body = [models::OauthAuthorized]),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
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

/// Delete an authorized OAuth app
#[utoipa::path(
    delete,
    path = "/authorized/{id}",
    params(
        ("id" = OauthAuthorizedId, description = "The ID of the authorized OAuth app to delete")
    ),
    responses(
        (status = 200, description = "Successfully removed authorized OAuth app"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "Authorized OAuth app not found", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
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
        (status = 200, description = "The authorized OAuth app info", body = models::OauthAuthorized),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "Authorized OAuth app not found", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
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
        (status = 200, description = "The OAuth app info", body = models::OauthApp),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "Validation or parsing error", body = ApiHttpError),
        (status = 404, description = "OAuth app not found", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn get_app(
    State(global): State<Arc<GlobalState>>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Path(request)): Valid<Path<AppParam>>,
) -> HttpResult<Json<models::OauthApp>> {
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
        return Err(ApiError::OAuthAppNotFound(request.id.to_string()));
    }

    Ok(Json(models::OauthApp::from(app)))
}
