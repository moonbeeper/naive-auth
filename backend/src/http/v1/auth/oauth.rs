use std::{str::FromStr, sync::Arc};

use argon2::{Argon2, PasswordHash, PasswordVerifier as _};
use axum::{
    Extension,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse as _, Redirect, Response},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;
use url::Url;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::{Validate, ValidateLength, ValidateUrl};

use crate::{
    auth::{
        middleware::AuthContext,
        oauth::{
            OauthError, OauthErrorKind, OauthHttpError, OauthHttpResult, ops::create_token,
            scopes::OauthScope,
        },
        ops::{build_cookie, delete_cookie, remove_session},
        ticket::OauthTicket,
    },
    database::{
        models::{
            oauth::{OauthApp, OauthAppId, OauthAuthorized},
            user::{User, UserId},
        },
        redis::models::{
            FlowId,
            oauth::{OauthFlow, OauthFlowKey},
        },
        string_id::StringId,
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::{
        HttpResult, OAUTH_TAG,
        error::{ApiError, ApiHttpError},
        validation::{Form, Json, Query},
    },
};

// I sadly figured out late that I couldn't use Validator for this because... well, I don't know why now. great job me

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(authorize))
        .routes(routes!(exchange))
        .routes(routes!(get_info))
        .routes(routes!(finish_authorize))
}

// enforces use of only "code" via mr serde
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OauthResponseType {
    Code,
    Token,
    #[serde(rename = "token code")] // I hate this
    Hybrid,
    #[serde(rename = "code token")]
    Hybrid2,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, ToSchema)]
pub enum CodeChallengeMethod {
    S256,
    #[serde(rename = "plain")]
    Plain,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Validate, ToSchema, utoipa::IntoParams)]
pub struct Authorize {
    /// The OAuth response type, must be code!
    response_type: OauthResponseType,
    /// The OAuth client ID
    // #[validate(length(equal = 32))]
    client_id: OauthAppId,
    /// The redirect after authorization
    // #[validate(url)]
    redirect_uri: Option<String>,
    /// The requested scopes, space separated. If not provided, the OAuth app default scopes will be used
    scope: Option<String>,
    /// The state to be returned back after authorization
    state: Option<String>,
    /// PKCE code challenge, 43 characters, base64url encoded
    // #[validate(length(equal = 43))]
    code_challenge: String,
    /// PKCE challenge method, must be S256!
    code_challenge_method: CodeChallengeMethod,
}

// #[derive(Debug, serde::Serialize, ToSchema)]
// pub struct AuthorizeResponse {
//     link_id: FlowId,
//     scopes: Vec<String>,
// }

/// Start the OAuth authorization request
///
/// Starts the OAuth authorization by first validating the request and then appending a temporary cookie with the
/// necessary information to continue the process. If the user has already authorized the app with the requested scopes,
/// it will skip the consent prompt and redirect the user to the client's callback with the code directly.
#[utoipa::path(
    get,
    path = "/authorize",
    params(Authorize),
    responses(
        (status = 303, description = "Redirect to consent prompt or already authorized (redirected to client)"),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 400, description = "OAuth error, validation or parsing error", body = OauthHttpError),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn authorize(
    State(global): State<Arc<GlobalState>>,
    Query(request): Query<Authorize>,
    cookies: Cookies,
    Extension(auth_context): Extension<AuthContext>,
) -> OauthHttpResult<Response> {
    if !auth_context.is_authenticated() {
        // sadly, its hardcoded to my own frontend lol
        return Ok(Redirect::to(&global.settings.http.frontend_url).into_response());
        // return Err(ApiError::YouAreNotLoggedIn.into());
    }

    if request.response_type != OauthResponseType::Code {
        return Err(OauthErrorKind::UnsupportedResponseType.into());
    }

    if request.code_challenge_method != CodeChallengeMethod::S256 {
        return Err(OauthErrorKind::UnsupportedCodeChallengeMethod.into());
    }

    if !request.client_id.validate_length(None, None, Some(32))
        || !request.redirect_uri.validate_url()
        || !request.code_challenge.validate_length(None, None, Some(43))
    {
        return Err(OauthErrorKind::InvalidRequest.into());
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin.into());
    };

    let Some(client) = OauthApp::get(&request.client_id, &global.database).await? else {
        return Err(OauthErrorKind::InvalidClient.into());
    };

    let redirect_uri = match request.redirect_uri {
        Some(ref uri) => {
            validate_uri(uri, &client.callback_url)?;
            uri.clone()
        }
        None => client.callback_url,
    };

    let requested_scopes = request.scope.as_deref().unwrap_or("user");

    let requested_scopes = OauthScope::from_str(requested_scopes).map_err(|e| {
        OauthErrorKind::FailedParsingScopes(e)
            .with_redirect(request.state.clone(), Some(redirect_uri.clone()))
    })?;
    let client_scopes = OauthScope::from(client.scopes);
    if !client_scopes.contains(requested_scopes) {
        return Err(OauthErrorKind::InvalidScope.with_state(request.state.clone()));
    }

    let authorized = OauthAuthorized::get_app(&client.id, &global.database).await?;
    let is_upgrade = matches!(authorized, Some(ref item) if !OauthScope::from(item.scopes).contains(requested_scopes));

    match authorized {
        Some(item) if OauthScope::from(item.scopes).contains(requested_scopes) => {
            let mut tx = global.database.begin().await?;
            item.update(&mut tx).await?; // update the date in the updated_at field (lol)
            tx.commit().await?;

            let email = AuthEmails::OauthApproved {
                login: user.login.clone(),
                app_name: client.name,
                scopes: OauthScope::from(item.scopes).to_string(),
                is_upgrade,
                is_reauthorize: true,
            };
            global.mailer.send(&user.email, email).await?;

            Ok(create_token_request(
                client.id,
                redirect_uri,
                requested_scopes.bits(),
                request.state,
                request.code_challenge,
                is_upgrade,
                auth_context.user_id(),
                &global,
            )
            .await?
            .into_response())
        }
        _ => {
            let flow_id = FlowId::new();
            let flow_key = OauthFlowKey::UserFlow {
                flow_id,
                user_id: auth_context.user_id(),
            };

            OauthFlow::AuthorizeRequest {
                client_id: client.id,
                redirect_uri,
                state: request.state,
                scopes: requested_scopes.bits(),
                code_challenge: request.code_challenge,
                is_upgrade,
            }
            .store(flow_key, &global.redis)
            .await?;

            let duration = chrono::Duration::minutes(5);
            let token = OauthTicket::new(auth_context.user_id(), flow_id, duration)
                .generate(&global.settings)?;

            let cookie = build_cookie(
                global.settings.oauth.cookie_name.clone(),
                duration.num_seconds(),
                global.settings.http.secure_cookies,
                token,
            );
            cookies.add(cookie);

            Ok(
                Redirect::to(&format!("{}/authorize", global.settings.http.frontend_url))
                    .into_response(),
            )
        }
    }
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct OauthInformation {
    id: OauthAppId,
    name: String,
    scopes: Vec<String>,
    redirect_uri: String,
}

/// Get information about the current OAuth authorization request
///
/// Its used to get the info about the app and requested scopes before approving or denying the request without
/// consuming the authorization flow. To be able to use it, the user must have a previously started the authorization
/// flow.
///
/// If the request has new scopes that the user has not approved yet, they won't be added until the oauth client has
/// exchanged the code response for a access token. That also means that the user's authorized app won't be updated.
// NOTE: The big use of OauthFlowNotFound is primarily to simplify the way that it'll be handled on the frontend
#[utoipa::path(
    get,
    path = "/context",
    responses(
        (status = 200, description = "Information about the current OAuth2 authorization", body=OauthInformation),
        (status = 401, description = "Not authenticated", body = ApiHttpError),
        (status = 404, description = "OAuth authorization flow was not found", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn get_info(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
    cookies: Cookies,
) -> HttpResult<Json<OauthInformation>> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn);
    }

    // isn't this redundant? like I already check if the user exists in the auth context middleware. Because the session
    // would not exist if the user was deleted.
    // let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
    //     remove_session(auth_context, &cookies, &global).await?;
    //     return Err(ApiError::InvalidLogin.into());
    // };

    let Some(cookie) = cookies.get(&global.settings.oauth.cookie_name) else {
        return Err(ApiError::OauthFlowNotFound);
    };

    let Ok(ticket) = OauthTicket::validate(cookie.value_trimmed(), &global.settings) else {
        return Err(ApiError::OauthFlowNotFound);
    };

    if auth_context.user_id() != ticket.user_id {
        return Err(ApiError::OauthFlowNotFound);
    }

    let flow_key = OauthFlowKey::UserFlow {
        flow_id: ticket.flow_id,
        user_id: auth_context.user_id(),
    };
    let flow = OauthFlow::get(flow_key.clone(), &global.redis).await?;

    if let Some(OauthFlow::AuthorizeRequest {
        client_id,
        redirect_uri,
        scopes,
        ..
    }) = flow
    {
        let Some(client) = OauthApp::get(&client_id, &global.database).await? else {
            // you need to remove the flow if the client is actually gone. am so cleaver god dammit
            OauthFlow::remove(flow_key, &global.redis).await?;
            return Err(ApiError::OauthFlowNotFound);
        };
        let legible_scopes = OauthScope::from(scopes).as_vec();
        // println!("legible scopes: {legible_scopes:?}");

        Ok(Json(OauthInformation {
            id: client.id,
            name: client.name,
            scopes: legible_scopes,
            redirect_uri,
        }))
    } else {
        cookies.add(delete_cookie(
            global.settings.oauth.cookie_name.clone(),
            global.settings.http.secure_cookies,
        ));
        Err(ApiError::OauthFlowNotFound)
    }
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct FinishAuthorize {
    /// Whether to authorize or deny the request
    authorize: bool,
}

#[derive(Debug, serde::Serialize, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    #[default]
    Bearer,
    #[serde(rename = "mac")]
    _Mac, // never will use this
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct AuthorizeResponse {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#name-authorization-response
    iss: String,
}

/// Finish a OAuth authorization request
///
/// Finish the OAuth authorization request by approving or denying it. If approved, the user will be redirected to the
/// client's callback. This consumes the authorization flow, so it cannot be used again.
// NOTE: removed unnecessary use of OauthErrorKind when you could just use ApiError to be able to handle it better on
// the frontend.
#[utoipa::path(
    post,
    path = "/authorize",
    request_body = FinishAuthorize,
    responses(
        (status = 303, description = "OAuth authorization approved"),
        (status = 401, description = "Not authenticated or access denied by the user"),
        (status = 400, description = "OAuth error, validation or parsing error"),
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OAUTH_TAG
)]
async fn finish_authorize(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
    cookies: Cookies,
    Form(request): Form<FinishAuthorize>,
) -> OauthHttpResult<Response> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn.into());
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin.into());
    };

    let Some(cookie) = cookies.get(&global.settings.oauth.cookie_name) else {
        return Err(ApiError::OauthFlowNotFound.into());
    };

    let Ok(ticket) = OauthTicket::validate(cookie.value_trimmed(), &global.settings) else {
        return Err(ApiError::OauthFlowNotFound.into());
    };

    if auth_context.user_id() != ticket.user_id {
        return Err(ApiError::OauthFlowNotFound.into());
    }

    let flow_key = OauthFlowKey::UserFlow {
        flow_id: ticket.flow_id,
        user_id: auth_context.user_id(),
    };
    let flow = OauthFlow::get(flow_key.clone(), &global.redis).await?;

    if let Some(OauthFlow::AuthorizeRequest {
        client_id,
        redirect_uri,
        state,
        scopes: scope,
        code_challenge,
        is_upgrade,
    }) = flow
    {
        OauthFlow::remove(flow_key, &global.redis).await?;
        cookies.remove(global.settings.oauth.cookie_name.clone().into());

        let Some(client) = OauthApp::get(&client_id, &global.database).await? else {
            return Err(ApiError::OAuthAppNotFound(client_id.to_string()).into());
        };

        if request.authorize {
            let email = AuthEmails::OauthApproved {
                login: user.login.clone(),
                app_name: client.name,
                scopes: OauthScope::from(scope).to_string(),
                is_upgrade,
                is_reauthorize: false,
            };
            global.mailer.send(&user.email, email).await?;

            Ok(create_token_request(
                client.id,
                redirect_uri,
                scope,
                state,
                code_challenge,
                is_upgrade,
                auth_context.user_id(),
                &global,
            )
            .await?
            .into_response())
        } else {
            // This redirects the user to the client's callback url with the error code and other params
            Err(OauthErrorKind::AccessDenied.with_redirect(state, Some(redirect_uri)))
        }
    } else {
        Err(ApiError::OauthFlowNotFound.into())
    }
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq, ToSchema)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ExchangeRequest {
    // I some times hate clippy's demands, but seems like swagger likes double ``
    /// The OAuth grant type, must be `authorization_code`
    grant_type: GrantType,
    /// The OAuth code received
    // #[validate(length(equal = 32))]
    code: StringId,
    /// The redirect url requested when authorizing, must match exactly to the one used when authorizing
    // #[validate(url)]
    redirect_uri: Option<String>,
    /// The OAuth app client ID
    // #[validate(length(equal = 32))]
    client_id: OauthAppId,
    /// The OAuth app client secret
    // #[validate(length(equal = 52))]
    client_secret: String,
    /// The origin random string that was used to create the code challenge
    // #[validate(length(min = 43, max = 128))]
    code_verifier: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ExchangeResponse {
    access_token: String,
    token_type: TokenType,
    scope: String,
}

/// Exchange a OAuth code for a access token
///
/// Exchanges a previously obtained OAuth code for an access token to be used in future requests. The token will be
/// valid until the user revokes the authorization or the OAuth app is deleted. The code will be consumed after
/// the first pass of validation, after the second pass (code challenge, etc) it will be consumed and you will need to
/// restart the authorization process from the beginning.
#[utoipa::path(
    post,
    path = "/token",
    request_body = ExchangeRequest,
    responses(
        (status = 200, description = "OAuth token exchanged", body = ExchangeResponse),
        (status = 400, description = "OAuth error, validation or parsing error"), // I don't know if I need to be more descriptive
        (status = 422, description = "Missing required fields", body = ApiHttpError),
    ),
    tag = OAUTH_TAG,
    operation_id = "authOauthToken"
)]
async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Form(request): Form<ExchangeRequest>,
) -> OauthHttpResult<Response> {
    if request.grant_type != GrantType::AuthorizationCode {
        return Err(OauthErrorKind::UnsupportedGrantType.into());
    }

    if !request.code.validate_length(None, None, Some(32))
        || !request.redirect_uri.validate_url()
        || !request.client_id.validate_length(None, None, Some(32))
        || !request.client_secret.validate_length(None, None, Some(52))
        || !request
            .code_verifier
            .validate_length(Some(43), Some(128), None)
    {
        return Err(OauthErrorKind::InvalidRequest.into());
    }

    let flow_key = OauthFlowKey::Code(request.code);
    let flow = OauthFlow::get(flow_key.clone(), &global.redis).await?;

    if let Some(OauthFlow::TokenRequest {
        client_id,
        redirect_uri,
        scopes,
        code_challenge,
        is_upgrade,
        user_id,
    }) = flow
    {
        OauthFlow::remove(flow_key, &global.redis).await?;
        let Some(user) = User::get(user_id, &global.database).await? else {
            return Err(OauthErrorKind::InvalidExchangeId.into());
        };

        let hashed_challenge =
            BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(request.code_verifier.as_bytes()));

        if hashed_challenge != code_challenge {
            return Err(OauthErrorKind::InvalidGrant.into());
        }

        if let Some(ref uri) = request.redirect_uri {
            validate_uri(uri, &redirect_uri)?;
        }

        if request.client_id != client_id {
            return Err(OauthErrorKind::InvalidClient.into());
        }

        let Some(client) = OauthApp::get(&request.client_id, &global.database).await? else {
            return Err(OauthErrorKind::InvalidClient.into());
        };

        let argon2 = Argon2::default();
        argon2
            .verify_password(
                request.client_secret.as_bytes(),
                &PasswordHash::new(&client.key)?,
            )
            .map_err(|_| OauthErrorKind::InvalidClient)?;

        let token = create_token();
        let hashed_token = blake3::hash(token.as_bytes()).to_string();

        let mut tx = global.database.begin().await?;

        // perform clean up of old authorizations for this user + app
        if is_upgrade {
            OauthAuthorized::delete_by_app_and_user(client.id.clone(), user.id, &mut tx).await?;
        }

        let model = OauthAuthorized::builder()
            .app(client.id.clone())
            .user_id(user.id) // wtf, why was I using the auth_context here???
            .scopes(scopes)
            .token(hashed_token)
            .build();
        model.insert(&mut tx).await?;

        tx.commit().await?;

        let token = format!("{}_{token}", global.settings.oauth.token_prefix);
        let scopes = OauthScope::from(scopes).to_string();
        let json = Json(ExchangeResponse {
            access_token: token,
            token_type: TokenType::Bearer,
            scope: scopes,
        });

        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

        return Ok((headers, json).into_response());
    }

    Err(OauthErrorKind::InvalidExchangeId.into())
}

fn validate_uri(requested: &str, stored: &str) -> Result<(), OauthErrorKind> {
    let requested = Url::parse(requested).map_err(|_| OauthErrorKind::InvalidRequest)?;
    let stored = Url::parse(stored).map_err(|_| OauthErrorKind::InvalidRequest)?;

    if stored.scheme() == "https" && requested.scheme() != "https" {
        return Err(OauthErrorKind::InvalidRedirectUri);
    }

    if requested.fragment().is_some() {
        return Err(OauthErrorKind::InvalidRedirectUri);
    }

    if is_localhost(&stored) && is_localhost(&requested) {
        if stored.scheme() == requested.scheme()
            && stored.host_str() == requested.host_str()
            && stored.path() == requested.path()
        {
            return Ok(());
        }
    } else if (stored.scheme() == requested.scheme()
        || (requested.scheme() == "https" && stored.scheme() == "http"))
        && stored.host_str() == requested.host_str()
        && stored.path() == requested.path()
        && stored.port_or_known_default() == requested.port_or_known_default()
    {
        return Ok(());
    }

    Err(OauthErrorKind::InvalidRedirectUri)
}

fn is_localhost(uri: &Url) -> bool {
    match uri.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_token_request(
    client_id: OauthAppId,
    redirect_uri: String,
    scopes: i64,
    state: Option<String>,
    code_challenge: String,
    is_upgrade: bool,
    user_id: UserId,
    global: &Arc<GlobalState>,
) -> Result<Redirect, OauthError> {
    let code = StringId::new();
    OauthFlow::TokenRequest {
        client_id,
        redirect_uri: redirect_uri.clone(),
        scopes,
        code_challenge,
        is_upgrade,
        user_id,
    }
    .store(OauthFlowKey::Code(code.clone()), &global.redis)
    .await?;

    let query: String = serde_urlencoded::to_string(AuthorizeResponse {
        code: code.to_string(),
        state,
        iss: global.settings.http.origin.clone(),
    })
    .unwrap_or_default();

    let uri = if redirect_uri.contains('?') {
        format!("{redirect_uri}&{query}")
    } else {
        format!("{redirect_uri}?{query}")
    };
    let uri = Url::parse(&uri).map_err(|_| OauthErrorKind::FailedMakingUrl)?;

    Ok(Redirect::to(uri.to_string().as_str()))
}
