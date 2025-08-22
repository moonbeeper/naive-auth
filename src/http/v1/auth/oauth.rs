use std::{str::FromStr, sync::Arc};

use argon2::{Argon2, PasswordHash, PasswordVerifier as _};
use axum::{
    Extension, Form, Json,
    extract::{Query, State},
    response::{IntoResponse as _, Redirect, Response},
};
use axum_valid::Valid;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;
use url::Url;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use validator::Validate;

use crate::{
    auth::{
        middleware::AuthContext,
        oauth::{
            OauthError, OauthErrorKind, OauthHttpResult, ops::create_token, scopes::OauthScope,
        },
        ops::remove_session,
    },
    database::{
        models::{
            oauth::{OauthApp, OauthAppId, OauthAuthorized},
            user::User,
        },
        redis::models::{
            FlowId,
            oauth::{OauthFlow, OauthFlowKey},
        },
        string_id::StringId,
    },
    email::resources::AuthEmails,
    global::GlobalState,
    http::error::ApiError,
};

pub fn routes() -> OpenApiRouter<Arc<GlobalState>> {
    OpenApiRouter::new()
        .routes(routes!(pre_authorize, authorize))
        .routes(routes!(exchange))
}

// enforces use of only "code" via mr serde
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OauthResponseType {
    Code,
    Token,
    #[serde(rename = "token code")]
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
pub struct PreAuthorize {
    response_type: OauthResponseType,
    #[validate(length(equal = 32))]
    client_id: OauthAppId,
    #[validate(url)]
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    #[validate(length(equal = 43))]
    code_challenge: String,
    code_challenge_method: CodeChallengeMethod,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct PreAuthorizeResponse {
    link_id: FlowId,
    scopes: Vec<String>,
}

/// Get the Link ID to be able to authorize or refuse authorization for the OAuth client
#[utoipa::path(
    get,
    path = "/authorize",
    params(PreAuthorize),
    responses(
        (status = 200, description = "Authorization needed", body = PreAuthorizeResponse),
        (status = 400, description = "Invalid request or not authenticated")
    ),
    tag = "oauth"
)]
async fn pre_authorize(
    State(global): State<Arc<GlobalState>>,
    Query(request): Query<PreAuthorize>,
    Extension(auth_context): Extension<AuthContext>,
) -> OauthHttpResult<Response> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn.into());
    }

    if request.response_type != OauthResponseType::Code {
        return Err(OauthErrorKind::UnsupportedResponseType.into());
    }

    if request.code_challenge_method != CodeChallengeMethod::S256 {
        return Err(OauthErrorKind::UnsupportedCodeChallengeMethod.into());
    }

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

    match authorized {
        Some(item) if OauthScope::from(item.scopes).contains(requested_scopes) => {
            let mut tx = global.database.begin().await?;
            item.update(&mut tx).await?; // update created_at
            tx.commit().await?;

            Ok(create_token_request(
                client.id,
                redirect_uri,
                requested_scopes.bits(),
                request.state,
                request.code_challenge,
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
            }
            .store(flow_key, &global.redis)
            .await?;

            Ok(Json(PreAuthorizeResponse {
                link_id: flow_id,
                scopes: requested_scopes.as_vec(),
            })
            .into_response())
        }
    }
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct Authorize {
    #[validate(length(equal = 26))]
    link_id: FlowId,
    authorize: bool,
}

#[derive(Debug, serde::Serialize, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    #[default]
    Bearer,
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

/// Exchange the Link ID to authorize or refuse authorizing a OAuth client
#[utoipa::path(
    post,
    path = "/authorize",
    request_body = Authorize,
    responses(
        (status = 200, description = "Authorization approved", body = AuthorizeResponse),
        (status = 400, description = "Invalid request or not authenticated")
    ),
    tag = "oauth"
)]
async fn authorize(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
    cookies: Cookies,
    Valid(Json(request)): Valid<Json<Authorize>>,
) -> OauthHttpResult<Response> {
    if !auth_context.is_authenticated() {
        return Err(ApiError::YouAreNotLoggedIn.into());
    }

    let Some(user) = User::get(auth_context.user_id(), &global.database).await? else {
        remove_session(auth_context, &cookies, &global).await?;
        return Err(ApiError::InvalidLogin.into());
    };

    let flow_key = OauthFlowKey::UserFlow {
        flow_id: request.link_id,
        user_id: auth_context.user_id(),
    };
    let flow = OauthFlow::get(flow_key.clone(), &global.redis).await?;

    if let Some(OauthFlow::AuthorizeRequest {
        client_id,
        redirect_uri,
        state,
        scopes: scope,
        code_challenge,
    }) = flow
    {
        OauthFlow::remove(flow_key, &global.redis).await?;
        let Some(client) = OauthApp::get(&client_id, &global.database).await? else {
            return Err(OauthErrorKind::InvalidClient.into());
        };

        if request.authorize {
            let email = AuthEmails::OauthApproved {
                login: user.login.clone(),
                app_name: client.name,
                scopes: OauthScope::from(scope).to_string(),
            };

            global.mailer.send(&user.email, email).await?;

            Ok(create_token_request(
                client.id,
                redirect_uri,
                scope,
                state,
                code_challenge,
                &global,
            )
            .await?
            .into_response())
        } else {
            Err(OauthErrorKind::AccessDenied.with_redirect(state, Some(redirect_uri)))
        }
    } else {
        Err(OauthErrorKind::InvalidAuthorizeId.into())
    }
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq, ToSchema)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

#[derive(Debug, serde::Deserialize, Validate, ToSchema)]
pub struct ExchangeRequest {
    grant_type: GrantType,
    #[validate(length(equal = 32))]
    code: StringId,
    #[validate(url)]
    redirect_uri: Option<String>,
    #[validate(length(equal = 32))]
    client_id: OauthAppId,
    #[validate(length(equal = 52))]
    client_secret: String,
    #[validate(length(min = 43, max = 128))]
    code_verifier: String,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ExchangeResponse {
    access_token: String,
    token_type: TokenType,
    scope: String,
}

/// Exchange a code for a Bearer access token
#[utoipa::path(
    post,
    path = "/token",
    request_body = ExchangeRequest,
    responses(
        (status = 200, description = "OAuth token exchanged", body = ExchangeResponse),
        (status = 400, description = "Invalid request or client")
    ),
    tag = "oauth",
    operation_id = "authOauthToken"
)]
async fn exchange(
    State(global): State<Arc<GlobalState>>,
    Extension(auth_context): Extension<AuthContext>,
    Valid(Form(request)): Valid<Form<ExchangeRequest>>,
) -> OauthHttpResult<Json<ExchangeResponse>> {
    if request.grant_type != GrantType::AuthorizationCode {
        return Err(OauthErrorKind::UnsupportedGrantType.into());
    }

    let flow_key = OauthFlowKey::Code(request.code);
    let flow = OauthFlow::get(flow_key.clone(), &global.redis).await?;

    if let Some(OauthFlow::TokenRequest {
        client_id,
        redirect_uri,
        scopes,
        code_challenge,
    }) = flow
    {
        OauthFlow::remove(flow_key, &global.redis).await?;
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
        let model = OauthAuthorized::builder()
            .app(client.id.clone())
            .user_id(auth_context.user_id())
            .scopes(scopes)
            .token(hashed_token)
            .build();
        model.insert(&mut tx).await?;
        tx.commit().await?;

        let token = format!("{}_{token}", global.settings.oauth.token_prefix);
        let scopes = OauthScope::from(scopes).to_string();
        return Ok(Json(ExchangeResponse {
            access_token: token,
            token_type: TokenType::Bearer,
            scope: scopes,
        }));
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
        // TODO: Should have ipv6?
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

async fn create_token_request(
    client_id: OauthAppId,
    redirect_uri: String,
    scopes: i64,
    state: Option<String>,
    code_challenge: String,
    global: &Arc<GlobalState>,
) -> Result<Redirect, OauthError> {
    let code = StringId::new();
    OauthFlow::TokenRequest {
        client_id,
        redirect_uri: redirect_uri.clone(),
        scopes,
        code_challenge,
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

    Ok(Redirect::temporary(uri.to_string().as_str()))
}
