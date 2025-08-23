use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use tower::Service;

use crate::{
    auth::oauth::scopes::OauthScope,
    database::{
        models::{
            oauth::{OauthAuthorized, OauthAuthorizedId},
            user::UserId,
        },
        string_id::StringId,
    },
    global::GlobalState,
    http::{HttpResult, error::ApiError},
};

#[derive(Debug, Clone)]
pub enum OauthContext {
    Some {
        user_id: UserId,
        oauth_app_id: StringId,
        scopes: i64,
        oauth_authorized_id: OauthAuthorizedId,
    },
    None,
    Empty,
}

impl OauthContext {
    pub const fn user_id(&self) -> UserId {
        match self {
            Self::Some { user_id, .. } => *user_id,
            Self::None | Self::Empty => UserId::nil(),
        }
    }

    pub const fn id(&self) -> OauthAuthorizedId {
        match self {
            Self::Some {
                oauth_authorized_id,
                ..
            } => *oauth_authorized_id,
            Self::None | Self::Empty => OauthAuthorizedId::nil(),
        }
    }

    pub fn app_id(&self) -> StringId {
        match self {
            Self::Some { oauth_app_id, .. } => oauth_app_id.clone(),
            Self::None | Self::Empty => StringId::nil(),
        }
    }

    pub const fn raw_scopes(&self) -> i64 {
        match self {
            Self::Some { scopes, .. } => *scopes,
            Self::None | Self::Empty => 0,
        }
    }

    pub fn to_scopes(&self) -> OauthScope {
        OauthScope::from(self.raw_scopes())
    }

    pub fn has_scopes(&self, required_scopes: &Vec<OauthScope>) -> bool {
        match self {
            &Self::Some { scopes, .. } => {
                let scopes = OauthScope::from(scopes);
                let mut required = OauthScope::empty();
                for scope in required_scopes {
                    required.insert(*scope);
                }

                scopes.contains(required)
            }
            Self::None | Self::Empty => false,
        }
    }

    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub const fn is_some(&self) -> bool {
        matches!(self, Self::Some { .. })
    }
}

#[derive(Clone)]
pub struct OauthManagerLayer(Arc<GlobalState>);

impl OauthManagerLayer {
    pub const fn new(global: Arc<GlobalState>) -> Self {
        Self(global)
    }
}

impl<S> tower::Layer<S> for OauthManagerLayer {
    type Service = OauthManagerMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OauthManagerMiddleware {
            inner,
            global: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct OauthManagerMiddleware<S> {
    inner: S,
    global: Arc<GlobalState>,
}

impl<S: Send + Sync + 'static> OauthManagerMiddleware<S> {
    // https://github.com/Owez/axum-auth/blob/master/src/auth_bearer.rs
    async fn do_something(&self, headers: &HeaderMap<HeaderValue>) -> HttpResult<OauthContext> {
        let Some(authorization) = headers.get(AUTHORIZATION) else {
            return Ok(OauthContext::Empty);
        };

        let Ok(authorization) = authorization.to_str() else {
            return Err(ApiError::InvalidAuthentication);
        };

        // Check that its a well-formed bearer and return
        let split = authorization.split_once(' ');
        let header_value = match split {
            // Found proper bearer
            Some(("Bearer", contents)) => contents,
            // Found empty bearer; sometimes request libraries format them as this
            _ if authorization == "Bearer" => return Ok(OauthContext::None),
            // Found nothing
            _ => return Ok(OauthContext::None),
        };
        println!("header: {header_value:?}");

        let token_id = header_value
            .strip_prefix(&format!("{}_", self.global.settings.oauth.token_prefix))
            .ok_or(ApiError::InvalidAuthentication)?;

        let token = blake3::hash(token_id.as_bytes()).to_hex();

        let Some(token) = OauthAuthorized::get_token(token.as_str(), &self.global.database).await?
        else {
            return Err(ApiError::InvalidAuthentication);
        };

        Ok(OauthContext::Some {
            user_id: token.user_id,
            oauth_app_id: token.app,
            scopes: token.scopes,
            oauth_authorized_id: token.id,
        })
    }
}

impl<S> Service<Request> for OauthManagerMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Sync + Send + 'static,
    Request: fmt::Debug,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let span = tracing::info_span!("oauth_man");
        let this = self.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let guard = span.enter();

            let auth_context = match this.do_something(request.headers()).await {
                Ok(context) => context,
                Err(e) => return Ok(e.into_response()),
            };

            request.extensions_mut().insert(auth_context);

            drop(guard);
            inner.call(request).await
        })
    }
}
