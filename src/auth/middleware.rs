use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    response::{IntoResponse as _, Response},
};
use futures_util::future::BoxFuture;
use tower::Service;
use tower_cookies::{Cookie, Cookies};
use tracing::Instrument;

use crate::{
    auth::{SESSION_COOKIE_NAME, ticket::AuthTicket},
    database::models::{
        session::{Session, SessionId},
        user::UserId,
    },
    global::GlobalState,
    http::HttpResult,
};

#[derive(Debug, Clone)]
pub enum AuthContext {
    Authenticated {
        user_id: UserId,
        session_id: SessionId,
    },
    NotAuthenticated,
}

impl AuthContext {
    pub fn user_id(&self) -> Option<UserId> {
        match self {
            Self::Authenticated { user_id, .. } => Some(*user_id),
            Self::NotAuthenticated => None,
        }
    }

    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Authenticated { session_id, .. } => Some(*session_id),
            Self::NotAuthenticated => None,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated { .. }) // no need to use mr if statements wohoo
    }
}

#[derive(Clone)]
pub struct AuthManagerLayer(Arc<GlobalState>);

impl AuthManagerLayer {
    pub const fn new(global: Arc<GlobalState>) -> Self {
        Self(global)
    }
}

impl<S> tower::Layer<S> for AuthManagerLayer {
    type Service = AuthManagerMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthManagerMiddleware {
            inner,
            global: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthManagerMiddleware<S> {
    inner: S,
    global: Arc<GlobalState>,
}

impl<S> AuthManagerMiddleware<S> {
    async fn do_something(&self, cookies: &Cookies) -> HttpResult<AuthContext> {
        let Some(session_cookie) = cookies.get(SESSION_COOKIE_NAME) else {
            return Ok(AuthContext::NotAuthenticated);
        };

        let token_value = session_cookie.value().to_string();
        tracing::info!("session cookie found");

        let Ok(token) = AuthTicket::validate(&token_value, &self.global) else {
            tracing::debug!("invalid token");
            let cookie = Cookie::build((SESSION_COOKIE_NAME, "")).path("/");
            cookies.remove(cookie.into());
            return Ok(AuthContext::NotAuthenticated);
        };

        let session = match Session::get(token.session_id, &self.global.database).await {
            Ok(Some(session)) => session,
            _ => {
                let cookie = Cookie::build((SESSION_COOKIE_NAME, "")).path("/");
                cookies.remove(cookie.into());
                return Ok(AuthContext::NotAuthenticated);
            }
        };

        tracing::debug!("session found");

        if session.is_expired() {
            tracing::debug!("session is expired");
            let cookie = Cookie::build((SESSION_COOKIE_NAME, "")).path("/");
            cookies.remove(cookie.into());
            return Ok(AuthContext::NotAuthenticated);
        }

        if !session.is_active() {
            tracing::debug!("session is inactive");
            let mut tx = self.global.database.begin().await?;
            let session = Session {
                active_expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                inactive_expires_at: chrono::Utc::now() + chrono::Duration::days(30),
                ..session
            };
            session.update(&mut tx).await?;
            tx.commit().await?;
        }

        Ok(AuthContext::Authenticated {
            user_id: session.user_id,
            session_id: session.id,
        })
    }
}

impl<S> Service<Request> for AuthManagerMiddleware<S>
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
        let span = tracing::info_span!("auth_man");
        let this = self.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(
            async move {
                let Some(cookies) = request.extensions().get::<Cookies>().cloned() else {
                    tracing::error!("missing cookies in request extension????");
                    return Ok(Response::default());
                };

                let auth_context = match this.do_something(&cookies).await {
                    Ok(context) => context,
                    Err(e) => return Ok(e.into_response()),
                };
                request.extensions_mut().insert(auth_context);

                inner.call(request).await.map_err(Into::into)
            }
            .instrument(span),
        )
    }
}
