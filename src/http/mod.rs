use std::sync::Arc;

use axum::routing::get;
use tokio::{net::TcpSocket, sync::oneshot};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use utoipa::{
    OpenApi,
    openapi::{
        Components,
        security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme},
    },
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_scalar::{Scalar, Servable as _};
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    auth::{middleware::AuthManagerLayer, oauth::middleware::OauthManagerLayer},
    global::GlobalState,
};

pub mod error;
mod v1;

pub type HttpResult<T> = Result<T, error::ApiError>;

// quite ugly, isn't it?
pub const AUTH_TAG: &str = "Auth";
pub const OAUTH_TAG: &str = "OAuth";
pub const TOTP_TAG: &str = "Totp";
pub const PASSWORD_TAG: &str = "Password";
pub const OTP_TAG: &str = "Otp";
pub const SESSION_TAG: &str = "Session";
pub const SUDO_TAG: &str = "Sudo";

#[derive(OpenApi)]
#[openapi(
    security(
        ("Bearer Auth (OAuth2 Access Token)" = []),
        ("Cookie Auth (Session JWT)" = [])
    ),
    modifiers(&WhyUtoipa),
    tags(
        (name = AUTH_TAG, description = "General authentication related endpoints"),
        (name = OAUTH_TAG, description = "OAuth2 related endpoints"),
        (name = TOTP_TAG, description = "TOTP related endpoints"),
        (name = PASSWORD_TAG, description = "Password Authentication endpoints"),
        (name = OTP_TAG, description = "One-Time Passcode Authentication endpoints"),
        (name = SESSION_TAG, description = "Session related endpoints"),
        (name = SUDO_TAG, description = "Endpoints related to Sudo mode"),
        (name = "default", description = "Uncategorized"),
    )
)]
pub struct ApiDoc;

fn routes(global: &Arc<GlobalState>) -> OpenApiRouter {
    let mut openapi = ApiDoc::openapi();

    let components = openapi.components.as_mut().unwrap();
    let mut session = ApiKeyValue::new(global.settings.session.cookie_name.clone());
    session.description = Some("Session cookie used for authentication. Shouldn't be needed as the session is set on the browser's cookies".to_string());
    components.add_security_scheme(
        "Cookie Auth (Session JWT)",
        SecurityScheme::ApiKey(ApiKey::Cookie(session)),
    );

    OpenApiRouter::with_openapi(openapi)
        .nest("/v1", v1::routes())
        .route("/", get(|| async { "Hello, World!" }))
        .layer(
            ServiceBuilder::new()
                .layer(CookieManagerLayer::new())
                .layer(AuthManagerLayer::new(global.clone()))
                .layer(OauthManagerLayer::new(global.clone())),
        )
        .with_state(global.clone())
}

pub async fn run(
    global: Arc<GlobalState>,
    shutdown_signal: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!("Listening on http://{}", global.settings.http.bind);

    let socket = TcpSocket::new_v4()?;

    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;

    socket.bind(global.settings.http.bind)?;
    let listener = socket.listen(1024)?;

    let router = routes(&global).split_for_parts();
    let router = if global.settings.http.api_explorer {
        router
            .0
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", router.1.clone()))
            .merge(Scalar::with_url("/scalar", router.1.clone()))
    } else {
        router.0
    };

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { _ = shutdown_signal.await })
        .await
        .expect("Failed to start the HTTP server");

    Ok(())
}

struct WhyUtoipa;

impl utoipa::Modify for WhyUtoipa {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if openapi.components.is_none() {
            openapi.components = Some(Components::default());
        }

        let components = openapi.components.as_mut().unwrap();

        let mut oauth = Http::new(HttpAuthScheme::Bearer);
        oauth.bearer_format = Some("JWT".to_string());
        oauth.description = Some("Bearer token used for OAuth2".to_string());

        components.add_security_scheme(
            "Bearer Auth (OAuth2 Access Token)",
            SecurityScheme::Http(oauth),
        );
    }
}
