use std::sync::Arc;

use axum::{Router, routing::get};
use tokio::{net::TcpSocket, sync::oneshot};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use utoipa::{
    OpenApi,
    openapi::{
        extensions::Extensions,
        security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme},
    },
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    auth::{middleware::AuthManagerLayer, oauth::middleware::OauthManagerLayer, ops::TotpResponse},
    global::GlobalState,
    http::v1::{
        JsonEither,
        auth::{
            RecoveryOptions, VerifyEmail, oauth,
            otp::{self, AuthResponse},
            totp,
        },
        models,
    },
};

pub mod error;
mod v1;

pub type HttpResult<T> = Result<T, error::ApiError>;

#[derive(OpenApi)]
#[openapi(
    security(
        ("bearerAuth" = []),
        ("cookieAuth" = [])
    ),
    modifiers(&WhyUtoipa),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "oauth", description = "OAuth2 endpoints"),
        (name = "totp", description = "TOTP endpoints"),
        (name = "general", description = "Typical or useful endpoints"),
    )
)]
pub struct ApiDoc;

fn routes(global: &Arc<GlobalState>) -> OpenApiRouter {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
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
    let router = router
        .0
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", router.1.clone()));

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
            openapi.components = Some(Default::default());
        }

        let components = openapi.components.as_mut().unwrap();

        let mut aaaa = Http::new(HttpAuthScheme::Bearer);
        aaaa.bearer_format = Some("JWT".to_string());
        aaaa.description = Some("Bearer token used for OAuth2".to_string());

        components.add_security_scheme("bearerAuth", SecurityScheme::Http(aaaa));

        let mut aaaaa = ApiKeyValue::new("BSESS");
        aaaaa.description = Some("Session cookie used for authentication".to_string());
        components.add_security_scheme("cookieAuth", SecurityScheme::ApiKey(ApiKey::Cookie(aaaaa)));
    }
}
