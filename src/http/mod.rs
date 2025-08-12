use std::{net::SocketAddr, sync::Arc};

use axum::{Router, routing::get};
use tokio::{net::TcpSocket, sync::oneshot};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;

use crate::{auth::middleware::AuthManagerLayer, global::GlobalState};

pub mod error;
mod v1;

pub type HttpResult<T> = Result<T, error::ApiError>;

fn routes(global: &Arc<GlobalState>) -> Router {
    Router::new()
        .nest("/v1", v1::routes())
        .route("/", get(|| async { "Hello, World!" }))
        .layer(
            ServiceBuilder::new()
                .layer(CookieManagerLayer::new())
                .layer(AuthManagerLayer::new(global.clone())),
        )
        .with_state(global.clone())
}

pub async fn run(
    global: Arc<GlobalState>,
    shutdown_signal: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!("Listening on http://localhost:8080");

    let socket = TcpSocket::new_v4()?;

    socket.set_reuseaddr(true)?;
    socket.set_nodelay(true)?;

    socket.bind(SocketAddr::from(([127, 0, 0, 1], 8080)))?;
    let listener = socket.listen(1024)?;

    axum::serve(listener, routes(&global))
        .with_graceful_shutdown(async move { _ = shutdown_signal.await })
        .await
        .expect("Failed to start the HTTP server");

    Ok(())
}
