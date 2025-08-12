#![warn(clippy::nursery, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::trait_duplication_in_bounds,
    clippy::new_ret_no_self,
	// clippy::enum_variant_names
)]

use std::{sync::Arc, time::Duration};

use tokio::sync::oneshot;

use crate::global::GlobalState;

mod auth;
mod database;
mod global;
mod http;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("heelo");
    // let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    let global = GlobalState::new()
        .await
        .expect("Failed to initialize global state");
    let global = Arc::new(global);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let http_server = tokio::spawn(http::run(global, shutdown_rx));

    let shutdown = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Received ctrl-c signal, shutting down...");
        shutdown_tx.send(()).ok();

        tokio::time::timeout(Duration::from_secs(60), tokio::signal::ctrl_c())
            .await
            .ok();
    });

    // // run our app with hyper, listening globally on port 3000
    // let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    // axum::serve(listener, app).await.unwrap();

    tokio::select! {
        r = http_server => {
            match r {
                Ok(_) => tracing::info!("HTTP server exited successfully"),
                Err(e) => tracing::error!("HTTP server exited with error: {:?}", e),
            }
        }
        _ = shutdown => {
            tracing::info!("Force shutdown..");
        }
    }
}
