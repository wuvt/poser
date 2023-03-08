//! # poser
//!
//! poser is a simple, opinionated authentication provider for nginx
//!
//! ## About
//!
//! poser authenticates with Google using OpenID Connect and then uses the
//! Google Workspace Admin SDK to determine what groups a user is a part of.
//! Basic information about the user and what groups they are a part of is
//! returned to nginx in a [Paseto v4] token, which is then passed to the
//! application.
//!
//! [Paseto v4]: https://github.com/paseto-standard/paseto-spec

pub mod config;
pub mod error;
pub mod oidc;
pub mod routes;

use std::env::var;

use config::Config;
use routes::routes;

use axum::Server;
use tokio::{
    runtime::Runtime,
    select,
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc},
    time::timeout,
};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{debug, error, info, warn, Level};

#[derive(Debug, Clone)]
pub struct ServerState {
    pub config: Config,

    // Signals back to the main thread when dropped
    _shutdown_complete: mpsc::Sender<()>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let config = Config::try_env().expect("invalid configuration");

    build_runtime().block_on(async move {
        let (shutdown_notify, _): (broadcast::Sender<()>, broadcast::Receiver<()>) =
            broadcast::channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let state = ServerState {
            config: config.clone(),
            _shutdown_complete: shutdown_tx.clone(),
        };

        let app = routes().with_state(state).layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .on_request(DefaultOnRequest::new().level(Level::INFO))
                        .on_response(
                            DefaultOnResponse::new()
                                .level(Level::INFO)
                                .latency_unit(LatencyUnit::Micros),
                        ),
                )
                .layer(CookieManagerLayer::new()),
        );
        let shutdown_signal = shutdown_notify.subscribe();
        let server = Server::bind(&config.addr)
            .serve(app.into_make_service())
            .with_graceful_shutdown(wait_for_shutdown(shutdown_signal));

        info!("listening on {}", config.addr);

        select! {
            _ = unix_signal(SignalKind::interrupt()) => {
                info!("received SIGINT, shutting down");
            }
            _ = unix_signal(SignalKind::terminate()) => {
                info!("received SIGTERM, shutting down");
            }
            Err(e) = tokio::spawn(server) => {
                error!("server unexpectedly stopped: {}", e);
            }
        }
        drop(shutdown_notify);
        drop(shutdown_tx);
        match timeout(config.grace_period, wait_for_complete(shutdown_rx)).await {
            Ok(()) => debug!("shutdown completed"),
            Err(_) => warn!(
                "graceful shutdown did not complete in {:?}, closing anyways",
                config.grace_period
            ),
        }
    })
}

fn build_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build threaded runtime")
}

async fn unix_signal(kind: SignalKind) {
    signal(kind).expect("register signal handler").recv().await;
}

async fn wait_for_shutdown(mut signal: broadcast::Receiver<()>) {
    _ = signal.recv().await;
}

async fn wait_for_complete(mut signal: mpsc::Receiver<()>) {
    _ = signal.recv().await;
}
