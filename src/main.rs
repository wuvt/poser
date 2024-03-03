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
pub mod token;

use std::env::var;
use std::future::IntoFuture;
use std::sync::Arc;

use config::Config;
use oidc::setup_auth;
use openidconnect::core::CoreClient;
use routes::routes;

use tokio::{
    net::TcpListener,
    runtime::Runtime,
    select,
    signal::unix::{signal, SignalKind},
    sync::{broadcast, mpsc},
    time::timeout,
};
use tokio_postgres::{Client, NoTls};
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
    pub db: Arc<Client>,
    pub oidc: CoreClient,

    // Signals back to the main thread when dropped
    _shutdown_complete: mpsc::Sender<()>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let config = Config::try_env().expect("invalid configuration");

    build_runtime().block_on(async move {
        let (shutdown_notify, _) = broadcast::channel(1);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let (db, conn) = tokio_postgres::connect(&config.database, NoTls)
            .await
            .expect("connect to the database");

        let oidc = setup_auth(&config)
            .await
            .expect("setup Google authentication");

        let state = ServerState {
            config: config.clone(),
            db: Arc::new(db),
            oidc,
            _shutdown_complete: shutdown_tx.clone(),
        };

        let db_signal = shutdown_tx.clone();
        let conn = tokio::spawn(async move {
            let res = conn.await;
            drop(db_signal);
            res
        });

        let router = routes().with_state(state).layer(
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
        let listener = TcpListener::bind(&config.addr)
            .await
            .expect("failed to bind to socket");
        let shutdown_signal = shutdown_notify.subscribe();
        let server = axum::serve(listener, router)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_signal));

        info!("listening on {}", config.addr);

        select! {
            _ = unix_signal(SignalKind::interrupt()) => {
                info!("received SIGINT, shutting down");
            },
            _ = unix_signal(SignalKind::terminate()) => {
                info!("received SIGTERM, shutting down");
            },
            res = conn => match res {
                Ok(Ok(_)) => error!("database connection closed unexpectedly"),
                Ok(Err(e)) => error!("database connection error: {}", e),
                Err(e) => error!("database executor unexpectedly stopped: {}", e),
            },
            res = tokio::spawn(server.into_future()) => match res {
                Ok(Ok(_)) => info!("server shutting down"),
                Ok(Err(e)) => error!("server unexpectedly stopped: {}", e),
                Err(e) => error!("server executor unexpectedly stopped: {}", e),
            },
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
