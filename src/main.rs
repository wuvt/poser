use std::env::var;
use std::future::IntoFuture;
use std::sync::Arc;

use poser::config::Config;
use poser::oidc::setup_auth;
use poser::shutdown;
use poser::{routes, ServerState};

use anyhow::Context;
use tokio::{
    net::TcpListener,
    runtime::Runtime,
    signal::unix::{signal, SignalKind},
    time::timeout,
};
use tokio_postgres::NoTls;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{debug, error, info, warn, Level};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or_else(|_| "warn,poser=info".to_string()))
        .init();

    let config = Config::try_env()
        .context("failed to build config")
        .unwrap_or_else(|e| {
            error!("{:#}", e);
            std::process::exit(1);
        });

    build_runtime().block_on(async move {
        let shutdown = shutdown::Sender::new();

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
            shutdown: shutdown.subscribe(),
        };

        let postgres_notify = shutdown.subscribe();
        let postgres = async move {
            let res = conn.await;
            drop(postgres_notify);
            res
        };

        let router = routes().with_state(state).layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .on_request(DefaultOnRequest::new().level(Level::INFO))
                        .on_response(
                            DefaultOnResponse::new()
                                .level(Level::INFO)
                                .latency_unit(tower_http::LatencyUnit::Micros),
                        ),
                )
                .layer(CookieManagerLayer::new()),
        );

        let listener = TcpListener::bind(&config.addr)
            .await
            .context("failed to bind to socket")
            .unwrap_or_else(|e| {
                error!("{:#}", e);
                std::process::exit(1);
            });

        let mut axum_notify = shutdown.subscribe();
        let server = axum::serve(listener, router)
            .with_graceful_shutdown(async move { _ = axum_notify.recv().await });

        info!("listening for connections on: {}", config.addr);
        tokio::select! {
            sig = shutdown_signal() => info!("received {}, starting graceful shutdown...", sig),
            res = tokio::spawn(postgres) => match res {
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

        tokio::select! {
            sig = shutdown_signal() => error!("received second {}, aborting.", sig),
            res = timeout(config.grace_period, shutdown::Sender::shutdown(shutdown)) => match res {
                Ok(()) => debug!("shutdown completed"),
                Err(_) => warn!(
                    "graceful shutdown did not complete in {:?}, closing anyways",
                    config.grace_period
                ),
            },
        }
    })
}

fn build_runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build threaded runtime")
        .unwrap_or_else(|e| {
            error!("{:#}", e);
            std::process::exit(1);
        })
}

async fn shutdown_signal() -> &'static str {
    async fn wait_for_signal(kind: SignalKind) {
        signal(kind)
            .context("failed to register signal handler")
            .unwrap_or_else(|e| {
                error!("{:#}", e);
                std::process::exit(1);
            })
            .recv()
            .await;
    }

    tokio::select! {
        _ = wait_for_signal(SignalKind::interrupt()) => "SIGINT",
        _ = wait_for_signal(SignalKind::terminate()) => "SIGTERM",
    }
}
