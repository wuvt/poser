mod config;
mod error;
mod oidc;
mod routes;

use std::env::var;
use std::fs::read_to_string;
use std::net::SocketAddr;
use std::path::PathBuf;

use config::Config;
use routes::routes;

use anyhow::{Context, Result};
use axum::Server;
use clap::Parser;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(author, version)]
/// poser is a simple, opinionated authentication provider for nginx
///
/// poser authenticates with Google using OpenID Connect and then uses the
/// Google Workspace Admin SDK to determine what groups a user is a part of.
/// Basic information about the users as well as what groups they are a part
/// of is returned to nginx in a PASETO v4 token, which is then passed to the
/// application.
struct Args {
    /// Configuration file
    #[arg(long, default_value = "/data/config/config.toml")]
    config: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ServerState {
    pub config: Config,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let config: Config = toml::from_str(&read_to_string(&args.config).with_context(|| {
        format!(
            "Failed to read config file at {}",
            args.config.to_string_lossy()
        )
    })?)
    .context("Failed to parse config file")?;

    let state = ServerState {
        config: config.clone(),
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

    let server =
        Server::bind(&SocketAddr::from((config.ip, config.port))).serve(app.into_make_service());

    info!("Serving on {}:{}", config.ip, config.port);
    server.await.context("Server unexpectedly stopped")?;

    Ok(())
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();
}
