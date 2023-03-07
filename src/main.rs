//! poser is a simple, opinionated authentication provider for nginx
//!
//! poser authenticates with Google using OpenID Connect and then uses the
//! Google Workspace Admin SDK to determine what groups a user is a part of.
//! Basic information about the users, as well as what groups they are a part
//! of, is returned to nginx in a PASETO v4 token, which is then passed to the
//! application.

mod config;
mod error;
mod oidc;
mod routes;

use std::env::var;

use config::Config;
use routes::routes;

use axum::Server;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::{info, Level};

#[derive(Debug, Clone)]
pub struct ServerState {
    pub config: Config,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let config = Config::try_env().expect("invalid configuration");

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
    let server = Server::bind(&config.addr).serve(app.into_make_service());

    info!("serving on {}", config.addr);
    server.await.expect("server unexpectedly stopped");
}
