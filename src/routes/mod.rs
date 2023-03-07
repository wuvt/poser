//! HTTP routes for interacting with poser.

pub mod auth;
pub mod callback;
pub mod login;

use crate::ServerState;
use auth::auth_handler;
use callback::callback_handler;
use login::login_handler;

use axum::{
    http::StatusCode,
    routing::{get, Router},
};

/// The complete router for this application.
pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/auth", get(auth_handler))
        .route("/callback", get(callback_handler))
        .route("/login", get(login_handler))
        .route("/ping", get(ping_handler))
}

/// A handler for a basic health check ping.
#[axum::debug_handler(state = ServerState)]
pub async fn ping_handler() -> StatusCode {
    StatusCode::OK
}
