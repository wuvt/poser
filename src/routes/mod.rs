//! HTTP routes for interacting with poser.

pub mod callback;
pub mod login;
pub mod token;

use crate::ServerState;
use callback::callback_handler;
use login::login_handler;
use token::token_handler;

use axum::{
    http::StatusCode,
    routing::{get, post, Router},
};

/// The complete router for this application.
pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/token", post(token_handler))
        .route("/callback", get(callback_handler))
        .route("/login", get(login_handler))
        .route("/ping", get(ping_handler))
}

/// A handler for a basic health check ping.
#[axum::debug_handler(state = ServerState)]
pub async fn ping_handler() -> StatusCode {
    StatusCode::OK
}
