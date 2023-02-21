mod auth;

use crate::ServerState;
use auth::auth_handler;

use axum::{
    http::StatusCode,
    routing::{get, Router},
};

pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/auth", get(auth_handler))
        .route("/ping", get(ping_handler))
}

#[axum::debug_handler(state = ServerState)]
async fn ping_handler() -> StatusCode {
    StatusCode::OK
}
