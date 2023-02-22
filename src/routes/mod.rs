mod auth;
mod callback;
mod login;

use crate::ServerState;
use auth::auth_handler;
use callback::callback_handler;
use login::login_handler;

use axum::{
    http::StatusCode,
    routing::{get, Router},
};

pub fn routes() -> Router<ServerState> {
    Router::new()
        .route("/auth", get(auth_handler))
        .route("/callback", get(callback_handler))
        .route("/login", get(login_handler))
        .route("/ping", get(ping_handler))
}

#[axum::debug_handler(state = ServerState)]
async fn ping_handler() -> StatusCode {
    StatusCode::OK
}
