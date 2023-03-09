//! A route for handling the OIDC callback.

use std::collections::HashMap;

use crate::ServerState;
use crate::{error::HttpError, oidc::OidcState};

use axum::{
    extract::{Query, State},
    response::Redirect,
};
use tower_cookies::{Cookie, Cookies};
use tracing::error;

/// A handler for receiving the callback during the OIDC flow.
#[axum::debug_handler(state = ServerState)]
pub async fn callback_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, HttpError> {
    // Yes, I know this isn't how OIDC works. I'm just getting things ready.
    let state_token = params
        .get("state")
        .ok_or(HttpError::BadRequest("No state parameter provided"))?;

    let cookie = cookies
        .get(&format!("{}_csrf", state.config.cookie.name))
        .ok_or(HttpError::BadRequest("Missing CSRF cookie"))?;

    let oidc = OidcState::from_tokens(state_token, cookie.value(), &state.config.cookie.secret)
        .map_err(|e| {
            error!("Failed to restore OIDC state: {}", e);
            HttpError::BadRequest("CSRF checking failed")
        })?;

    // This is how you remove a cookie...
    cookies.remove(Cookie::new(cookie.name().to_string(), ""));

    Ok(Redirect::to(oidc.get_redirect()))
}
