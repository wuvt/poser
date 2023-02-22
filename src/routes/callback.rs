use std::collections::HashMap;

use crate::oidc::OidcState;
use crate::ServerState;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use tower_cookies::{Cookie, Cookies};
use tracing::error;

#[axum::debug_handler(state = ServerState)]
pub async fn callback_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, Response> {
    // Yes, I know this isn't how OIDC works. I'm just getting things ready.
    let state_token = params
        .get("state")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "No state parameter provided").into_response())?;

    let cookie = cookies
        .get(&format!("{}_csrf", state.config.cookie.name))
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing CSRF cookie").into_response())?;

    let oidc = OidcState::from_tokens(state_token, cookie.value(), &state.config.cookie.secret)
        .map_err(|e| {
            error!("Failed to restore OIDC state: {}", e);

            (StatusCode::BAD_REQUEST, "CSRF checking failed").into_response()
        })?;

    // This is how you remove a cookie...
    cookies.remove(Cookie::new(cookie.name().to_string(), ""));

    Ok(Redirect::to(oidc.get_redirect()))
}
