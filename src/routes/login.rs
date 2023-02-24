use std::collections::HashMap;

use crate::error::HttpError;
use crate::oidc::OidcState;
use crate::ServerState;

use axum::{
    extract::{Query, State},
    response::Redirect,
};
use tower_cookies::{Cookie, Cookies};
use tracing::error;

#[axum::debug_handler(state = ServerState)]
pub async fn login_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, HttpError> {
    let redirect = params.get("redirect").map(|s| s.as_str()).unwrap_or("/");
    let oidc = OidcState::new_request(redirect);

    cookies.add(
        Cookie::build(
            format!("{}_csrf", state.config.cookie.name),
            oidc.to_state_cookie(&state.config.cookie.secret)
                .map_err(|e| {
                    error!("Failed to generate OIDC cookie: {}", e);
                    HttpError::Internal("Failed to generate login request")
                })?,
        )
        .secure(true)
        .http_only(true)
        .finish(),
    );

    let state_token = oidc
        .to_state_token(&state.config.cookie.secret)
        .map_err(|e| {
            error!("Failed to generate OIDC state: {}", e);
            HttpError::Internal("Failed to generate login request")
        })?;

    Ok(Redirect::to(&format!("/callback?state={}", state_token)))
}
