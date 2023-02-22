use std::collections::HashMap;

use crate::{oidc::OidcState, ServerState};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use tower_cookies::{Cookie, Cookies};
use tracing::error;

#[axum::debug_handler(state = ServerState)]
pub async fn login_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, Response> {
    let redirect = params.get("redirect").map(|s| s.as_str()).unwrap_or("/");
    let oidc = OidcState::new_request(redirect);

    cookies.add(
        Cookie::build(
            format!("{}_csrf", state.config.cookie.name),
            oidc.to_state_cookie(&state.config.cookie.secret)
                .map_err(|e| {
                    error!("Failed to generate OIDC cookie: {}", e);

                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to generate login request",
                    )
                        .into_response()
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

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate login request",
            )
                .into_response()
        })?;

    Ok(Redirect::to(&format!("/callback?state={}", state_token)))
}
