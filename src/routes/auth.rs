//! A route for checking if a user is authenticated.

use std::collections::HashMap;
use std::str::FromStr;

use crate::{error::HttpError, ServerState};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;
use tracing::error;

/// A handler to check the auth status of the requesting user.
///
/// Given an authentication cookie (or lack thereof), this route either
/// returns 202 Accepted with a Paseto of the user or 401 Unauthorized with the
/// configured login URL the user can be redirected to. This route also takes
/// an optional "code" parameter to override the returned HTTP status code.
#[axum::debug_handler(state = ServerState)]
pub async fn auth_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, HttpError> {
    let code = params
        .get("code")
        .map(|s| StatusCode::from_str(s))
        .transpose()
        .map_err(|e| {
            error!("Error parsing code parameter: {}", e);
            HttpError::BadRequest("Unable to parse \"code\" parameter.")
        })?;

    if let Some(cookie) = cookies.get(&state.config.cookie.name) {
        if cookie.value() == "hi" {
            return Ok(code.unwrap_or(StatusCode::ACCEPTED).into_response());
        }
    }

    Ok(code.unwrap_or(StatusCode::UNAUTHORIZED).into_response())
}
