use std::collections::HashMap;
use std::str::FromStr;

use crate::ServerState;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower_cookies::Cookies;
use tracing::error;

#[axum::debug_handler(state = ServerState)]
pub async fn auth_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    let code = params
        .get("code")
        .map(|s| StatusCode::from_str(s))
        .transpose()
        .map_err(|e| {
            error!("Error parsing code parameter: {}", e);

            (
                StatusCode::BAD_REQUEST,
                "Unable to parse \"code\" parameter.",
            )
                .into_response()
        })?;

    if let Some(cookie) = cookies.get(&state.config.cookie.name) {
        if cookie.value() == "hi" {
            return Ok(code.unwrap_or(StatusCode::ACCEPTED).into_response());
        }
    }

    Ok(code.unwrap_or(StatusCode::UNAUTHORIZED).into_response())
}
