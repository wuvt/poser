//! A route for startng the OIDC flow.

use std::collections::HashMap;

use crate::oidc::OidcState;
use crate::ServerState;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect, Response},
};
use openidconnect::{core::CoreResponseType, AuthenticationFlow, CsrfToken, Scope};
use serde_json::json;
use thiserror::Error;
use tower_cookies::{Cookie, Cookies};
use tracing::error;

/// Errors returned by the handler.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("error generating OIDC state")]
    GenerateState,
    #[error("error generating OIDC cookie")]
    GenerateCookie,
}

/// A handler to start the OIDC flow.
#[axum::debug_handler(state = ServerState)]
pub async fn login_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, Error> {
    let redirect = params.get("redirect").map(|s| s.as_str()).unwrap_or("/");

    let oidc_state = OidcState::new_request(redirect);
    let csrf = oidc_state
        .to_state(&state.config.cookie.secret)
        .map_err(|e| {
            error!("error generating OIDC state: {}", e);
            Error::GenerateState
        })?;
    let nonce = oidc_state.get_nonce().clone();

    let mut auth = state
        .oidc
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(csrf),
            || nonce,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()));

    if let Some(hd) = state.config.google.email_domain {
        auth = auth.add_extra_param("hd", hd);
    }

    let (authorize_url, _, _) = auth.url();

    cookies.add(
        Cookie::build((
            format!("{}_csrf", state.config.cookie.name),
            oidc_state
                .to_cookie(&state.config.cookie.secret)
                .map_err(|e| {
                    error!("error generating OIDC cookie: {}", e);
                    Error::GenerateCookie
                })?,
        ))
        .secure(state.config.cookie.secure)
        .http_only(true)
        .build(),
    );

    Ok(Redirect::to(authorize_url.as_str()))
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let response = match self {
            Error::GenerateState | Error::GenerateCookie => json!({ "error": "internal error" }),
        };

        (StatusCode::BAD_REQUEST, Json(response)).into_response()
    }
}
