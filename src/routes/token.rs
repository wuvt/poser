//! A route for requesting tokens from a user session.

use std::collections::HashMap;

use crate::token::UserToken;
use crate::ServerState;

use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use pasetors::{keys::AsymmetricSecretKey, version4::V4};
use serde_json::json;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_postgres::Client;
use tracing::error;
use uuid::Uuid;

/// Errors returned by the handler.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("invalid session token")]
    InvalidSessionToken,
    #[error("invalid session")]
    InvalidSession,
    #[error("missing session token")]
    MissingSessionToken,
    #[error("error generating id token")]
    TokenError,
}

/// A handler to generate a short-lived id token from a user's session token.
///
/// Given a session token (stored in the auth cookie), this route either
/// returns 200 OK with a short-lived Paseto of the user or 400 Bad Request
/// with an error message and possibly the configured login URL for
/// redirecting the user.
#[axum::debug_handler(state = ServerState)]
pub async fn token_handler(
    State(state): State<ServerState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<Response, Error> {
    let session_token = params.get("code").ok_or_else(|| {
        error!("missing session token parameter");
        Error::MissingSessionToken
    })?;

    let session_id = Uuid::try_parse(session_token).map_err(|_| {
        error!("failed to parse session token as uuid");
        Error::InvalidSessionToken
    })?;

    let token = build_token(&session_id, &state.db, &state.config.key).await?;

    Ok(Json(json!({ "expires_in": 3600, "id_token": token })).into_response())
}

async fn build_token(
    session_id: &Uuid,
    db: &Client,
    key: &AsymmetricSecretKey<V4>,
) -> Result<String, Error> {
    let session = db
        .query_one("SELECT * from session WHERE id = $1::UUID", &[&session_id])
        .await
        .map_err(|e| {
            error!("database error: {}", e);
            Error::InvalidSession
        })?;

    let expiration: OffsetDateTime = session.get("expire");
    if expiration < OffsetDateTime::now_utc() {
        error!("session is expired");
        return Err(Error::InvalidSession);
    }

    let token = UserToken {
        id: session.get("uid"),
        name: session.get("name"),
        email: session.get("email"),
        groups: session.get("groups"),
    };

    token.sign(key).map_err(|e| {
        error!("error generating token: {}", e);
        Error::TokenError
    })
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let response = match self {
            Error::InvalidSessionToken | Error::MissingSessionToken => {
                json!({ "error": "invalid request" })
            }
            Error::InvalidSession => json!({ "error": "bad session" }),
            Error::TokenError => json!({ "error": "internal error" }),
        };

        (StatusCode::BAD_REQUEST, Json(response)).into_response()
    }
}
