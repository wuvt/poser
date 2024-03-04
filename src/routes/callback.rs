//! A route for handling the OIDC callback.

use std::collections::HashMap;
use std::sync::Arc;

use crate::oidc::OidcState;
use crate::token::UserToken;
use crate::ServerState;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect, Response},
};
use openidconnect::{core::CoreClient, reqwest::async_http_client, AuthorizationCode, Nonce};
use serde_json::json;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_postgres::Client;
use tower_cookies::{Cookie, Cookies};
use tracing::error;
use uuid::Uuid;

/// Errors returned by the handler.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("invalid oidc state")]
    InvalidState,
    #[error("invalid datetime")]
    InvalidDateTime,
    #[error("missing oidc state")]
    MissingState,
    #[error("missing oidc code")]
    MissingCode,
    #[error("missing csrf cookie")]
    MissingCookie,
    #[error("missing id token")]
    MissingToken,
    #[error("error exchanging code")]
    CodeExchange,
    #[error("error verifying token")]
    VerifyToken,
    #[error("error interacting with database")]
    DatabaseInsert,
}

/// A handler for receiving the callback during the OIDC flow.
#[axum::debug_handler(state = ServerState)]
pub async fn callback_handler(
    State(state): State<ServerState>,
    cookies: Cookies,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Redirect, Error> {
    let state_token = params.get("state").ok_or_else(|| {
        error!("missing oidc state parameter");
        Error::MissingState
    })?;
    let code = params.get("code").ok_or_else(|| {
        error!("missing oidc code parameter");
        Error::MissingCode
    })?;

    let cookie = cookies
        .get(&format!("{}_csrf", state.config.cookie.name))
        .ok_or_else(|| {
            error!("missing csrf cookie");
            Error::MissingCookie
        })?;

    let oidc = OidcState::from_tokens(state_token, cookie.value(), &state.config.cookie.secret)
        .map_err(|e| {
            error!("failed to recover oidc state: {}", e);
            Error::InvalidState
        })?;

    // this is how you remove a cookie...
    cookies.remove(Cookie::new(cookie.name().to_string(), ""));

    let (token, expiration) = get_token(
        &state.oidc,
        AuthorizationCode::new(code.clone()),
        oidc.get_nonce(),
    )
    .await?;

    let id = create_session(&state.db, &token, &expiration).await?;

    cookies.add(
        Cookie::build((state.config.cookie.name, id.simple().to_string()))
            .secure(state.config.cookie.secure)
            .http_only(true)
            .expires(expiration)
            .build(),
    );

    Ok(Redirect::to(oidc.get_redirect()))
}

async fn get_token(
    client: &CoreClient,
    code: AuthorizationCode,
    nonce: &Nonce,
) -> Result<(UserToken, OffsetDateTime), Error> {
    let token_response = client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!("failed to exchange code for token: {}", e);
            Error::CodeExchange
        })?;

    let token = token_response.extra_fields().id_token().ok_or_else(|| {
        error!("server response missing an id token");
        Error::MissingToken
    })?;

    let id_token_verifier = client.id_token_verifier();
    let claims = token.claims(&id_token_verifier, nonce).map_err(|e| {
        error!("failed to verify id token: {}", e);
        Error::VerifyToken
    })?;

    let subj = claims.subject();
    let name = claims.name().and_then(|s| s.get(None)).ok_or_else(|| {
        error!("name missing from id token");
        Error::VerifyToken
    })?;
    let email = claims.email().ok_or_else(|| {
        error!("email missing from id token");
        Error::VerifyToken
    })?;
    let expiration = claims
        .expiration()
        .timestamp_nanos_opt()
        .expect("todo: fix timestamp handling before 2262");

    Ok((
        UserToken {
            id: subj.to_string(),
            name: name.to_string(),
            email: email.to_string(),
            // TODO
            groups: Vec::new(),
        },
        OffsetDateTime::from_unix_timestamp_nanos(expiration as i128).map_err(|e| {
            error!("expiration time out of range: {}", e);
            Error::InvalidDateTime
        })?,
    ))
}

async fn create_session(
    db: &Arc<Client>,
    token: &UserToken,
    expiration: &OffsetDateTime,
) -> Result<Uuid, Error> {
    let id = Uuid::new_v4();

    db.query_one(
        r#"
            INSERT INTO session
                VALUES ($1::UUID, $2::VARCHAR, $3::VARCHAR, $4::VARCHAR, $5::VARCHAR[], $6::TIMESTAMPTZ)
                ON CONFLICT (id) DO UPDATE
                SET uid=$2::VARCHAR, name=$3::VARCHAR, email=$4::VARCHAR, groups=$5::VARCHAR[], expire=$6::TIMESTAMPTZ
                RETURNING id
        "#,
        &[
            &id,
            &token.id,
            &token.name,
            &token.email,
            &token.groups,
            &expiration,
        ],
    )
    .await
    .map_err(|e| {
        error!("error creating session: {}", e);
        Error::DatabaseInsert
    })
    .map(|r| r.get::<_, Uuid>("id"))
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let response = match self {
            Error::InvalidState
            | Error::MissingState
            | Error::MissingCode
            | Error::MissingCookie => json!({ "error": "invalid request" }),
            Error::MissingToken | Error::VerifyToken => json!({ "error": "authentication error" }),
            Error::InvalidDateTime | Error::CodeExchange | Error::DatabaseInsert => {
                json!({ "error": "internal error" })
            }
        };

        (StatusCode::BAD_REQUEST, Json(response)).into_response()
    }
}
