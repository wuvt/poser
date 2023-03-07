//! HTTP error types for handlers.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// HTTP error codes that can be returned by a handler.
#[derive(Debug)]
pub enum HttpError {
    BadRequest(&'static str),
    Internal(&'static str),
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        match self {
            HttpError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            HttpError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        }
    }
}
