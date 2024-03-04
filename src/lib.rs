//! # poser
//!
//! poser is a simple, opinionated authentication provider for nginx
//!
//! ## About
//!
//! poser authenticates with Google using OpenID Connect and then uses the
//! Google Workspace Admin SDK to determine what groups a user is a part of.
//! Basic information about the user and what groups they are a part of is
//! returned to nginx in a [Paseto v4] token, which is then passed to the
//! application.
//!
//! [Paseto v4]: https://github.com/paseto-standard/paseto-spec

pub mod config;
pub mod error;
pub mod oidc;
mod routes;
pub mod shutdown;
pub mod token;

pub use routes::routes;

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ServerState {
    pub config: crate::config::Config,
    pub db: Arc<tokio_postgres::Client>,
    pub oidc: openidconnect::core::CoreClient,

    // Signals back to the main thread when dropped
    pub shutdown: crate::shutdown::Receiver,
}
