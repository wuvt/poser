//! User tokens.

pub mod claims;
pub mod local;
pub mod public;

use std::time::Duration;

pub use claims::{Claims, ClaimsValidator};
pub use local::SecretKey;
pub use public::SigningKey;

use thiserror::Error;
use time::OffsetDateTime;
use tracing::error;

/// An error that occurs while processing a user token.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("paseto claims error: {0}")]
    ClaimsError(#[from] claims::Error),
    #[error("failed to sign Paseto")]
    SigningError,
}

/// A token represented an authenticated user.
#[derive(Clone, Debug)]
pub struct UserToken {
    pub id: String,
    pub name: String,
    pub email: String,
    pub groups: Vec<String>,
}

impl UserToken {
    /// Sign a user token as a Paseto
    pub fn sign(&self, key: &SigningKey, lifetime: Duration) -> Result<String, Error> {
        let claims = Claims::new()
            .with_subject(&self.id)?
            .with_expiration(&(OffsetDateTime::now_utc() + lifetime))?
            .with_custom_claim("name", self.name.as_str())?
            .with_custom_claim("email", self.email.as_str())?
            .with_custom_claim("group", self.groups.clone())?;

        key.sign(&claims, None, None).map_err(|_| {
            error!("error signing paseto");
            Error::SigningError
        })
    }
}

// this applies a bitmask since the Paseto standard requires that the highest
// bit of each unsigned integer is unset
fn to_64_le(n: usize) -> [u8; 8] {
    (n as u64 & 0x7FFFFFFFFFFFFF).to_le_bytes()
}
