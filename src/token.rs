//! User tokens.

use pasetors::{claims::Claims, keys::AsymmetricSecretKey, public::sign, version4::V4};
use thiserror::Error;
use tracing::error;

/// An error that occurs while processing a user token.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("generated Paseto would have invalid claims")]
    InvalidClaim,
    #[error("invalid user id")]
    InvalidId,
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
    pub fn sign(&self, key: &AsymmetricSecretKey<V4>) -> Result<String, Error> {
        let mut claims = Claims::new().map_err(|e| {
            error!("error generating Paseto claims: {}", e);
            Error::InvalidClaim
        })?;

        claims.subject(&self.id).map_err(|_| {
            error!("token user id is empty");
            Error::InvalidId
        })?;

        // unwrap is safe since Claims::add_additional only returns an error
        // when the claim name matches a reserved name, which none of these do
        claims.add_additional("name", self.name.as_str()).unwrap();
        claims.add_additional("email", self.email.as_str()).unwrap();
        claims.add_additional("group", self.groups.clone()).unwrap();

        sign(key, &claims, None, None).map_err(|e| {
            error!("error signing Paseto: {}", e);
            Error::SigningError
        })
    }
}
