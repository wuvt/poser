//! User tokens.

pub mod claims;
pub mod public;

use std::time::Duration;

pub use claims::Claims;
pub use public::SigningKey;

use bytes::{BufMut, Bytes, BytesMut};
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

fn pre_auth_encode(pieces: &[&[u8]]) -> Bytes {
    let mut capacity = 8;
    for piece in pieces {
        capacity += 8 + piece.len();
    }

    // bitmasks since the Paseto standard requires that the highest bit of
    // each unsigned integer is unset
    let mut pae = BytesMut::with_capacity(capacity);
    pae.put_u64_le(pieces.len() as u64 & 0x7FFFFFFFFFFFFF);
    for piece in pieces {
        pae.put_u64_le(piece.len() as u64 & 0x7FFFFFFFFFFFFF);
        pae.put_slice(piece);
    }

    pae.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn pae() {
        let one = pre_auth_encode(&[]);
        assert_eq!(*one, hex!("0000000000000000"));

        let two = pre_auth_encode(&[b""]);
        assert_eq!(*two, hex!("0100000000000000 0000000000000000"));

        let three = pre_auth_encode(&[b"test"]);
        assert_eq!(*three, hex!("0100000000000000 0400000000000000 74657374"));
    }
}
