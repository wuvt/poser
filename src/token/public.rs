//! Paseto version 4 public tokens.

use super::claims::Claims;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::{BufMut, Bytes, BytesMut};
use ed25519::Signature;
use pkcs8::DecodePrivateKey;
use signature::Signer;
use thiserror::Error;

const PUBLIC_HEADER: &str = "v4.public.";

/// Errors while interacting with public tokens.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("unable to decode private key")]
    PemError,
    #[error("unable to encode claims as json")]
    EncodeError,
}

/// A key for signing Paseto.
#[derive(Clone, Debug)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Create a new signing key from an Ed25519 secret key in a PEM-encoded
    /// PKCS#8 document.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        match ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(Error::PemError),
        }
    }

    fn sign_message(
        &self,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit: Option<&[u8]>,
    ) -> String {
        let pae = pre_auth_encode(&[
            PUBLIC_HEADER.as_bytes(),
            message,
            footer.unwrap_or(&[]),
            implicit.unwrap_or(&[]),
        ]);
        let sig = self.0.sign(&pae);

        let mut body = Vec::with_capacity(message.len() + Signature::BYTE_SIZE);
        body.extend_from_slice(message);
        body.extend_from_slice(&sig.to_bytes());

        let mut token = PUBLIC_HEADER.to_string();
        token += &URL_SAFE_NO_PAD.encode(&body);
        if let Some(footer) = footer {
            token += ".";
            token += &URL_SAFE_NO_PAD.encode(footer);
        }

        token
    }

    /// Sign a new public token given a set of claims and an optional footer
    /// and implicit assertion.
    ///
    /// # Errors
    ///
    /// If any of the claims is unable to be serialized as JSON, an error is
    /// returned.
    pub fn sign(
        &self,
        claims: &Claims,
        footer: Option<&[u8]>,
        implicit: Option<&[u8]>,
    ) -> Result<String, Error> {
        let message = serde_json::to_vec(&claims).map_err(|_| Error::EncodeError)?;

        Ok(self.sign_message(&message, footer, implicit))
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

    use ed25519_dalek::SECRET_KEY_LENGTH;
    use hex_literal::hex;

    #[test]
    fn decode_pem() {
        let secret_key: [u8; SECRET_KEY_LENGTH] = [
            223, 102, 004, 198, 203, 162, 190, 016, 206, 137, 153, 124, 016, 013, 224, 179, 239,
            117, 207, 173, 054, 008, 070, 081, 194, 201, 131, 119, 059, 140, 015, 143,
        ];
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIN9mBMbLor4QzomZfBAN4LPvdc+tNghGUcLJg3c7jA+P\n-----END PRIVATE KEY-----\n";

        let signing_key = SigningKey::from_pem(pem).expect("decode pem");

        assert_eq!(secret_key, signing_key.0.to_bytes())
    }

    #[test]
    fn pae() {
        let one = pre_auth_encode(&[]);
        assert_eq!(*one, hex!("0000000000000000"));

        let two = pre_auth_encode(&[b""]);
        assert_eq!(*two, hex!("0100000000000000 0000000000000000"));

        let three = pre_auth_encode(&[b"test"]);
        assert_eq!(*three, hex!("0100000000000000 0400000000000000 74657374"));
    }

    #[test]
    fn public_sign() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----\n";
        let signing_key = SigningKey::from_pem(pem).expect("decode pem");

        let payload =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let implicit = b"{\"test-vector\":\"4-S-3\"}";

        let one = signing_key.sign_message(payload, None, None);
        assert_eq!(one, "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA");

        let two = signing_key.sign_message(payload, Some(footer), None);
        assert_eq!(two, "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");

        let three = signing_key.sign_message(payload, Some(footer), Some(implicit));
        assert_eq!(three, "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9");
    }
}
