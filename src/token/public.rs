//! Paseto version 4 public tokens.

use crate::token::{claims::Claims, pre_auth_encode};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pkcs8::DecodePrivateKey;
use signature::Signer;
use thiserror::Error;

pub const PUBLIC_HEADER: &str = "v4.public.";

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
        let sig = self.0.sign(&pre_auth_encode(&[
            PUBLIC_HEADER.as_bytes(),
            message,
            footer.unwrap_or(&[]),
            implicit.unwrap_or(&[]),
        ]));

        let mut token = PUBLIC_HEADER.to_string();
        token += &URL_SAFE_NO_PAD.encode([message, &sig.to_bytes()].concat());
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

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----\n";

    #[test]
    fn decode_pem() {
        let key_bytes = hex!("B4CBFB43DF4CE210727D953E4A713307FA19BB7D9F85041438D9E11B942A3774");

        let key = SigningKey::from_pem(KEY_PEM).expect("decode pem");
        assert_eq!(key.0.to_bytes(), key_bytes);
    }

    #[test]
    fn public_sign() {
        let payload =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let expected = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";

        let key = SigningKey::from_pem(KEY_PEM).expect("decode pem");

        let token = key.sign_message(payload, None, None);
        assert_eq!(token, expected);
    }

    #[test]
    fn public_sign_with_footer() {
        let payload =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let expected = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let key = SigningKey::from_pem(KEY_PEM).expect("decode pem");

        let token = key.sign_message(payload, Some(footer), None);
        assert_eq!(token, expected);
    }

    #[test]
    fn public_sign_with_implicit() {
        let payload =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let implicit = b"{\"test-vector\":\"4-S-3\"}";
        let expected = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let key = SigningKey::from_pem(KEY_PEM).expect("decode pem");

        let token = key.sign_message(payload, Some(footer), Some(implicit));
        assert_eq!(token, expected);
    }
}
