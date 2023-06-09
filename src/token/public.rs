//! Paseto version 4 public tokens.

use crate::token::{claims::Claims, to_64_le};

use base64::{encoded_len, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{ed25519::signature::Signer, pkcs8::DecodePrivateKey, SIGNATURE_LENGTH};
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

        let size = PUBLIC_HEADER.len()
            + encoded_len(message.len() + SIGNATURE_LENGTH, false).unwrap()
            + footer.map_or(0, |f| encoded_len(f.len(), false).unwrap() + 1);
        let mut token = String::with_capacity(size);
        token += PUBLIC_HEADER;
        URL_SAFE_NO_PAD.encode_string([message, &sig.to_bytes()].concat(), &mut token);
        if let Some(footer) = footer {
            token += ".";
            URL_SAFE_NO_PAD.encode_string(footer, &mut token);
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

fn pre_auth_encode(pieces: &[&[u8]]) -> Vec<u8> {
    let mut capacity = 8;
    for piece in pieces {
        capacity += 8 + piece.len();
    }

    let mut pae = Vec::with_capacity(capacity);
    pae.extend_from_slice(&to_64_le(pieces.len()));
    for piece in pieces {
        pae.extend_from_slice(&to_64_le(piece.len()));
        pae.extend_from_slice(piece);
    }

    pae
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn decode_pem() {
        let key_bytes = hex!("DF6604C6CBA2BE10CE89997C100DE0B3EF75CFAD36084651C2C983773B8C0F8F");

        let key = SigningKey::from_pem("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIN9mBMbLor4QzomZfBAN4LPvdc+tNghGUcLJg3c7jA+P\n-----END PRIVATE KEY-----\n").expect("decode pem");
        assert_eq!(key.0.to_bytes(), key_bytes);
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

    macro_rules! test_vector {
        ($vec_name:ident, $token:expr, $payload:expr, $footer:expr, $implicit:expr) => {
            #[test]
            fn $vec_name() {
                let token: &str = $token;
                let payload: &[u8] = $payload;
                let footer: Option<&[u8]> = $footer;
                let implicit: Option<&[u8]> = $implicit;

                let key = SigningKey::from_pem("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----\n").expect("decode pem");

                let sign = key.sign_message(payload, footer, implicit);
                assert_eq!(sign, token);
            }
        };
    }

    test_vector!(
        vec_4_s_1,
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
        b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        None,
        None
    );

    test_vector!(
        vec_4_s_2,
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        None
    );

    test_vector!(
        vec_4_s_3,
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        Some(b"{\"test-vector\":\"4-S-3\"}")
    );
}
