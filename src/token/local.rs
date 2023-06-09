//! Paseto version 4 local tokens.

use crate::token::claims::{Claims, ClaimsValidator};
use crate::token::to_64_le;

use base64::{encoded_len, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2::{
    digest::{
        consts::{U24, U32, U56},
        generic_array::GenericArray,
        CtOutput, Mac,
    },
    Blake2bMac,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};
use getrandom::getrandom;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

const LOCAL_HEADER: &str = "v4.local.";

const DOMAIN_ENCRYPT: &[u8] = b"paseto-encryption-key";
const DOMAIN_AUTH: &[u8] = b"paseto-auth-key-for-aead";

/// Errors while interacting with public tokens.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("key must be 32 bytes")]
    SizeError,
    #[error("unable to encode claims as json")]
    EncodeError,
    #[error("failed to get randomness for nonce")]
    RngError,
    #[error("supplied token has invalid header")]
    InvalidHeader,
    #[error("unable to decode token message")]
    InvalidMessage,
    #[error("unable to decode token footer")]
    InvalidFooter,
    #[error("failed to authenticate ciphertext")]
    AuthFailure,
    #[error("unable to decode claims as json")]
    DecodeError,
    #[error("token claims failed validation")]
    BadClaims,
}

/// A key for signing Paseto.
#[derive(Clone, Debug)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
        Ok(Self(key.try_into().map_err(|_| Error::SizeError)?))
    }

    fn encrypt_message(
        &self,
        message: &[u8],
        nonce: &[u8],
        footer: Option<&[u8]>,
        implicit: Option<&[u8]>,
    ) -> String {
        let (mut key, mut n2, mut auth_key) = split_key(&self.0, nonce).expect("split key");

        let mut c = message.to_vec();
        XChaCha20::new(&key, &n2).apply_keystream(&mut c);
        key.zeroize();
        n2.zeroize();

        let mac = token_mac(&auth_key, nonce, &c, footer, implicit)
            .expect("generate mac for token")
            .into_bytes();
        auth_key.zeroize();

        let size = LOCAL_HEADER.len()
            + encoded_len(nonce.len() + c.len() + mac.len(), false).unwrap()
            + footer.map_or(0, |f| encoded_len(f.len(), false).unwrap() + 1);
        let mut token = String::with_capacity(size);
        token += LOCAL_HEADER;
        URL_SAFE_NO_PAD.encode_string([nonce, &c, &mac].concat(), &mut token);
        if let Some(footer) = footer {
            token += ".";
            URL_SAFE_NO_PAD.encode_string(footer, &mut token);
        }

        token
    }

    /// Encrypt a new local token given a set of claims and an optional footer
    /// and implicit assertion.
    ///
    /// # Errors
    ///
    /// If any of the claims is unable to be serialized as JSON, an error is
    /// returned.
    pub fn encrypt(
        &self,
        claims: &Claims,
        footer: Option<&[u8]>,
        implicit: Option<&[u8]>,
    ) -> Result<String, Error> {
        let message = serde_json::to_vec(&claims).map_err(|_| Error::EncodeError)?;

        let mut nonce = [0; 32];
        getrandom(&mut nonce).map_err(|_| Error::RngError)?;

        Ok(self.encrypt_message(&message, &nonce, footer, implicit))
    }

    fn decrypt_message(
        &self,
        token: &[u8],
        implicit: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
        let mut body = token
            .strip_prefix(LOCAL_HEADER.as_bytes())
            .ok_or(Error::InvalidHeader)?
            .split(|b| *b == b'.');

        let message = match body.next().map(|msg| URL_SAFE_NO_PAD.decode(msg)) {
            Some(Ok(d)) if d.len() >= 64 => d,
            _ => return Err(Error::InvalidMessage),
        };
        let footer = body
            .next()
            .map(|msg| URL_SAFE_NO_PAD.decode(msg))
            .transpose()
            .map_err(|_| Error::InvalidFooter)?;

        let (nonce, remaining) = message.split_at(32);
        let (c, mac) = remaining.split_at(remaining.len() - 32);

        let (mut key, mut n2, mut auth_key) = split_key(&self.0, nonce).expect("split key");

        let mac_expected = token_mac(&auth_key, nonce, c, footer.as_deref(), implicit)
            .expect("generate mac for token");
        auth_key.zeroize();

        if mac_expected
            .ct_eq(&GenericArray::<u8, U32>::from_slice(mac).into())
            .into()
        {
            let mut p = c.to_vec();
            XChaCha20::new(&key, &n2).apply_keystream(&mut p);
            key.zeroize();
            n2.zeroize();

            Ok((p, footer))
        } else {
            Err(Error::AuthFailure)
        }
    }

    /// Decrypt a local token, checking it against a claims validator.
    ///
    /// # Errors
    ///
    /// If any of the claims is unable to be serialized as JSON, an error is
    /// returned.
    pub fn decrypt(
        &self,
        token: &str,
        validator: &ClaimsValidator,
        implicit: Option<&[u8]>,
    ) -> Result<Claims, Error> {
        let (message, _) = self.decrypt_message(token.as_bytes(), implicit)?;

        let claims = serde_json::from_slice(&message).map_err(|_| Error::DecodeError)?;

        if validator.validate(&claims) {
            Ok(claims)
        } else {
            Err(Error::BadClaims)
        }
    }
}

fn token_mac(
    key: &[u8],
    nonce: &[u8],
    c: &[u8],
    footer: Option<&[u8]>,
    implicit: Option<&[u8]>,
) -> Result<CtOutput<Blake2bMac<U32>>, Error> {
    pre_auth_hash(
        key,
        &[
            LOCAL_HEADER.as_bytes(),
            nonce,
            c,
            footer.unwrap_or(&[]),
            implicit.unwrap_or(&[]),
        ],
    )
}

fn pre_auth_hash(key: &[u8], pieces: &[&[u8]]) -> Result<CtOutput<Blake2bMac<U32>>, Error> {
    let mut hash = Blake2bMac::<U32>::new_from_slice(key)
        .map_err(|_| Error::SizeError)?
        .chain_update(to_64_le(pieces.len()));

    for piece in pieces {
        hash.update(&to_64_le(piece.len()));
        hash.update(piece);
    }

    Ok(hash.finalize())
}

type SplitKey = (
    GenericArray<u8, U32>,
    GenericArray<u8, U24>,
    GenericArray<u8, U32>,
);

fn split_key(base_key: &[u8], split_nonce: &[u8]) -> Result<SplitKey, Error> {
    let mut enc_hash = Blake2bMac::<U56>::new_from_slice(base_key)
        .map_err(|_| Error::SizeError)?
        .chain_update(DOMAIN_ENCRYPT)
        .chain_update(split_nonce)
        .finalize()
        .into_bytes();

    let (head, tail) = enc_hash.split_at(32);
    let key = GenericArray::<u8, U32>::clone_from_slice(head);
    let nonce = GenericArray::<u8, U24>::clone_from_slice(tail);
    enc_hash.zeroize();

    let auth_key = Blake2bMac::<U32>::new_from_slice(base_key)
        .map_err(|_| Error::SizeError)?
        .chain_update(DOMAIN_AUTH)
        .chain_update(split_nonce)
        .finalize()
        .into_bytes();

    Ok((key, nonce, auth_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn pae_hash() {
        let key = hex!("0000");
        let hash = |bytes: &[u8]| {
            Blake2bMac::<U32>::new_from_slice(&key)
                .unwrap()
                .chain_update(bytes)
                .finalize()
                .into_bytes()
        };

        let one = pre_auth_hash(&key, &[]).unwrap().into_bytes();
        assert_eq!(one, hash(&hex!("0000000000000000")));

        let two = pre_auth_hash(&key, &[b""]).unwrap().into_bytes();
        assert_eq!(two, hash(&hex!("0100000000000000 0000000000000000")));

        let three = pre_auth_hash(&key, &[b"test"]).unwrap().into_bytes();
        assert_eq!(
            three,
            hash(&hex!("0100000000000000 0400000000000000 74657374"))
        );
    }

    macro_rules! test_vector {
        ($vec_name:ident, $token:expr, $payload:expr, $nonce:expr, $footer:expr, $implicit:expr) => {
            #[test]
            fn $vec_name() {
                let token: &str = $token;
                let payload: &[u8] = $payload;
                let nonce: [u8; 32] = $nonce;
                let footer: Option<&[u8]> = $footer;
                let implicit: Option<&[u8]> = $implicit;

                let key = SecretKey::from_slice(&hex!(
                    "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
                ))
                .expect("load key");

                let enc = key.encrypt_message(payload, &nonce, footer, implicit);
                assert_eq!(enc, token);

                let (dec, dec_footer) = key.decrypt_message(token.as_bytes(), implicit).unwrap();
                assert_eq!(dec, payload);
                assert_eq!(dec_footer, footer.map(Vec::<u8>::from));
            }
        };
    }

    test_vector!(
        vec_4_e_1,
        "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
        b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        None,
        None
    );

    test_vector!(
        vec_4_e_2,
        "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A",
        b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        None,
        None
    );

    test_vector!(
        vec_4_e_3,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA",
        b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        None,
        None
    );

    test_vector!(
        vec_4_e_4,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ",
        b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        None,
        None
    );

    test_vector!(
        vec_4_e_5,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        None
    );

    test_vector!(
        vec_4_e_6,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        None
    );

    test_vector!(
        vec_4_e_7,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        Some(b"{\"test-vector\":\"4-E-7\"}")
    );

    test_vector!(
        vec_4_e_8,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        Some(b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"),
        Some(b"{\"test-vector\":\"4-E-8\"}")
    );

    test_vector!(
        vec_4_e_9,
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
        b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"),
        Some(b"arbitrary-string-that-isn't-json"),
        Some(b"{\"test-vector\":\"4-E-9\"}")
    );
}
