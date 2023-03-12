//! Paseto version 4 local tokens.

use crate::token::{claims::Claims, pre_auth_encode};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2::{
    digest::{
        consts::{U24, U32, U56},
        generic_array::GenericArray,
        Mac,
    },
    Blake2bMac,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20,
};
use getrandom::getrandom;
use thiserror::Error;

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
        // unwrapping since key sizes are guaranteed
        let enc_hash = Blake2bMac::<U56>::new_from_slice(&self.0)
            .unwrap()
            .chain_update([DOMAIN_ENCRYPT, nonce].concat())
            .finalize()
            .into_bytes();
        let (key, n2) = enc_hash.split_at(32);

        let auth_key = &Blake2bMac::<U32>::new_from_slice(&self.0)
            .unwrap()
            .chain_update([DOMAIN_AUTH, nonce].concat())
            .finalize()
            .into_bytes();

        let mut c = message.to_owned();
        XChaCha20::new(
            GenericArray::<u8, U32>::from_slice(key),
            GenericArray::<u8, U24>::from_slice(n2),
        )
        .apply_keystream(&mut c);

        let mac = Blake2bMac::<U32>::new_from_slice(auth_key)
            .unwrap()
            .chain_update(pre_auth_encode(&[
                LOCAL_HEADER.as_bytes(),
                nonce,
                &c,
                footer.unwrap_or(&[]),
                implicit.unwrap_or(&[]),
            ]))
            .finalize()
            .into_bytes();

        let mut token = LOCAL_HEADER.to_string();
        token += &URL_SAFE_NO_PAD.encode([nonce, &c, &mac].concat());
        if let Some(footer) = footer {
            token += ".";
            token += &URL_SAFE_NO_PAD.encode(footer);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const KEY: [u8; 32] = hex!("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");

    #[test]
    fn local_encrypt_zero_nonce() {
        let payload =
            b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let expected = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, None, None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_zero_nonce_2() {
        let payload =
            b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let expected = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, None, None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt() {
        let payload =
            b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, None, None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_2() {
        let payload =
            b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, None, None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_with_footer() {
        let payload =
            b"{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, Some(footer), None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_with_footer_2() {
        let payload =
            b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, Some(footer), None);
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_with_implicit() {
        let payload =
            b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let footer = b"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        let implicit = b"{\"test-vector\":\"4-E-8\"}";
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, Some(footer), Some(implicit));
        assert_eq!(token, expected);
    }

    #[test]
    fn local_encrypt_with_implicit_2() {
        let payload =
            b"{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        let nonce = hex!("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8");
        let footer = b"arbitrary-string-that-isn't-json";
        let implicit = b"{\"test-vector\":\"4-E-9\"}";
        let expected = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";

        let key = SecretKey::from_slice(&KEY).expect("load key");

        let token = key.encrypt_message(payload, &nonce, Some(footer), Some(implicit));
        assert_eq!(token, expected);
    }
}
