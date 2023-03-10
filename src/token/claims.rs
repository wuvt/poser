//! Paseto claims.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

/// Errors while interacting with claims.
#[derive(Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("claim would be empty")]
    EmptyClaim,
    #[error("claim not present")]
    MissingClaim,
    #[error("claim in unexpected format")]
    InvalidClaimFormat,
    #[error("token alread non-expiring")]
    NonExpiring,
    #[error("cannot set registered claim as custom")]
    RegisteredClaim,
    #[error("cannot serialize value as json")]
    SerializeError,
    #[error("unable to parse value")]
    ParseError,
}

/// Registered Paseto claims. These claims can only be modified through the
/// provided setters, which will prevent invalid values from being set.
pub const REGISTERED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// A collection of claims for a Paseto.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct Claims(HashMap<String, Value>);

impl Claims {
    /// Create a new set of claims. This sets "Not Before" and "Issued At" to
    /// the current time and "Expiration" to one hour from now.
    pub fn new() -> Self {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::hours(1);

        // the only possible way for formatting the time to fail is if it were
        // the year 10,000. I'm unwrapping for API cleanliness, sorry future.
        Self(HashMap::new())
            .set_expiration(&exp)
            .unwrap()
            .set_not_before(&iat)
            .unwrap()
            .set_issued_at(&iat)
            .unwrap()
    }

    /// Set a non-registered claim to a serializable value.
    ///
    /// # Errors
    ///
    /// Returns an error when attempting to set a registered claim or when the
    /// provided value can't be serialized to JSON.
    pub fn set_custom_claim<V>(mut self, claim: &str, value: V) -> Result<Self, Error>
    where
        V: Serialize,
    {
        if REGISTERED_CLAIMS.contains(&claim) {
            Err(Error::RegisteredClaim)
        } else {
            let value = serde_json::to_value(value).map_err(|_| Error::SerializeError)?;
            self.0.insert(claim.to_string(), value);

            Ok(self)
        }
    }

    /// Get the JSON value of a claim.
    ///
    /// Returns [`None`] if the claim is not set.
    pub fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.0.get(claim)
    }

    /// Remove a claim.
    ///
    /// # Errors
    ///
    /// Will return an error if no claim with the given name is set.
    pub fn remove_claim(mut self, claim: &str) -> Result<Self, Error> {
        self.0.remove(claim).ok_or(Error::MissingClaim)?;

        Ok(self)
    }

    /// Convenience method for removing the expiration claim, making to token
    /// last forever.
    ///
    /// # Errors
    ///
    /// Will return an error if no expiration is currently set.
    pub fn set_non_expiring(self) -> Result<Self, Error> {
        self.remove_claim("exp").map_err(|_| Error::NonExpiring)
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

impl Claims {
    fn set_claim_str(mut self, key: &str, value: String) -> Result<Self, Error> {
        if value.is_empty() {
            return Err(Error::EmptyClaim);
        } else {
            self.0.insert(key.to_string(), Value::String(value));
        }

        Ok(self)
    }

    fn get_claim_str(&self, claim: &str) -> Option<&str> {
        self.get_claim(claim).and_then(Value::as_str)
    }

    /// Set the token issuer.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn set_issuer(self, iss: &str) -> Result<Self, Error> {
        self.set_claim_str("iss", iss.to_string())
    }

    /// Set the token subject.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn set_subject(self, sub: &str) -> Result<Self, Error> {
        self.set_claim_str("sub", sub.to_string())
    }

    /// Set the token subject.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn set_audience(self, aud: &str) -> Result<Self, Error> {
        self.set_claim_str("aud", aud.to_string())
    }

    /// Set the token expiration date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn set_expiration(self, exp: &OffsetDateTime) -> Result<Self, Error> {
        self.set_claim_str("exp", format_time(exp)?)
    }

    /// Set the token not before date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn set_not_before(self, nbf: &OffsetDateTime) -> Result<Self, Error> {
        self.set_claim_str("nbf", format_time(nbf)?)
    }

    /// Set the token issued at date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn set_issued_at(self, iat: &OffsetDateTime) -> Result<Self, Error> {
        self.set_claim_str("iat", format_time(iat)?)
    }

    /// Set the token identifier.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn set_token_identifier(self, jti: &str) -> Result<Self, Error> {
        self.set_claim_str("jti", jti.to_string())
    }

    /// Get the token issuer.
    ///
    /// Returns [`None`] if the issuer is not set.
    pub fn get_issuer(&self) -> Option<&str> {
        self.get_claim_str("iss")
    }

    /// Get the token subject.
    ///
    /// Returns [`None`] if the subject is not set.
    pub fn get_subject(&self) -> Option<&str> {
        self.get_claim_str("sub")
    }

    /// Get the token audience.
    ///
    /// Returns [`None`] if the audience is not set.
    pub fn get_audience(&self) -> Option<&str> {
        self.get_claim_str("aud")
    }

    /// Get the token expiration date.
    ///
    /// Returns [`None`] if the expiration date is not set.
    pub fn get_expiration(&self) -> Option<OffsetDateTime> {
        self.get_claim_str("exp").map(parse_time)
    }

    /// Get the token not before date.
    ///
    /// Returns [`None`] if the not before date is not set.
    pub fn get_not_before(&self) -> Option<OffsetDateTime> {
        self.get_claim_str("nbf").map(parse_time)
    }

    /// Get the token issued at date.
    ///
    /// Returns [`None`] if the issued at date is not set.
    pub fn get_issued_at(&self) -> Option<OffsetDateTime> {
        self.get_claim_str("iat").map(parse_time)
    }

    /// Get the token identifier.
    ///
    /// Returns [`None`] if the token identifier is not set.
    pub fn get_token_identifier(&self) -> Option<&str> {
        self.get_claim_str("jti")
    }
}

fn format_time(time: &OffsetDateTime) -> Result<String, Error> {
    time.format(&Rfc3339).map_err(|_| Error::SerializeError)
}

// WARN: only for use when the value is guaranteed to be valid RFC3339 (i.e.
// when it was set a setter using format_time)
fn parse_time(time: &str) -> OffsetDateTime {
    OffsetDateTime::parse(time, &Rfc3339).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_claims() {
        let now = OffsetDateTime::now_utc();
        let now_offset = now + Duration::hours(1);

        let claims = Claims::new();
        let exp = claims.get_expiration().expect("get expiration claim");
        let nbf = claims.get_not_before().expect("get not before claim");
        let iat = claims.get_issued_at().expect("get issued at claim");

        // now is taken at a slightly different time from when the claims are
        // generated, so I'm using a 1 second threshold
        assert!(exp >= now_offset && exp - now_offset < Duration::seconds(1));
        assert!(nbf >= now && nbf - now < Duration::seconds(1));
        assert!(iat >= now && iat - now < Duration::seconds(1));
    }

    #[test]
    fn registered_claims() {
        let epoch = OffsetDateTime::UNIX_EPOCH;

        let mut claims = Claims::new();
        claims = claims.set_issuer("iss").expect("set issuer");
        claims = claims.set_subject("sub").expect("set subject");
        claims = claims.set_audience("aud").expect("set audience");
        claims = claims.set_expiration(&epoch).expect("set expiration");
        claims = claims.set_not_before(&epoch).expect("set not before");
        claims = claims.set_issued_at(&epoch).expect("set issued t");
        claims = claims.set_token_identifier("jti").expect("set token id");

        assert_eq!(claims.get_issuer().expect("get issuer"), "iss");
        assert_eq!(claims.get_subject().expect("get subject"), "sub");
        assert_eq!(claims.get_audience().expect("get audience"), "aud");
        assert_eq!(claims.get_expiration().expect("get expiration"), epoch);
        assert_eq!(claims.get_not_before().expect("get not before"), epoch);
        assert_eq!(claims.get_issued_at().expect("get issued at"), epoch);
        assert_eq!(claims.get_token_identifier().expect("get token id"), "jti");
    }

    #[test]
    fn custom_claims() {
        let mut claims = Claims::new()
            .set_subject("sub")
            .expect("set subject")
            .set_custom_claim("hello", "world")
            .expect("set custom claim");

        assert_eq!(
            claims.clone().set_custom_claim("sub", "fail"),
            Err(Error::RegisteredClaim)
        );

        assert_eq!(
            claims.get_claim("hello").expect("get custom claim"),
            "world"
        );
    }

    #[test]
    fn non_expiring() {
        let claims = Claims::new()
            .set_non_expiring()
            .expect("set as non-expiring");

        assert_eq!(claims.0.get("exp"), None);
    }
}
