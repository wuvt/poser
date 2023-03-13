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
    ///
    /// # Examples
    ///
    /// ```
    /// # use poser::token::{Claims, Error};
    /// # use serde_json::Value;
    /// # fn try_main() -> Result<(), Error> {
    /// let claims = Claims::new()
    ///     .with_subject("poser")?
    ///     .with_custom_claim("name", "User")?;
    ///
    /// assert_eq!(claims.subject(), Some("poser"));
    /// assert_eq!(claims.get("name").and_then(Value::as_str), Some("User"));
    /// assert!(claims.expiration().unwrap() > claims.issued_at().unwrap());
    /// #     Ok(())
    /// # }
    /// # fn main() { try_main().unwrap(); }
    /// ```
    pub fn new() -> Self {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::hours(1);

        // the only possible way for formatting the time to fail is if it were
        // the year 10,000. I'm unwrapping for API cleanliness, sorry future.
        Self(HashMap::new())
            .with_expiration(&exp)
            .unwrap()
            .with_not_before(&iat)
            .unwrap()
            .with_issued_at(&iat)
            .unwrap()
    }

    /// Get the JSON value of a claim. While this can be used to access
    /// reserved claims, the convenience methods should be preferred as they
    /// additionally parse the value.
    ///
    /// Returns [`None`] if the claim is not set.
    pub fn get(&self, claim: &str) -> Option<&Value> {
        self.0.get(claim)
    }

    fn set_unchecked<V>(&mut self, claim: &str, value: V) -> Result<(), Error>
    where
        V: Serialize,
    {
        let value = serde_json::to_value(value).map_err(|_| Error::SerializeError)?;
        self.0.insert(claim.to_string(), value);

        Ok(())
    }

    /// Remove a claim.
    ///
    /// # Errors
    ///
    /// Will return an error if no claim with the given name is set.
    pub fn remove(&mut self, claim: &str) -> Result<(), Error> {
        self.0.remove(claim).ok_or(Error::MissingClaim)?;

        Ok(())
    }

    /// Make the token non-expiring by removing the expiration date from the
    /// claims set.
    ///
    /// # Errors
    ///
    /// Will return an error if no expiration is currently set.
    pub fn non_expiring(mut self) -> Result<Self, Error> {
        self.remove("exp").map_err(|_| Error::NonExpiring)?;

        Ok(self)
    }

    /// Set a non-registered claim to a JSON-serializable value.
    ///
    /// # Errors
    ///
    /// Returns an error when attempting to set a registered claim or when the
    /// provided value can't be serialized to JSON.
    pub fn with_custom_claim<V>(mut self, claim: &str, value: V) -> Result<Self, Error>
    where
        V: Serialize,
    {
        if REGISTERED_CLAIMS.contains(&claim) {
            Err(Error::RegisteredClaim)
        } else {
            self.set_unchecked(claim, value)?;

            Ok(self)
        }
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

impl Claims {
    /// Get the token issuer.
    ///
    /// Returns [`None`] if the issuer is not set.
    pub fn issuer(&self) -> Option<&str> {
        self.get("iss").and_then(Value::as_str)
    }

    /// Get the token subject.
    ///
    /// Returns [`None`] if the subject is not set.
    pub fn subject(&self) -> Option<&str> {
        self.get("sub").and_then(Value::as_str)
    }

    /// Get the token audience.
    ///
    /// Returns [`None`] if the audience is not set.
    pub fn audience(&self) -> Option<&str> {
        self.get("aud").and_then(Value::as_str)
    }

    /// Get the token expiration date.
    ///
    /// Returns [`None`] if the expiration date is not set.
    pub fn expiration(&self) -> Option<OffsetDateTime> {
        self.get("exp").and_then(Value::as_str).map(parse_time)
    }

    /// Get the token not before date.
    ///
    /// Returns [`None`] if the not before date is not set.
    pub fn not_before(&self) -> Option<OffsetDateTime> {
        self.get("nbf").and_then(Value::as_str).map(parse_time)
    }

    /// Get the token issued at date.
    ///
    /// Returns [`None`] if the issued at date is not set.
    pub fn issued_at(&self) -> Option<OffsetDateTime> {
        self.get("iat").and_then(Value::as_str).map(parse_time)
    }

    /// Get the token identifier.
    ///
    /// Returns [`None`] if the token identifier is not set.
    pub fn token_identifier(&self) -> Option<&str> {
        self.get("jti").and_then(Value::as_str)
    }
}

// WARN: only for use when the value is guaranteed to be valid RFC3339 (i.e.
// when it was set a setter using format_time)
fn parse_time(time: &str) -> OffsetDateTime {
    OffsetDateTime::parse(time, &Rfc3339).unwrap()
}

impl Claims {
    /// Set the token issuer.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn with_issuer(mut self, iss: &str) -> Result<Self, Error> {
        if iss.is_empty() {
            Err(Error::EmptyClaim)
        } else {
            self.set_unchecked("iss", iss)?;

            Ok(self)
        }
    }

    /// Set the token subject.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn with_subject(mut self, sub: &str) -> Result<Self, Error> {
        if sub.is_empty() {
            Err(Error::EmptyClaim)
        } else {
            self.set_unchecked("sub", sub)?;

            Ok(self)
        }
    }

    /// Set the token subject.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn with_audience(mut self, aud: &str) -> Result<Self, Error> {
        if aud.is_empty() {
            Err(Error::EmptyClaim)
        } else {
            self.set_unchecked("aud", aud)?;

            Ok(self)
        }
    }

    /// Set the token expiration date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn with_expiration(mut self, exp: &OffsetDateTime) -> Result<Self, Error> {
        self.set_unchecked("exp", format_time(exp)?)?;

        Ok(self)
    }

    /// Set the token not before date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn with_not_before(mut self, nbf: &OffsetDateTime) -> Result<Self, Error> {
        self.set_unchecked("nbf", format_time(nbf)?)?;

        Ok(self)
    }

    /// Set the token issued at date.
    ///
    /// # Errors
    ///
    /// Will return an error if the provided OffsetDateTime cannot be
    /// represented as an RFC3339 timestamp.
    pub fn with_issued_at(mut self, iat: &OffsetDateTime) -> Result<Self, Error> {
        self.set_unchecked("iat", format_time(iat)?)?;

        Ok(self)
    }

    /// Set the token identifier.
    ///
    /// # Errors
    ///
    /// Will return an error if given an empty string.
    pub fn with_token_identifier(mut self, jti: &str) -> Result<Self, Error> {
        if jti.is_empty() {
            Err(Error::EmptyClaim)
        } else {
            self.set_unchecked("jti", jti)?;

            Ok(self)
        }
    }
}

fn format_time(time: &OffsetDateTime) -> Result<String, Error> {
    time.format(&Rfc3339).map_err(|_| Error::SerializeError)
}

/// A collection of rules to validate a set of claims against.
pub struct ClaimsValidator(Vec<Box<dyn Fn(&Claims) -> bool>>);

impl ClaimsValidator {
    /// Create a claims validator. By default, the validator will check that
    /// "Not Before" is set and before the current time, "Issued At" is set
    /// and before the current time, and "Expiration" is set and after the
    /// current time.
    pub fn new() -> Self {
        Self::empty().with_rule(default_rule)
    }

    /// Create a claims validator without the default validation rules.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Add a new rule to a claims validator.
    pub fn with_rule<F: Fn(&Claims) -> bool + 'static>(mut self, rule: F) -> Self {
        self.0.push(Box::new(rule));

        self
    }

    /// Validate a set of claims with a claims validator.
    pub fn validate(&self, claims: &Claims) -> bool {
        for f in &self.0 {
            if !f(claims) {
                return false;
            }
        }

        true
    }
}

fn default_rule(claims: &Claims) -> bool {
    if let Some(exp) = claims.expiration() {
        if let Some(nbf) = claims.not_before() {
            if let Some(iat) = claims.issued_at() {
                let now = OffsetDateTime::now_utc();

                return exp >= now && nbf <= now && iat <= now;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_claims() {
        let now = OffsetDateTime::now_utc();
        let now_offset = now + Duration::hours(1);

        let claims = Claims::new();
        let exp = claims.expiration().expect("get expiration claim");
        let nbf = claims.not_before().expect("get not before claim");
        let iat = claims.issued_at().expect("get issued at claim");

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
        claims = claims.with_issuer("iss").expect("set issuer");
        claims = claims.with_subject("sub").expect("set subject");
        claims = claims.with_audience("aud").expect("set audience");
        claims = claims.with_expiration(&epoch).expect("set expiration");
        claims = claims.with_not_before(&epoch).expect("set not before");
        claims = claims.with_issued_at(&epoch).expect("set issued t");
        claims = claims.with_token_identifier("jti").expect("set token id");

        assert_eq!(claims.issuer().expect("get issuer"), "iss");
        assert_eq!(claims.subject().expect("get subject"), "sub");
        assert_eq!(claims.audience().expect("get audience"), "aud");
        assert_eq!(claims.expiration().expect("get expiration"), epoch);
        assert_eq!(claims.not_before().expect("get not before"), epoch);
        assert_eq!(claims.issued_at().expect("get issued at"), epoch);
        assert_eq!(claims.token_identifier().expect("get token id"), "jti");
    }

    #[test]
    fn custom_claims() {
        let claims = Claims::new()
            .with_subject("sub")
            .expect("set subject")
            .with_custom_claim("hello", "world")
            .expect("set custom claim");

        assert_eq!(
            claims.clone().with_custom_claim("sub", "fail"),
            Err(Error::RegisteredClaim)
        );

        assert_eq!(claims.get("hello").expect("get custom claim"), "world");
    }

    #[test]
    fn non_expiring() {
        let claims = Claims::new().non_expiring().expect("set as non-expiring");

        assert_eq!(claims.0.get("exp"), None);
    }

    #[test]
    fn validation() {
        let validator = ClaimsValidator::new();

        let normal = Claims::new();
        assert!(validator.validate(&normal));

        let bad_exp = Claims::new()
            .with_expiration(&OffsetDateTime::UNIX_EPOCH)
            .expect("set expiration");
        assert!(!validator.validate(&bad_exp));

        let now_offset = OffsetDateTime::now_utc() + Duration::hours(1);

        let bad_nbf = Claims::new()
            .with_not_before(&now_offset)
            .expect("set not before");
        assert!(!validator.validate(&bad_nbf));

        let bad_iat = Claims::new()
            .with_issued_at(&now_offset)
            .expect("set issued at");
        assert!(!validator.validate(&bad_iat));
    }
}
