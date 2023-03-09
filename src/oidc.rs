//! Helpers for performing the OpenID Connect flow.

use crate::config::Config;

use openidconnect::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod,
        CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
    },
    reqwest::async_http_client,
    AdditionalProviderMetadata, CsrfToken, IssuerUrl, Nonce, ProviderMetadata, RedirectUrl,
    RevocationUrl,
};
use pasetors::{
    claims::{Claims, ClaimsValidationRules},
    keys::SymmetricKey,
    local::{decrypt, encrypt},
    token::UntrustedToken,
    version4::V4,
    Local,
};
use ring::constant_time::verify_slices_are_equal;
use serde::{Deserialize, Serialize};
use serde_json::from_value;
use thiserror::Error;
use tracing::error;

/// Errors while setting up OpenID Connect.
#[derive(Error, Clone, Debug)]
pub enum SetupError {
    #[error("invalid issuer url")]
    InvalidIssuer,
    #[error("invalid revocation url")]
    InvalidRevocation,
    #[error("invalid redirect url")]
    InvalidRedirect,
    #[error("error during oidc discovery")]
    DiscoveryError,
}

/// Errors during the OpenID Connect flow.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("generated paseto would have invalid claims")]
    InvalidClaim,
    #[error("invalid paseto token")]
    InvalidToken,
    #[error("invalid csrf claim")]
    InvalidCsrf,
    #[error("invalid redirect claim")]
    InvalidRedirect,
    #[error("invalid nonce claim")]
    InvalidNonce,
    #[error("missing csrf claim")]
    MissingCsrf,
    #[error("missing redirect claim")]
    MissingRedirect,
    #[error("missing nonce claim")]
    MissingNonce,
    #[error("failed to encrypt paseto")]
    EncryptionError,
    #[error("csrf tokens don't match")]
    CsrfMismatch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}

impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}

/// Prepare an authentication client for Google using OpenID Connect
/// Discovery.
pub async fn setup_auth(config: &Config) -> Result<CoreClient, SetupError> {
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string()).map_err(|e| {
        error!("error setting up issuer url: {}", e);
        SetupError::InvalidIssuer
    })?;

    let provider_metadata = ProviderMetadata::<
        RevocationEndpointProviderMetadata,
        CoreAuthDisplay,
        CoreClientAuthMethod,
        CoreClaimName,
        CoreClaimType,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >::discover_async(issuer_url, async_http_client)
    .await
    .map_err(|e| {
        error!("failed OIDC discovery: {}", e);
        SetupError::DiscoveryError
    })?;

    let revocation_endpoint = provider_metadata
        .additional_metadata()
        .revocation_endpoint
        .clone();

    let mut redirect_url = config.site_url.clone();
    redirect_url.set_path("callback");

    Ok(CoreClient::from_provider_metadata(
        provider_metadata,
        config.google.client_id.clone(),
        Some(config.google.client_secret.clone()),
    )
    .set_revocation_uri(RevocationUrl::new(revocation_endpoint).map_err(|e| {
        error!("Google returned an invalid revocation url: {}", e);
        SetupError::InvalidRevocation
    })?)
    .set_redirect_uri(RedirectUrl::new(redirect_url.into()).map_err(|e| {
        error!("invalid redirect url: {}", e);
        SetupError::InvalidRedirect
    })?))
}

#[derive(Clone, Debug)]
pub struct OidcState {
    csrf: CsrfToken,
    nonce: Nonce,
    redirect: String,
}

impl OidcState {
    /// Randomly generate new state parameters for an OpenID Connect flow
    /// given a redirect URL.
    pub fn new_request(redirect: &str) -> Self {
        Self {
            csrf: CsrfToken::new_random(),
            nonce: Nonce::new_random(),
            redirect: redirect.to_string(),
        }
    }

    /// Validate if an OpenID Connect authentication request was successful
    /// given the returned state and browser CSRF cookie.
    pub fn from_tokens(state: &str, cookie: &str, key: &SymmetricKey<V4>) -> Result<Self, Error> {
        let state_claims = get_claims(state, key)?;
        let cookie_claims = get_claims(cookie, key)?;

        let state_csrf = state_claims.get_claim("csrf").ok_or_else(|| {
            error!("state missing csrf claim");
            Error::MissingCsrf
        })?;
        let redirect = state_claims.get_claim("redirect").ok_or_else(|| {
            error!("state missing redirect claim");
            Error::MissingRedirect
        })?;
        let cookie_csrf = cookie_claims.get_claim("csrf").ok_or_else(|| {
            error!("cookie missing csrf claim");
            Error::MissingCsrf
        })?;
        let nonce = cookie_claims.get_claim("nonce").ok_or_else(|| {
            error!("cookie missing nonce claim");
            Error::MissingNonce
        })?;

        let state_csrf: CsrfToken = from_value(state_csrf.clone()).map_err(|e| {
            error!("unable to parse state csrf token: {}", e);
            Error::InvalidCsrf
        })?;
        let redirect = from_value(redirect.clone()).map_err(|e| {
            error!("unable to parse state redirect value: {}", e);
            Error::InvalidRedirect
        })?;
        let cookie_csrf: CsrfToken = from_value(cookie_csrf.clone()).map_err(|e| {
            error!("unable to parse cookie csrf token: {}", e);
            Error::InvalidCsrf
        })?;
        let nonce = from_value(nonce.clone()).map_err(|e| {
            error!("unable to parse cookie nonce value: {}", e);
            Error::InvalidNonce
        })?;

        verify_slices_are_equal(
            state_csrf.secret().as_bytes(),
            cookie_csrf.secret().as_bytes(),
        )
        .map_err(|_| {
            error!("csrf tokens dont match!");
            Error::CsrfMismatch
        })
        .map(|_| Self {
            csrf: state_csrf,
            nonce,
            redirect,
        })
    }

    pub fn get_redirect(&self) -> &str {
        &self.redirect
    }

    pub fn get_nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Generate the state parameter for an authorization request.
    pub fn to_state(&self, key: &SymmetricKey<V4>) -> Result<String, Error> {
        let mut claims = Claims::new().map_err(|e| {
            error!("error generating Paseto claims: {}", e);
            Error::InvalidClaim
        })?;

        // unwrap is safe since Claims::add_additional only returns an error
        // when the claim name matches a reserved name, which none of these do
        claims
            .add_additional("csrf", self.csrf.secret().clone())
            .unwrap();
        claims
            .add_additional("redirect", self.redirect.clone())
            .unwrap();

        encrypt(key, &claims, None, None).map_err(|e| {
            error!("error encrypting Paseto: {}", e);
            Error::EncryptionError
        })
    }

    /// Generate a browser cookie for use in verifying the result of an
    /// authorization request.
    pub fn to_cookie(&self, key: &SymmetricKey<V4>) -> Result<String, Error> {
        let mut claims = Claims::new().map_err(|e| {
            error!("error generating Paseto claims: {}", e);
            Error::InvalidClaim
        })?;

        // unwrap is safe since Claims::add_additional only returns an error
        // when the claim name matches a reserved name, which none of these do
        claims
            .add_additional("csrf", self.csrf.secret().clone())
            .unwrap();
        claims
            .add_additional("nonce", self.nonce.secret().clone())
            .unwrap();

        encrypt(key, &claims, None, None).map_err(|e| {
            error!("error encrypting Paseto: {}", e);
            Error::EncryptionError
        })
    }
}

fn get_claims(token: &str, key: &SymmetricKey<V4>) -> Result<Claims, Error> {
    let rules = ClaimsValidationRules::new();

    let token = UntrustedToken::<Local, V4>::try_from(token).map_err(|e| {
        error!("error parsing token: {}", e);
        Error::InvalidToken
    })?;

    let token = decrypt(key, &token, &rules, None, None).map_err(|e| {
        error!("error decrypting token: {}", e);
        Error::InvalidToken
    })?;

    token
        .payload_claims()
        .ok_or_else(|| {
            error!("no claims found on token");
            Error::InvalidToken
        })
        .map(|c| c.clone())
}
