//! Helpers for performing the OpenID Connect flow.

use crate::config::Config;
use crate::token::{claims, Claims, ClaimsValidator, SecretKey};

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
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
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
    #[error("missing csrf claim")]
    MissingCsrf,
    #[error("missing redirect claim")]
    MissingRedirect,
    #[error("missing nonce claim")]
    MissingNonce,
    #[error("error working with paseto claims: {0}")]
    ClaimsError(#[from] claims::Error),
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
    pub fn from_tokens(state: &str, cookie: &str, key: &SecretKey) -> Result<Self, Error> {
        let state_claims = get_claims(state, key)?;
        let cookie_claims = get_claims(cookie, key)?;

        let state_csrf: CsrfToken = state_claims.get_value("csrf").ok_or_else(|| {
            error!("state missing csrf claim");
            Error::MissingCsrf
        })??;
        let redirect = state_claims.get_value("redirect").ok_or_else(|| {
            error!("state missing redirect claim");
            Error::MissingRedirect
        })??;
        let cookie_csrf: CsrfToken = cookie_claims.get_value("csrf").ok_or_else(|| {
            error!("cookie missing csrf claim");
            Error::MissingCsrf
        })??;
        let nonce = cookie_claims.get_value("nonce").ok_or_else(|| {
            error!("cookie missing nonce claim");
            Error::MissingNonce
        })??;

        if state_csrf
            .secret()
            .as_bytes()
            .ct_eq(cookie_csrf.secret().as_bytes())
            .into()
        {
            Ok(Self {
                csrf: state_csrf,
                nonce,
                redirect,
            })
        } else {
            error!("csrf tokens dont match!");
            Err(Error::CsrfMismatch)
        }
    }

    pub fn get_redirect(&self) -> &str {
        &self.redirect
    }

    pub fn get_nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Generate the state parameter for an authorization request.
    pub fn to_state(&self, key: &SecretKey) -> Result<String, Error> {
        let claims = Claims::new()
            .with_custom_claim("csrf", self.csrf.secret().clone())?
            .with_custom_claim("redirect", self.redirect.clone())?;

        key.encrypt(&claims, None, None).map_err(|e| {
            error!("error encrypting Paseto: {}", e);
            Error::EncryptionError
        })
    }

    /// Generate a browser cookie for use in verifying the result of an
    /// authorization request.
    pub fn to_cookie(&self, key: &SecretKey) -> Result<String, Error> {
        let claims = Claims::new()
            .with_custom_claim("csrf", self.csrf.secret().clone())?
            .with_custom_claim("nonce", self.nonce.secret().clone())?;

        key.encrypt(&claims, None, None).map_err(|e| {
            error!("error encrypting Paseto: {}", e);
            Error::EncryptionError
        })
    }
}

fn get_claims(token: &str, key: &SecretKey) -> Result<Claims, Error> {
    let rules = ClaimsValidator::new();

    key.decrypt(token, &rules, None).map_err(|e| {
        error!("error decrypting token: {}", e);
        Error::InvalidToken
    })
}
