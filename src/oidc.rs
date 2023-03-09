//! Helper functions for performing the OIDC flow.

use crate::config::Config;

use anyhow::{anyhow, Result};
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
use serde::{Deserialize, Serialize};
use serde_json::from_value;
use thiserror::Error;
use tracing::error;

/// Errors while setting up OIDC.
#[derive(Error, Clone, Debug)]
pub enum SetupError {
    #[error("invalid issuer url")]
    InvalidIssuer,
    #[error("invalid revocation url")]
    InvalidRevocation,
    #[error("invalid redirect url")]
    InvalidRedirect,
    #[error("error during OIDC discovery")]
    DiscoveryError,
}

/// Errors generating values for OIDC.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("generated Paseto would have invalid claims")]
    InvalidClaim,
    #[error("failed to encrypt Paseto")]
    EncryptionError,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}

impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}

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
    pub fn new_request(redirect: &str) -> Self {
        // TODO: Generate random values
        Self {
            csrf: CsrfToken::new_random(),
            nonce: Nonce::new_random(),
            redirect: redirect.to_string(),
        }
    }

    pub fn from_tokens(state: &str, cookie: &str, key: &SymmetricKey<V4>) -> Result<Self> {
        let rules = ClaimsValidationRules::new();

        let untrusted_state = UntrustedToken::<Local, V4>::try_from(state)?;
        let state_token = decrypt(key, &untrusted_state, &rules, None, None)?;
        let untrusted_cookie = UntrustedToken::<Local, V4>::try_from(cookie)?;
        let cookie_token = decrypt(key, &untrusted_cookie, &rules, None, None)?;

        let state_claims = state_token
            .payload_claims()
            .ok_or_else(|| anyhow!("No claims found in state"))?;
        let cookie_claims = cookie_token
            .payload_claims()
            .ok_or_else(|| anyhow!("No claims found in cookie"))?;

        let state_csrf: CsrfToken = from_value(
            state_claims
                .get_claim("csrf")
                .ok_or_else(|| anyhow!("State missing csrf claim"))?
                .clone(),
        )?;
        let redirect = from_value(
            state_claims
                .get_claim("redirect")
                .ok_or_else(|| anyhow!("State missing redirect claim"))?
                .clone(),
        )?;
        let cookie_csrf: CsrfToken = from_value(
            cookie_claims
                .get_claim("csrf")
                .ok_or_else(|| anyhow!("Cookie missing csrf claim"))?
                .clone(),
        )?;
        let nonce = from_value(
            cookie_claims
                .get_claim("nonce")
                .ok_or_else(|| anyhow!("Cookie missing nonce claim"))?
                .clone(),
        )?;

        if state_csrf.secret() == cookie_csrf.secret() {
            Ok(Self {
                csrf: state_csrf,
                nonce,
                redirect,
            })
        } else {
            Err(anyhow!("CSRF tokens mismatch!"))
        }
    }

    pub fn get_redirect(&self) -> &str {
        &self.redirect
    }

    pub fn get_nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Generate the state parameter for an authorization request
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
    /// authorization request
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
