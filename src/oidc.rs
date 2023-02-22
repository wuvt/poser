use anyhow::{anyhow, Result};
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

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OidcState {
    csrf: [u8; 16],
    nonce: [u8; 16],
    redirect: String,
}

impl OidcState {
    pub fn new_request(redirect: &str) -> Self {
        // TODO: Generate random values
        Self {
            csrf: [0; 16],
            nonce: [0; 16],
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

        let state_csrf: [u8; 16] = from_value(
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
        let cookie_csrf: [u8; 16] = from_value(
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

        if state_csrf == cookie_csrf {
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

    pub fn to_state_token(&self, key: &SymmetricKey<V4>) -> Result<String> {
        let mut claims = Claims::new()?;
        claims.add_additional("csrf", self.csrf.to_vec())?;
        claims.add_additional("redirect", self.redirect.clone())?;

        let token = encrypt(key, &claims, None, None)?;

        Ok(token)
    }

    pub fn to_state_cookie(&self, key: &SymmetricKey<V4>) -> Result<String> {
        let mut claims = Claims::new()?;
        claims.add_additional("csrf", self.csrf.to_vec())?;
        claims.add_additional("nonce", self.nonce.to_vec())?;

        let token = encrypt(key, &claims, None, None)?;

        Ok(token)
    }
}
