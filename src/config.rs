use std::env::{var, VarError};
use std::net::SocketAddr;
use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use pasetors::{keys::SymmetricKey, version4::V4};
use thiserror::Error;
use tracing::error;

#[derive(Error, Clone, Debug)]
pub enum ConfigError {
    #[error("invalid environment variable")]
    InvalidEnvVar,
    #[error("invalid socket address")]
    InvalidAddr,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("invalid symmetric key")]
    InvalidSymmetricKey,
    #[error("missing cookie secret")]
    MissingCookieSecret,
    #[error("missing Google client id")]
    MissingClientId,
    #[error("missing Google client secret")]
    MissingClientSecret,
    #[error("missing Google admin email")]
    MissingAdminEmail,
}

// Environment variables for each config option
const ENV_LISTEN_ADDR: &str = "POSER_AUTH_LISTEN_ADDR";

const ENV_COOKIE_NAME: &str = "POSER_AUTH_COOKIE_NAME";
const ENV_COOKIE_SECRET: &str = "POSER_AUTH_COOKIE_SECRET";

const ENV_GOOGLE_CLIENT_ID: &str = "POSER_AUTH_GOOGLE_CLIENT_ID";
const ENV_GOOGLE_CLIENT_SECRET: &str = "POSER_AUTH_GOOGLE_CLIENT_SECRET";
const ENV_GOOGLE_ALLOWED_DOMAINS: &str = "POSER_AUTH_GOOGLE_ALLOWED_DOMAINS";
const ENV_GOOGLE_AUTH_URL: &str = "POSER_AUTH_GOOGLE_AUTH_URL";
const ENV_GOOGLE_SERVICE_ACCOUNT: &str = "POSER_AUTH_GOOGLE_SERVICE_ACCOUNT";
const ENV_GOOGLE_ADMIN_EMAIL: &str = "POSER_AUTH_GOOGLE_ADMIN_EMAIL";

// Default values for some config options
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";

const DEFAULT_COOKIE_NAME: &str = "_poser_auth";

const DEFAULT_GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_GOOGLE_SERVICE_ACCOUNT: &str = "/data/service_account.json";

#[derive(Clone, Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub cookie: CookieConfig,
    pub google: GoogleConfig,
}

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub name: String,
    pub secret: SymmetricKey<V4>,
}

#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub allowed_domains: Vec<String>,
    pub auth_url: String,
    pub service_account_file: PathBuf,
    pub admin_email: String,
}

impl Config {
    pub fn try_env() -> Result<Self, ConfigError> {
        parse_config()
    }
}

pub fn parse_config() -> Result<Config, ConfigError> {
    let addr = get_env(ENV_LISTEN_ADDR)?
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string())
        .parse()
        .map_err(|_| {
            error!("could not parse socket address");
            ConfigError::InvalidAddr
        })?;

    let cookie = {
        let name = get_env(ENV_COOKIE_NAME)?.unwrap_or_else(|| DEFAULT_COOKIE_NAME.to_string());

        let secret_encoded = get_env(ENV_COOKIE_SECRET)?.ok_or_else(|| {
            error!("expected cookie secret");
            ConfigError::MissingCookieSecret
        })?;
        let secret_decoded = Base64::decode_vec(&secret_encoded).map_err(|_| {
            error!("failed to decode cookie secret as base64");
            ConfigError::InvalidBase64
        })?;
        let secret = SymmetricKey::<V4>::from(&secret_decoded).map_err(|_| {
            error!("failed to interprete cookie secret as encryption key");
            ConfigError::InvalidSymmetricKey
        })?;

        CookieConfig { name, secret }
    };

    let google = {
        let client_id = get_env(ENV_GOOGLE_CLIENT_ID)?.ok_or_else(|| {
            error!("expected Google client id");
            ConfigError::MissingClientId
        })?;

        let client_secret = get_env(ENV_GOOGLE_CLIENT_SECRET)?.ok_or_else(|| {
            error!("expected Google client secret");
            ConfigError::MissingClientSecret
        })?;

        let allowed_domains = get_env(ENV_GOOGLE_ALLOWED_DOMAINS)?.map_or(Vec::new(), |d| {
            d.split(',').map(str::to_string).collect::<Vec<String>>()
        });

        let auth_url =
            get_env(ENV_GOOGLE_AUTH_URL)?.unwrap_or_else(|| DEFAULT_GOOGLE_AUTH_URL.to_string());

        let service_account_file = get_env(ENV_GOOGLE_SERVICE_ACCOUNT)?
            .unwrap_or_else(|| DEFAULT_GOOGLE_SERVICE_ACCOUNT.to_string())
            .into();

        let admin_email = get_env(ENV_GOOGLE_ADMIN_EMAIL)?.ok_or_else(|| {
            error!("expected Google admin email");
            ConfigError::MissingAdminEmail
        })?;

        GoogleConfig {
            client_id,
            client_secret,
            allowed_domains,
            auth_url,
            service_account_file,
            admin_email,
        }
    };

    Ok(Config {
        addr,
        cookie,
        google,
    })
}

fn get_env(key: &str) -> Result<Option<String>, ConfigError> {
    match var(key) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => {
            error!("{} is not unicode", key);
            Err(ConfigError::InvalidEnvVar)
        }
    }
}
