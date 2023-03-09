//! Auth server configuration.

use std::env::{var, VarError};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use ed25519_compact::SecretKey;
use pasetors::keys::AsymmetricSecretKey;
use pasetors::{keys::SymmetricKey, version4::V4};
use regex::Regex;
use thiserror::Error;
use tracing::{error, trace};

/// An error that occurs while generating the server configuration.
#[derive(Error, Clone, Debug)]
pub enum ConfigError {
    #[error("invalid environment variable")]
    InvalidEnvVar,
    #[error("invalid socket address")]
    InvalidAddr,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("invalid symmetric key")]
    InvalidSymmetricKey,
    #[error("invalid duration")]
    InvalidDuration,
    #[error("missing secret key")]
    MissingSecretKey,
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
pub const ENV_LISTEN_ADDR: &str = "POSER_AUTH_LISTEN_ADDR";
pub const ENV_DATABASE_URI: &str = "POSER_AUTH_DATABASE_URI";
pub const ENV_SHUTDOWN_GRACE_PERIOD: &str = "POSER_AUTH_SHUTDOWN_GRACE_PERIOD";

/// An OpenSSL-compatible, PEM encoded ed25519 private key.
pub const ENV_SECRET_KEY: &str = "POSER_AUTH_SECRET_KEY";

pub const ENV_COOKIE_NAME: &str = "POSER_AUTH_COOKIE_NAME";
pub const ENV_COOKIE_SECRET: &str = "POSER_AUTH_COOKIE_SECRET";

pub const ENV_GOOGLE_CLIENT_ID: &str = "POSER_AUTH_GOOGLE_CLIENT_ID";
pub const ENV_GOOGLE_CLIENT_SECRET: &str = "POSER_AUTH_GOOGLE_CLIENT_SECRET";
pub const ENV_GOOGLE_ALLOWED_DOMAINS: &str = "POSER_AUTH_GOOGLE_ALLOWED_DOMAINS";
pub const ENV_GOOGLE_AUTH_URL: &str = "POSER_AUTH_GOOGLE_AUTH_URL";
pub const ENV_GOOGLE_SERVICE_ACCOUNT: &str = "POSER_AUTH_GOOGLE_SERVICE_ACCOUNT";
pub const ENV_GOOGLE_ADMIN_EMAIL: &str = "POSER_AUTH_GOOGLE_ADMIN_EMAIL";

// Default values for some config options
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
pub const DEFAULT_DATABASE_URI: &str = "postgresql://poser@localhost/poser";
pub const DEFAULT_SHUTDOWN_GRACE_PERIOD: &str = "60s";

pub const DEFAULT_COOKIE_NAME: &str = "_poser_auth";

pub const DEFAULT_GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const DEFAULT_GOOGLE_SERVICE_ACCOUNT: &str = "/data/service_account.json";

/// The main application config.
#[derive(Clone, Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub database: String,
    pub key: AsymmetricSecretKey<V4>,
    pub cookie: CookieConfig,
    pub google: GoogleConfig,
    pub grace_period: Duration,
}

/// Settings related to handling cookies.
#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub name: String,
    pub secret: SymmetricKey<V4>,
}

/// Settings related to authenticating with Google.
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
    /// Try to generate a new Config with environment variables.
    pub fn try_env() -> Result<Self, ConfigError> {
        trace!("parsing config from environment variables");

        let addr_raw = get_env_default(ENV_LISTEN_ADDR, DEFAULT_LISTEN_ADDR)?;
        let addr = parse_socket_addr(addr_raw)?;

        let database = get_env_default(ENV_DATABASE_URI, DEFAULT_DATABASE_URI)?;

        let key_raw = get_env(ENV_SECRET_KEY)?.ok_or_else(|| {
            error!("expected private key");
            ConfigError::MissingSecretKey
        })?;
        let key = SecretKey::from_pem(&key_raw).map_err(|e| {
            error!("failed to parse private key: {}", e);
            ConfigError::InvalidSecretKey
        })?;
        let key = AsymmetricSecretKey::<V4>::from(&*key).unwrap();

        let cookie = {
            let name = get_env_default(ENV_COOKIE_NAME, DEFAULT_COOKIE_NAME)?;

            let secret_raw = get_env(ENV_COOKIE_SECRET)?.ok_or_else(|| {
                error!("expected cookie secret");
                ConfigError::MissingCookieSecret
            })?;
            let secret = parse_secret_key(secret_raw)?;

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

            let auth_url = get_env_default(ENV_GOOGLE_AUTH_URL, DEFAULT_GOOGLE_AUTH_URL)?;

            let service_account_file =
                get_env_default(ENV_GOOGLE_SERVICE_ACCOUNT, DEFAULT_GOOGLE_SERVICE_ACCOUNT)?.into();

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

        let grace_period_raw =
            get_env_default(ENV_SHUTDOWN_GRACE_PERIOD, DEFAULT_SHUTDOWN_GRACE_PERIOD)?;
        let grace_period = parse_duration(grace_period_raw)?;

        Ok(Config {
            addr,
            database,
            key,
            cookie,
            google,
            grace_period,
        })
    }
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

fn get_env_default(key: &str, default: &str) -> Result<String, ConfigError> {
    Ok(get_env(key)?.unwrap_or_else(|| default.to_string()))
}

fn parse_socket_addr(str: String) -> Result<SocketAddr, ConfigError> {
    str.parse().map_err(|_| {
        error!("could not parse socket address");
        ConfigError::InvalidAddr
    })
}

fn parse_secret_key(str: String) -> Result<SymmetricKey<V4>, ConfigError> {
    let decoded = Base64::decode_vec(&str).map_err(|_| {
        error!("failed to decode cookie secret as base64");
        ConfigError::InvalidBase64
    })?;

    SymmetricKey::<V4>::from(&decoded).map_err(|_| {
        error!("failed to interprete cookie secret as encryption key");
        ConfigError::InvalidSymmetricKey
    })
}

fn parse_duration(str: String) -> Result<Duration, ConfigError> {
    let re = Regex::new(r"^\s*(\d+)(ns|us|ms|s)?\s*$").expect("build duration regex");
    let caps = re.captures(&str).ok_or_else(|| {
        error!("unrecognised duration format");
        ConfigError::InvalidDuration
    })?;

    let value = (caps[1]).parse().map_err(|_| {
        error!("failed to parse number in duration");
        ConfigError::InvalidDuration
    })?;

    match caps.get(2).map(|m| m.as_str()) {
        Some("ns") => Ok(Duration::from_nanos(value)),
        Some("us") => Ok(Duration::from_micros(value)),
        Some("ms") => Ok(Duration::from_millis(value)),
        Some("s") => Ok(Duration::from_secs(value)),
        None => Ok(Duration::from_secs(value)),
        Some(s) => {
            error!("unrecognised duration suffix: {}", s);
            Err(ConfigError::InvalidDuration)
        }
    }
}
