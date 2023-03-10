//! Auth server configuration.

use std::env::{var, VarError};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::token::SigningKey;

use ct_codecs::{Base64, Decoder};
use openidconnect::{url::Url, ClientId, ClientSecret};
use pasetors::{keys::SymmetricKey, version4::V4};
use regex::Regex;
use thiserror::Error;
use tracing::{error, trace};

/// An error that occurs while generating the server configuration.
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error("invalid environment variable")]
    InvalidEnvVar,
    #[error("invalid socket address")]
    InvalidAddr,
    #[error("invalid URL")]
    InvalidUrl,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid boolean value")]
    InvalidBool,
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
pub const ENV_SITE_URL: &str = "POSER_AUTH_SITE_URL";
pub const ENV_DATABASE_URI: &str = "POSER_AUTH_DATABASE_URI";
pub const ENV_SHUTDOWN_GRACE_PERIOD: &str = "POSER_AUTH_SHUTDOWN_GRACE_PERIOD";

/// An OpenSSL-compatible, PEM encoded ed25519 private key.
pub const ENV_SECRET_KEY: &str = "POSER_AUTH_SECRET_KEY";

pub const ENV_COOKIE_NAME: &str = "POSER_AUTH_COOKIE_NAME";
pub const ENV_COOKIE_SECRET: &str = "POSER_AUTH_COOKIE_SECRET";
pub const ENV_COOKIE_SECURE: &str = "POSER_AUTH_COOKIE_SECURE";

pub const ENV_GOOGLE_CLIENT_ID: &str = "POSER_AUTH_GOOGLE_CLIENT_ID";
pub const ENV_GOOGLE_CLIENT_SECRET: &str = "POSER_AUTH_GOOGLE_CLIENT_SECRET";
pub const ENV_GOOGLE_ALLOWED_DOMAINS: &str = "POSER_AUTH_GOOGLE_ALLOWED_DOMAINS";
pub const ENV_GOOGLE_EMAIL_DOMAIN: &str = "POSER_AUTH_GOOGLE_EMAIL_DOMAIN";
pub const ENV_GOOGLE_SERVICE_ACCOUNT: &str = "POSER_AUTH_GOOGLE_SERVICE_ACCOUNT";
pub const ENV_GOOGLE_ADMIN_EMAIL: &str = "POSER_AUTH_GOOGLE_ADMIN_EMAIL";

// Default values for some config options
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
pub const DEFAULT_SITE_URL: &str = "http://localhost:8080";
pub const DEFAULT_DATABASE_URI: &str = "postgresql://poser@localhost/poser";
pub const DEFAULT_SHUTDOWN_GRACE_PERIOD: &str = "60s";

pub const DEFAULT_COOKIE_NAME: &str = "_poser_auth";
pub const DEFAULT_COOKIE_SECURE: &str = "true";

pub const DEFAULT_GOOGLE_SERVICE_ACCOUNT: &str = "/data/service_account.json";

/// The main application config.
#[derive(Clone, Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub database: String,
    pub site_url: Url,
    pub key: SigningKey,
    pub cookie: CookieConfig,
    pub google: GoogleConfig,
    pub grace_period: Duration,
}

/// Settings related to handling cookies.
#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub name: String,
    pub secret: SymmetricKey<V4>,
    pub secure: bool,
}

/// Settings related to authenticating with Google.
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub allowed_domains: Vec<String>,
    pub email_domain: Option<String>,
    pub service_account_file: PathBuf,
    pub admin_email: String,
}

impl Config {
    /// Try to generate a new Config with environment variables.
    pub fn try_env() -> Result<Self, Error> {
        trace!("parsing config from environment variables");

        let addr_raw = get_env_default(ENV_LISTEN_ADDR, DEFAULT_LISTEN_ADDR)?;
        let addr = parse_socket_addr(addr_raw)?;

        let database = get_env_default(ENV_DATABASE_URI, DEFAULT_DATABASE_URI)?;

        let site_url_raw = get_env_default(ENV_SITE_URL, DEFAULT_SITE_URL)?;
        let site_url = parse_url(site_url_raw)?;

        let key_raw = get_env(ENV_SECRET_KEY)?.ok_or_else(|| {
            error!("expected private key");
            Error::MissingSecretKey
        })?;
        let key = SigningKey::from_pem(&key_raw).map_err(|_| {
            error!("failed to parse private key");
            Error::InvalidSecretKey
        })?;

        let cookie = {
            let name = get_env_default(ENV_COOKIE_NAME, DEFAULT_COOKIE_NAME)?;

            let secret_raw = get_env(ENV_COOKIE_SECRET)?.ok_or_else(|| {
                error!("expected cookie secret");
                Error::MissingCookieSecret
            })?;
            let secret = parse_secret_key(secret_raw)?;

            let secure_raw = get_env_default(ENV_COOKIE_SECURE, DEFAULT_COOKIE_SECURE)?;
            let secure = parse_bool(secure_raw)?;

            CookieConfig {
                name,
                secret,
                secure,
            }
        };

        let google = {
            let client_id = get_env(ENV_GOOGLE_CLIENT_ID)?.ok_or_else(|| {
                error!("expected Google client id");
                Error::MissingClientId
            })?;

            let client_secret = get_env(ENV_GOOGLE_CLIENT_SECRET)?.ok_or_else(|| {
                error!("expected Google client secret");
                Error::MissingClientSecret
            })?;

            let allowed_domains = get_env(ENV_GOOGLE_ALLOWED_DOMAINS)?.map_or(Vec::new(), |d| {
                d.split(',').map(str::to_string).collect::<Vec<String>>()
            });

            let email_domain = get_env(ENV_GOOGLE_EMAIL_DOMAIN)?;

            let service_account_file =
                get_env_default(ENV_GOOGLE_SERVICE_ACCOUNT, DEFAULT_GOOGLE_SERVICE_ACCOUNT)?.into();

            let admin_email = get_env(ENV_GOOGLE_ADMIN_EMAIL)?.ok_or_else(|| {
                error!("expected Google admin email");
                Error::MissingAdminEmail
            })?;

            GoogleConfig {
                client_id: ClientId::new(client_id),
                client_secret: ClientSecret::new(client_secret),
                allowed_domains,
                email_domain,
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
            site_url,
            key,
            cookie,
            google,
            grace_period,
        })
    }
}

fn get_env(key: &str) -> Result<Option<String>, Error> {
    match var(key) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => {
            error!("{} is not unicode", key);
            Err(Error::InvalidEnvVar)
        }
    }
}

fn get_env_default(key: &str, default: &str) -> Result<String, Error> {
    Ok(get_env(key)?.unwrap_or_else(|| default.to_string()))
}

fn parse_socket_addr(str: String) -> Result<SocketAddr, Error> {
    str.parse().map_err(|_| {
        error!("could not parse socket address");
        Error::InvalidAddr
    })
}

fn parse_url(str: String) -> Result<Url, Error> {
    str.parse().map_err(|_| {
        error!("could not parse url");
        Error::InvalidUrl
    })
}

fn parse_secret_key(str: String) -> Result<SymmetricKey<V4>, Error> {
    let decoded = Base64::decode_to_vec(str, None).map_err(|_| {
        error!("failed to decode cookie secret as base64");
        Error::InvalidBase64
    })?;

    SymmetricKey::<V4>::from(&decoded).map_err(|_| {
        error!("failed to interprete cookie secret as encryption key");
        Error::InvalidSymmetricKey
    })
}

fn parse_bool(str: String) -> Result<bool, Error> {
    str.parse().map_err(|_| {
        error!("could not parse boolean");
        Error::InvalidBool
    })
}

fn parse_duration(str: String) -> Result<Duration, Error> {
    let re = Regex::new(r"^\s*(\d+)(ns|us|ms|s)?\s*$").expect("build duration regex");
    let caps = re.captures(&str).ok_or_else(|| {
        error!("unrecognised duration format");
        Error::InvalidDuration
    })?;

    let value = (caps[1]).parse().map_err(|_| {
        error!("failed to parse number in duration");
        Error::InvalidDuration
    })?;

    match caps.get(2).map(|m| m.as_str()) {
        Some("ns") => Ok(Duration::from_nanos(value)),
        Some("us") => Ok(Duration::from_micros(value)),
        Some("ms") => Ok(Duration::from_millis(value)),
        Some("s") => Ok(Duration::from_secs(value)),
        None => Ok(Duration::from_secs(value)),
        Some(s) => {
            error!("unrecognised duration suffix: {}", s);
            Err(Error::InvalidDuration)
        }
    }
}
