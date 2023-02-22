use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use pasetors::{keys::SymmetricKey, version4::V4};
use serde::{Deserialize, Deserializer};

const DEFAULT_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const DEFAULT_PORT: u16 = 8080;

const DEFAULT_COOKIE_NAME: &str = "_poser_auth";

const DEFAULT_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default = "default_addr")]
    pub ip: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    pub cookie: CookieConfig,
    pub google: GoogleConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CookieConfig {
    #[serde(default = "default_cookie_name")]
    pub name: String,
    #[serde(deserialize_with = "from_base64")]
    pub secret: SymmetricKey<V4>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub allowed_domains: Vec<String>,
    #[serde(default = "default_auth_url")]
    pub auth_url: String,
    pub service_account_file: PathBuf,
    pub admin_email: String,
}

fn from_base64<'de, D>(deserializer: D) -> Result<SymmetricKey<V4>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer)
        .and_then(|s| Base64::decode_vec(&s).map_err(|e| Error::custom(e.to_string())))
        .and_then(|b| SymmetricKey::<V4>::from(&b).map_err(|e| Error::custom(e.to_string())))
}

const fn default_addr() -> IpAddr {
    DEFAULT_ADDR
}

const fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_cookie_name() -> String {
    DEFAULT_COOKIE_NAME.to_string()
}

fn default_auth_url() -> String {
    DEFAULT_AUTH_URL.to_string()
}
