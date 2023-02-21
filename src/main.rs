mod config;

use std::env::var;
use std::fs::read_to_string;
use std::path::PathBuf;

use config::Config;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version)]
/// poser is a simple, opinionated authentication provider for nginx
///
/// poser authenticates with Google using OpenID Connect and then uses the
/// Google Workspace Admin SDK to determine what groups a user is a part of.
/// Basic information about the users as well as what groups they are a part
/// of is returned to nginx in a PASETO v4 token, which is then passed to the
/// application.
struct Args {
    /// Configuration file
    #[arg(long, default_value = "/data/config/config.toml")]
    config: PathBuf,
}

fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let config: Config = toml::from_str(&read_to_string(&args.config).with_context(|| {
        format!(
            "Failed to read config file at {}",
            args.config.to_string_lossy()
        )
    })?)
    .context("Failed to parse config file")?;

    println!("{:#?}", config);

    Ok(())
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(var("RUST_LOG").unwrap_or("info".to_string()))
        .init();
}
