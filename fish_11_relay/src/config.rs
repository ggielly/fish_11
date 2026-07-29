//! FCEP-2 Relay Bot TOML Configuration Engine
//!
//! Loads and manages `fish_relay.ini` configuration (similar structure to `fish_11.ini`).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

pub const DEFAULT_CONFIG_FILE: &str = "fish_relay.ini";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub relay: RelayConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub use_tls: bool,
    /// Accept invalid/self-signed TLS certificates (default: false)
    #[serde(default)]
    pub danger_accept_invalid_certs: bool,
    pub nickname: String,
    pub username: String,
    pub realname: String,
    pub channels: Vec<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub max_keypackages_per_device: usize,
    pub welcome_ttl_days: u64,
    pub commit_history_limit: usize,
    pub rate_limit_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                address: "irc.libera.chat".to_string(),
                port: 6697,
                use_tls: true,
                danger_accept_invalid_certs: false,
                nickname: "FiSH_Relay".to_string(),
                username: "fishbot".to_string(),
                realname: "FiSH-11 FCEP-2 Synchronization Relay".to_string(),
                channels: vec!["#fish11".to_string()],
                password: None,
            },
            relay: RelayConfig {
                max_keypackages_per_device: 20,
                welcome_ttl_days: 14,
                commit_history_limit: 500,
                rate_limit_per_sec: 4,
            },
            storage: StorageConfig { data_dir: "./relay_data".to_string() },
        }
    }
}

impl AppConfig {
    /// Load configuration from TOML file, creating default `fish_relay.ini` if it does not exist
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        if !p.exists() {
            let default_cfg = AppConfig::default();
            let toml_str = toml::to_string_pretty(&default_cfg)
                .context("Failed to serialize default TOML configuration")?;

            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            fs::write(p, toml_str).with_context(|| {
                format!("Failed to create default config file at {}", p.display())
            })?;

            info!("Created default configuration file: {}", p.display());
            return Ok(default_cfg);
        }

        let content = fs::read_to_string(p)
            .with_context(|| format!("Failed to read config file at {}", p.display()))?;

        let config: AppConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML config from {}", p.display()))?;

        info!("Loaded configuration from {}", p.display());
        Ok(config)
    }

    /// Validate configuration values, returning an error if any are invalid.
    ///
    /// Checks:
    /// - `rate_limit_per_sec` must be >= 1 (avoid division by zero in rate limiter)
    /// - `max_keypackages_per_device` must be >= 1
    /// - `welcome_ttl_days` must be >= 1
    /// - `commit_history_limit` must be >= 1
    /// - `server.port` must be a valid port number (1–65535)
    pub fn validate(&self) -> Result<()> {
        if self.relay.rate_limit_per_sec < 1 {
            anyhow::bail!(
                "relay.rate_limit_per_sec must be >= 1, got {}",
                self.relay.rate_limit_per_sec
            );
        }
        if self.relay.max_keypackages_per_device < 1 {
            anyhow::bail!(
                "relay.max_keypackages_per_device must be >= 1, got {}",
                self.relay.max_keypackages_per_device
            );
        }
        if self.relay.welcome_ttl_days < 1 {
            anyhow::bail!(
                "relay.welcome_ttl_days must be >= 1, got {}",
                self.relay.welcome_ttl_days
            );
        }
        if self.relay.commit_history_limit < 1 {
            anyhow::bail!(
                "relay.commit_history_limit must be >= 1, got {}",
                self.relay.commit_history_limit
            );
        }
        if self.server.port == 0 {
            anyhow::bail!("server.port must be in range 1–65535, got 0");
        }
        Ok(())
    }

    /// Convert ServerConfig into `irc::config::Config` for the `irc` crate
    pub fn to_irc_config(&self) -> irc::client::data::Config {
        irc::client::data::Config {
            server: Some(self.server.address.clone()),
            port: Some(self.server.port),
            use_tls: Some(self.server.use_tls),
            nickname: Some(self.server.nickname.clone()),
            username: Some(self.server.username.clone()),
            realname: Some(self.server.realname.clone()),
            channels: self.server.channels.clone(),
            password: self.server.password.clone(),
            ..Default::default()
        }
    }
}
