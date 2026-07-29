//! IRC client wrapper for the MLS Test Bot
//!
//! Provides async IRC connection management with automatic reconnection,
//! rate-limited message sending, and graceful shutdown.
//!
//! Uses the `irc` crate (v1.1.0) matching the fish_11_relay pattern.

use std::time::Duration;

use anyhow::{Result, anyhow};
use futures::StreamExt;
use irc::client::prelude::*;
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::database::EncryptedStore;
use crate::dll_bridge::DllBridge;
use crate::handler;

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Base delay for exponential backoff reconnection
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(5);

/// Maximum delay between reconnection attempts
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(300);

/// IRC client wrapper
pub struct IrcClient {
    config: AppConfig,
    bridge: DllBridge,
    store: EncryptedStore,
}

impl IrcClient {
    /// Create a new IRC client wrapper.
    pub fn new(config: AppConfig, bridge: DllBridge, store: EncryptedStore) -> Self {
        Self { config, bridge, store }
    }

    /// Run the IRC client with automatic reconnection.
    ///
    /// Connects to the configured IRC server, identifies, and processes
    /// messages until a shutdown signal is received or reconnection fails.
    pub async fn run(&self, mut shutdown_rx: tokio::sync::mswc::Receiver<()>) -> Result<()> {
        let mut attempt = 0u32;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("IRC client shutting down");
                    return Ok(());
                }
                result = self.connect_and_listen(&mut attempt) => {
                    match result {
                        Ok(()) => {
                            // Normal disconnect, attempt reconnection
                            attempt += 1;
                        }
                        Err(e) => {
                            error!("IRC error: {}", e);
                            attempt += 1;
                        }
                    }

                    if attempt >= MAX_RECONNECT_ATTEMPTS {
                        return Err(anyhow!(
                            "IRC reconnection failed after {} attempts", MAX_RECONNECT_ATTEMPTS
                        ));
                    }

                    let delay = std::cmp::min(
                        RECONNECT_BASE_DELAY * 2u32.saturating_pow(attempt),
                        RECONNECT_MAX_DELAY,
                    );
                    info!(
                        "Reconnecting to IRC in {:?} (attempt {}/{})",
                        delay, attempt, MAX_RECONNECT_ATTEMPTS
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Connect to IRC and listen for messages.
    async fn connect_and_listen(&self, attempt: &mut u32) -> Result<()> {
        let irc_config = self.config.to_irc_config();

        info!(
            "Connecting to {}:{} (TLS: {}) as '{}'...",
            self.config.server.address,
            self.config.server.port,
            self.config.server.use_tls,
            self.config.server.nickname,
        );

        let mut client = Client::from_config(irc_config).await
            .map_err(|e| anyhow!("Failed to create IRC client: {}", e))?;

        client.identify()
            .map_err(|e| anyhow!("Failed to identify on IRC: {}", e))?;

        info!("Connected to IRC as '{}'. Joining channels: {:?}",
              client.current_nickname(), self.config.server.channels);

        *attempt = 0;
        let mut stream = client.stream()?;

        while let Some(message_result) = stream.next().await {
            match message_result {
                Ok(message) => {
                    handler::handle_irc_message(
                        &client, &self.store, &self.bridge, &self.config, &message,
                    ).await;
                }
                Err(e) => {
                    warn!("IRC stream error: {}", e);
                    return Err(anyhow!("IRC stream error: {}", e));
                }
            }
        }

        warn!("Disconnected from IRC server");
        Ok(())
    }
}
