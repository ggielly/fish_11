//! Backlog TCP client for connecting to remote MLS peers
//!
//! Provides an async client that connects to other bots' backlog servers
//! (§11.4, §18.3) for direct KeyPackage exchange, Welcome delivery, and
//! Commit synchronisation outside IRC.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde_json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

use crate::backlog_server::BacklogMessage;

/// Backlog client for outbound connections to peer backlog servers
pub struct BacklogClient {
    addr: String,
    device_id: String,
    reconnect_secs: u64,
}

impl BacklogClient {
    /// Create a new backlog client.
    ///
    /// `addr` should be `host:port` of the remote backlog server.
    /// `device_id` is this bot's device identifier for PeerAnnounce.
    pub fn new(addr: String, device_id: String, reconnect_secs: u64) -> Self {
        Self { addr, device_id, reconnect_secs }
    }

    /// Connect to a peer backlog server and return a channel sender for outgoing messages.
    ///
    /// Automatically announces this device upon connection and sends periodic
    /// Ping heartbeats for NAT binding refresh.
    pub async fn connect(&self) -> Result<mpsc::Sender<BacklogMessage>> {
        let (tx, mut rx) = mpsc::channel::<BacklogMessage>(128);

        let stream = TcpStream::connect(&self.addr).await.map_err(|e| {
            anyhow::anyhow!("Failed to connect to backlog peer {}: {}", self.addr, e)
        })?;

        let peer_addr = stream.peer_addr().ok();
        info!(
            "Connected to backlog peer {} ({})",
            self.addr,
            peer_addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into())
        );

        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));

        // Send PeerAnnounce
        let announce = BacklogMessage::PeerAnnounce {
            device_id: self.device_id.clone(),
            endpoint: String::new(), // Will be filled by caller
            capabilities: vec!["fcep2".into(), "backlog-v1".into()],
        };
        {
            let mut w = writer.lock().await;
            let json = serde_json::to_vec(&announce)?;
            let len = (json.len() as u32).to_be_bytes();
            w.write_all(&len).await?;
            w.write_all(&json).await?;
        }
        debug!("Sent PeerAnnounce to {}", self.addr);

        // Reader task
        let addr_clone = self.addr.clone();
        let writer_for_reader = writer.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut len_buf = [0u8; 4];

            loop {
                match reader.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        debug!("Backlog peer {} closed connection", addr_clone);
                        break;
                    }
                    Err(e) => {
                        warn!("Backlog read error from {}: {}", addr_clone, e);
                        break;
                    }
                }

                let payload_len = u32::from_be_bytes(len_buf) as usize;
                if payload_len > 16 * 1024 * 1024 {
                    warn!("Oversized message from {}, skipping", addr_clone);
                    continue;
                }

                let mut payload = vec![0u8; payload_len];
                if reader.read_exact(&mut payload).await.is_err() {
                    break;
                }

                match serde_json::from_slice::<BacklogMessage>(&payload) {
                    Ok(BacklogMessage::Ping { timestamp }) => {
                        let pong = BacklogMessage::Pong { timestamp };
                        if let Ok(json) = serde_json::to_vec(&pong) {
                            let len = (json.len() as u32).to_be_bytes();
                            let mut w = writer_for_reader.lock().await;
                            let _ = w.write_all(&len).await;
                            let _ = w.write_all(&json).await;
                        }
                    }
                    Ok(BacklogMessage::Disconnect { reason }) => {
                        info!("Peer {} disconnected: {}", addr_clone, reason);
                        break;
                    }
                    Ok(msg) => {
                        debug!("Received backlog message from {}: {:?}", addr_clone, msg);
                    }
                    Err(e) => {
                        debug!("Invalid message from {}: {}", addr_clone, e);
                    }
                }
            }
        });

        // Writer task: forward messages from channel to the TCP stream
        let addr_clone = self.addr.clone();
        let writer_for_writer = writer.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        match serde_json::to_vec(&msg) {
                            Ok(json) => {
                                let len = (json.len() as u32).to_be_bytes();
                                let mut w = writer_for_writer.lock().await;
                                if let Err(e) = w.write_all(&len).await {
                                    error!("Failed to write to backlog peer {}: {}", addr_clone, e);
                                    break;
                                }
                                if let Err(e) = w.write_all(&json).await {
                                    error!("Failed to write payload to {}: {}", addr_clone, e);
                                    break;
                                }
                            }
                            Err(e) => warn!("Failed to serialize backlog message: {}", e),
                        }
                    }
                    _ = interval.tick() => {
                        // Send periodic heartbeat
                        let ping = BacklogMessage::Ping {
                            timestamp: Utc::now().timestamp(),
                        };
                        if let Ok(json) = serde_json::to_vec(&ping) {
                            let len = (json.len() as u32).to_be_bytes();
                            let mut w = writer_for_writer.lock().await;
                            let _ = w.write_all(&len).await;
                            let _ = w.write_all(&json).await;
                        }
                    }
                    else => break,
                }
            }

            warn!("Backlog client writer task ended for {}", addr_clone);
        });

        Ok(tx)
    }

    /// Connect with automatic reconnection.
    ///
    /// Returns a channel sender that survives disconnections by reconnecting
    /// internally.
    pub async fn connect_with_retry(&self) -> mpsc::Sender<BacklogMessage> {
        loop {
            match self.connect().await {
                Ok(tx) => return tx,
                Err(e) => {
                    warn!(
                        "Backlog connection to {} failed (retry in {}s): {}",
                        self.addr, self.reconnect_secs, e
                    );
                    tokio::time::sleep(Duration::from_secs(self.reconnect_secs)).await;
                }
            }
        }
    }
}
