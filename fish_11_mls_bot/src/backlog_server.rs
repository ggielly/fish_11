//! Backlog TCP server for out-of-band MLS traffic
//!
//! Implements the FCEP-2 relay bot's dedicated TCP channel on port 31337
//! (§11.4, §18.3). Operates alongside IRC to exchange KeyPackages, Welcomes,
//! Commits, and synchronisation records over a persistent or on-demand TCP
//! connection, bypassing IRC line-size constraints and providing NAT-friendly
//! keepalive.
//!
//! Protocol:
//!   All messages are framed as: `[4-byte big-endian length][payload]`
//!   Payload is JSON-encoded `BacklogMessage`.
//!
//! NAT handling:
//!   - SO_REUSEADDR set on the listen socket
//!   - TCP keepalive at 15s interval
//!   - Application-layer Ping/Pong every 10s

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::config::BacklogConfig;
use crate::nat_helper;

/// Maximum backlog message payload size (16 MiB)
const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

/// Backlog message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum BacklogMessage {
    /// KeyPackage distribution (§11.4)
    KeyPackage { device_id: String, keypackage_b64: String },
    /// Welcome delivery (§13.2)
    Welcome { device_id: String, group_id_b64: String, welcome_b64: String },
    /// Commit broadcast (§15.2)
    Commit { group_id_b64: String, epoch: u64, commit_b64: String },
    /// Sync request (§18.2)
    SyncRequest { group_id_b64: String, known_epoch: u64, request_id: String },
    /// Sync response (§18.2)
    SyncResponse {
        group_id_b64: String,
        request_id: String,
        commits: Vec<String>,
        current_epoch: u64,
    },
    /// Application-level heartbeat for NAT binding refresh
    Ping { timestamp: i64 },
    /// Heartbeat response
    Pong { timestamp: i64 },
    /// Peer discovery
    PeerAnnounce { device_id: String, endpoint: String, capabilities: Vec<String> },
    /// Disconnect notification
    Disconnect { reason: String },
}

/// Backlog peer state
#[derive(Debug, Clone)]
pub struct PeerState {
    pub device_id: String,
    pub addr: SocketAddr,
    pub connected_at: i64,
    pub last_active: i64,
    pub capabilities: Vec<String>,
}

/// Backlog server state
pub struct BacklogServer {
    config: BacklogConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, PeerState>>>,
    message_tx: broadcast::Sender<BacklogMessage>,
}

impl BacklogServer {
    /// Create a new backlog server.
    pub fn new(config: &BacklogConfig) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            config: config.clone(),
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_tx: tx,
        }
    }

    /// Subscribe to incoming backlog messages.
    pub fn subscribe(&self) -> broadcast::Receiver<BacklogMessage> {
        self.message_tx.subscribe()
    }

    /// Start the backlog server.
    ///
    /// Binds to the configured address:port and spawns an accept loop
    /// that handles each peer connection concurrently.
    pub async fn start(self: Arc<Self>) -> Result<()> {
        let nat_cfg = nat_helper::NatConfig::new(
            &self.config.bind_address,
            self.config.listen_port,
            &self.config.external_address,
        );

        let listen_addr = nat_cfg.listen_addr()?;
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind backlog on {}: {}", listen_addr, e))?;

        nat_helper::log_nat_status(&nat_cfg);
        info!(
            "Backlog server listening on {} (max peers: {}, timeout: {}s)",
            listen_addr, self.config.max_peers, self.config.peer_timeout_secs,
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let peer_count = self.peers.read().await.len();
                    if peer_count >= self.config.max_peers {
                        warn!("Max peers ({}) reached, rejecting {}", self.config.max_peers, addr);
                        continue;
                    }

                    info!("New backlog peer connection from {}", addr);
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.clone().handle_peer(stream, addr).await {
                            debug!("Peer {} disconnected: {}", addr, e);
                        }
                        server.peers.write().await.remove(&addr);
                    });
                }
                Err(e) => {
                    error!("Backlog accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handle an individual peer connection.
    async fn handle_peer(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        // Apply NAT keepalive on the TcpStream
        if let Err(e) = nat_helper::set_nat_keepalive(&stream, self.config.peer_timeout_secs) {
            warn!("Failed to set NAT keepalive for {}: {}", addr, e);
        }

        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));
        let mut buf_reader = tokio::io::BufReader::new(reader);

        // Send Ping heartbeat periodically
        let heartbeat_writer = writer.clone();
        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let ping = BacklogMessage::Ping { timestamp: Utc::now().timestamp() };
                if let Ok(json) = serde_json::to_vec(&ping) {
                    let len = (json.len() as u32).to_be_bytes();
                    let mut w = heartbeat_writer.lock().await;
                    let _ = w.write_all(&len).await;
                    let _ = w.write_all(&json).await;
                }
            }
        });

        // Track peer
        self.peers.write().await.insert(
            addr,
            PeerState {
                device_id: String::new(),
                addr,
                connected_at: Utc::now().timestamp(),
                last_active: Utc::now().timestamp(),
                capabilities: Vec::new(),
            },
        );

        // Read messages from the peer
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];

        loop {
            // Read 4-byte length prefix
            match buf_reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Peer {} disconnected gracefully", addr);
                    break;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Read error from {}: {}", addr, e));
                }
            }

            let payload_len = u32::from_be_bytes(len_buf) as usize;
            if payload_len > MAX_PAYLOAD_SIZE as usize {
                warn!("Oversized message ({} bytes) from {}, dropping", payload_len, addr);
                continue;
            }

            let mut payload = vec![0u8; payload_len];
            buf_reader
                .read_exact(&mut payload)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read payload from {}: {}", addr, e))?;

            // Deserialize and handle
            match serde_json::from_slice::<BacklogMessage>(&payload) {
                Ok(msg) => {
                    // Update peer last-active
                    if let Some(peer) = self.peers.write().await.get_mut(&addr) {
                        peer.last_active = Utc::now().timestamp();
                    }

                    // Handle special messages
                    match &msg {
                        BacklogMessage::PeerAnnounce { device_id, capabilities, .. } => {
                            if let Some(peer) = self.peers.write().await.get_mut(&addr) {
                                peer.device_id = device_id.clone();
                                peer.capabilities = capabilities.clone();
                            }
                            info!("Peer {} announced as device {}", addr, device_id);
                        }
                        BacklogMessage::Pong { .. } => {
                            debug!("Pong from {}", addr);
                        }
                        _ => {}
                    }

                    // Broadcast to all subscribers (including IRC handler)
                    let _ = self.message_tx.send(msg);
                }
                Err(e) => {
                    debug!("Invalid message from {}: {}", addr, e);
                }
            }
        }

        heartbeat_handle.abort();
        // Send disconnect notification
        let disconnect = BacklogMessage::Disconnect { reason: "Peer disconnected".into() };
        if let Ok(json) = serde_json::to_vec(&disconnect) {
            let len = (json.len() as u32).to_be_bytes();
            let mut w = writer.lock().await;
            let _ = w.write_all(&len).await;
            let _ = w.write_all(&json).await;
        }

        info!("Peer {} disconnected", addr);
        Ok(())
    }

    /// Get current peer count.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get list of connected peers.
    pub async fn list_peers(&self) -> Vec<PeerState> {
        self.peers.read().await.values().cloned().collect()
    }
}
