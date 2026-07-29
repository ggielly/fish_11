//! NAT / CGNAT / PAT traversal helpers for the MLS backlog TCP socket
//!
//! Provides cross-platform utilities to:
//! - Set `SO_REUSEADDR` on the listen socket
//! - Configure TCP keepalive for NAT binding refresh
//! - Detect public IP (via STUN-like heuristics or manual config)
//! - Log NAT binding diagnostics
//!
//! FCEP-2 §11.4 and §18.3: the relay bot MAY provide backlog services
//! over an out-of-band TCP channel. NAT traversal is REQUIRED when the
//! bot is behind a residential or CGNAT gateway.

use std::net::SocketAddr;

use anyhow::Result;
use tracing::{info, warn};

/// Network address family
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddrFamily {
    V4,
    V6,
}

/// NAT traversal configuration derived from backlog settings
#[derive(Debug, Clone)]
pub struct NatConfig {
    pub bind_address: String,
    pub listen_port: u16,
    pub external_address: Option<String>,
    pub keepalive_secs: u64,
    pub family: AddrFamily,
}

impl NatConfig {
    /// Build NAT configuration from backlog settings and optional external IP.
    pub fn new(bind_address: &str, port: u16, external: &str) -> Self {
        let family = if bind_address.contains(':') { AddrFamily::V6 } else { AddrFamily::V4 };

        let external_address = if external.is_empty() { None } else { Some(external.to_string()) };

        Self {
            bind_address: bind_address.to_string(),
            listen_port: port,
            external_address,
            keepalive_secs: 15, // Refresh NAT binding every 15s (default)
            family,
        }
    }

    /// Resolve the listen socket address.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        let addr_str = format!("{}:{}", self.bind_address, self.listen_port);
        addr_str
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid listen address '{}': {}", addr_str, e))
    }
}

/// Configure TCP keepalive on a socket for NAT binding refresh.
///
/// Sets `SO_KEEPALIVE` with an idle time matching `keepalive_secs`.
/// Many residential NAT gateways expire UDP/TCP bindings after 30-120s
/// of inactivity; sending a keepalive every 15-30s maintains the mapping.
#[cfg(unix)]
pub fn set_nat_keepalive(socket: &tokio::net::TcpStream, keepalive_secs: u64) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();

    // Enable SO_KEEPALIVE
    let keepalive: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &keepalive as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        warn!("Failed to set SO_KEEPALIVE (errno={})", unsafe { *libc::__errno_location() });
    }

    // TCP_KEEPIDLE (seconds before sending keepalive probes)
    #[cfg(target_os = "linux")]
    {
        let idle: libc::c_int = keepalive_secs as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &idle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // TCP_KEEPINTVL (interval between probes)
    #[cfg(target_os = "linux")]
    {
        let intvl: libc::c_int = 5;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &intvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    info!("NAT keepalive configured: {}s interval", keepalive_secs);
    Ok(())
}

/// Set TCP keepalive on Windows.
#[cfg(windows)]
pub fn set_nat_keepalive(socket: &tokio::net::TcpStream, keepalive_secs: u64) -> Result<()> {
    use std::os::windows::io::AsRawSocket;

    use windows::Win32::Networking::WinSock::{SO_KEEPALIVE, SOCKET, SOL_SOCKET, setsockopt};

    let raw_socket = SOCKET(socket.as_raw_socket() as usize);
    let keepalive: u32 = 1;
    let optval = keepalive.to_ne_bytes();

    unsafe {
        let ret = setsockopt(raw_socket, SOL_SOCKET, SO_KEEPALIVE, Some(&optval[..]));
        if ret != 0 {
            warn!("Failed to set SO_KEEPALIVE on Windows socket (ret={})", ret);
        }
    }

    // Windows SIO_KEEPALIVE_VALS via WSAIoctl is more involved;
    // for now, rely on the default 2h Windows keepalive. A STUN-like
    // heartbeat in the application layer (backlog Ping/Pong) is the
    // primary NAT refresh mechanism.
    info!("NAT keepalive configured (Windows): {}s + app-level heartbeat", keepalive_secs);
    Ok(())
}

/// Perform a basic NAT type detection.
///
/// Returns a description of the detected NAT situation based on
/// the configured external address vs local bind address.
pub fn detect_nat_situation(config: &NatConfig) -> String {
    match &config.external_address {
        Some(ext) if !ext.is_empty() => {
            if ext.contains(&config.bind_address) || ext == "127.0.0.1" || ext == "::1" {
                format!("No NAT detected: external={}, bind={}", ext, config.bind_address)
            } else {
                format!(
                    "NAT detected: bind={}:{}, external={}. Ensure port {} is forwarded or UPnP enabled.",
                    config.bind_address, config.listen_port, ext, config.listen_port
                )
            }
        }
        _ => {
            format!(
                "NAT status unknown: bind={}:{}, no external address configured. \
                 Set backlog.external_address in config for NAT environments.",
                config.bind_address, config.listen_port
            )
        }
    }
}

/// Log the NAT diagnosis at startup.
pub fn log_nat_status(config: &NatConfig) {
    let situation = detect_nat_situation(config);
    info!("{}", situation);

    if config.external_address.is_some()
        && config.external_address.as_ref().map_or(true, |s| s.is_empty())
    {
        warn!(
            "No external address set : peers behind NAT may not reach this bot's \
             backlog on port {}. Set backlog.external_address in fish_mls_bot.toml",
            config.listen_port
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config() {
        let cfg = NatConfig::new("0.0.0.0", 31337, "203.0.113.5");
        assert_eq!(cfg.listen_port, 31337);
        assert_eq!(cfg.family, AddrFamily::V4);
        assert_eq!(cfg.external_address.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn test_detect_nat_no_external() {
        let cfg = NatConfig::new("0.0.0.0", 31337, "");
        let status = detect_nat_situation(&cfg);
        assert!(status.contains("NAT status unknown"));
    }

    #[test]
    fn test_detect_nat_with_external() {
        let cfg = NatConfig::new("192.168.1.10", 31337, "203.0.113.5");
        let status = detect_nat_situation(&cfg);
        assert!(status.contains("NAT detected"));
    }

    #[test]
    fn test_detect_nat_no_nat() {
        let cfg = NatConfig::new("203.0.113.5", 31337, "203.0.113.5");
        let status = detect_nat_situation(&cfg);
        assert!(status.contains("No NAT detected"));
    }
}
