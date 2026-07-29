//! FCEP-2 IRC Synchronizer & Relay Bot Standalone CLI Executable
//!
//! Autonomous CLI binary for Windows & Linux that invokes `fish_11.dll` / `libfish_11.so`
//! exported functions to execute FCEP-2 relay and availability operations.

mod config;
mod dll_bridge;
mod handler;
mod store;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use config::{AppConfig, DEFAULT_CONFIG_FILE};
use dll_bridge::DllBridge;
use futures::StreamExt;
use handler::handle_irc_message;
use irc::client::prelude::*;
use store::RelayStore;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const MAX_RECONNECT_ATTEMPTS: u32 = 10;
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(5);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(300);
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "fish_11_relay",
    version = VERSION,
    about = "FiSH-11 FCEP-2 IRC Synchronizer & Relay Bot"
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
    config: PathBuf,

    /// Log level: trace, debug, info, warn, error
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Write logs to a file instead of (or in addition to) stderr
    #[arg(short = 'f', long)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the async IRC relay & sync bot
    Run,

    /// Initialize local device identity via DLL
    InitDevice {
        /// Device label
        #[arg(default_value = "RelayBot")]
        label: String,
    },

    /// Generate a signed KeyPackage via DLL
    GenKeypackage,

    /// Query group status & epoch via DLL
    Status {
        /// Channel name (e.g. #fish11)
        #[arg(default_value = "#fish11")]
        channel: String,
    },
}

/// Initialize tracing logging and return an optional guard that must be kept alive
/// for the lifetime of the process (if writing to a file).
fn init_logging(
    level: &str,
    log_file: Option<&Path>,
) -> Option<Vec<tracing_appender::non_blocking::WorkerGuard>> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(env_filter);

    match log_file {
        Some(path) => {
            let file_appender = tracing_appender::rolling::never(
                path.parent().unwrap_or(Path::new(".")),
                path.file_name().unwrap_or_default(),
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            subscriber.with_writer(non_blocking).init();
            Some(vec![guard])
        }
        None => {
            subscriber.init();
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // _log_guard must live for the entire process lifetime to keep
    // the non-blocking file appender worker thread alive.
    let _log_guard = init_logging(&cli.log_level, cli.log_file.as_deref());

    let bridge = DllBridge::new();

    match &cli.command {
        Commands::Run => run_relay_bot(&bridge, &cli.config).await,
        Commands::InitDevice { label } => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_InitDevice", label)?;
            println!("{}", res);
            Ok(())
        }
        Commands::GenKeypackage => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_GenKeyPackage", "")?;
            println!("{}", res);
            Ok(())
        }
        Commands::Status { channel } => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_GetGroupState", channel)?;
            println!("{}", res);
            Ok(())
        }
    }
}

/// Run async IRC relay bot loop with automatic reconnection and graceful shutdown
async fn run_relay_bot(bridge: &DllBridge, config_path: &Path) -> Result<()> {
    info!("FiSH-11 FCEP-2 IRC Synchronizer v{}", VERSION);

    // Initialize device identity via DLL
    let init_res = bridge.call_dll_fn("FiSH11_FCEP2_InitDevice", "RelayBot_CLI")?;
    info!("Device initialized: {}", init_res);

    let app_config = AppConfig::load_or_create(config_path)?;
    app_config.validate()?;
    let store = RelayStore::new(&app_config.storage.data_dir);

    // Start periodic persist and purge task (every 30s)
    let persist_store = store.clone();
    let persist_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            // Purge expired entries before persisting
            persist_store.purge_expired().await;
            if persist_store.take_dirty() {
                if let Err(e) = persist_store.persist().await {
                    warn!("Failed to persist store: {}", e);
                }
            }
        }
    });

    // Set up signal handler for graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    #[cfg(unix)]
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sigint) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            {
                sigint.recv().await;
                let _ = tx.send(()).await;
            }
        });
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sigterm) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                sigterm.recv().await;
                let _ = tx.send(()).await;
            }
        });
    }
    #[cfg(windows)]
    {
        let tx = shutdown_tx;
        tokio::spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                let _ = tx.send(()).await;
            }
        });
    }

    let mut attempt = 0u32;
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received, persisting store and exiting...");
                store.purge_expired().await;
                if let Err(e) = store.persist().await {
                    warn!("Failed to persist store on shutdown: {}", e);
                }
                persist_handle.abort();
                return Ok(());
            }
            result = connect_and_listen(bridge, &store, &app_config, &mut attempt) => {
                if let Err(e) = result {
                    error!("Fatal error in relay loop: {}", e);
                    // Persist one last time before returning
                    store.purge_expired().await;
                    if let Err(pe) = store.persist().await {
                        warn!("Failed to persist store on error: {}", pe);
                    }
                    persist_handle.abort();
                    return Err(e);
                }
            }
        }
    }
}

/// Attempt to connect to IRC, listen for FCEP-2 messages, and handle reconnection logic
async fn connect_and_listen(
    _bridge: &DllBridge,
    store: &RelayStore,
    app_config: &AppConfig,
    attempt: &mut u32,
) -> Result<()> {
    info!(
        "Connecting to {}:{} (TLS: {}) as '{}'...",
        app_config.server.address,
        app_config.server.port,
        app_config.server.use_tls,
        app_config.server.nickname
    );

    match Client::from_config(app_config.to_irc_config()).await {
        Ok(mut client) => {
            if let Err(e) = client.identify() {
                error!("Failed to identify: {}", e);
                *attempt += 1;
            } else {
                info!("Connected. Listening for FCEP-2 envelopes...");
                *attempt = 0;

                let mut stream = client.stream()?;
                while let Some(message_result) = stream.next().await {
                    match message_result {
                        Ok(message) => {
                            handle_irc_message(&client, store, app_config, &message).await;
                        }
                        Err(e) => {
                            error!("IRC stream error: {}", e);
                            break;
                        }
                    }
                }

                warn!("Disconnected from IRC server");
            }
        }
        Err(e) => {
            error!("Failed to connect: {}", e);
            *attempt += 1;
        }
    }

    if *attempt >= MAX_RECONNECT_ATTEMPTS {
        error!("Exceeded {} reconnect attempts, giving up", MAX_RECONNECT_ATTEMPTS);
        return Err(anyhow!("IRC reconnection failed after {} attempts", *attempt));
    }

    let delay =
        std::cmp::min(RECONNECT_BASE_DELAY * 2u32.saturating_pow(*attempt), RECONNECT_MAX_DELAY);
    info!("Reconnecting in {:?} (attempt {}/{})", delay, *attempt, MAX_RECONNECT_ATTEMPTS);
    tokio::time::sleep(delay).await;
    Ok(())
}
