//! FCEP-2 MLS IRC Test Bot — Standalone CLI
//!
//! Autonomous CLI binary for Windows & Linux that invokes `fish_11.dll` / `libfish_11.so`
//! exported functions to execute FCEP-2 MLS relay and master-key operations.
//!
//! Features:
//!   - Async IRC client with automatic reconnection
//!   - Encrypted NoSQL database (sled + ChaCha20-Poly1305)
//!   - Dedicated TCP backlog server on port 31337
//!   - NAT/CGNAT/PAT traversal support
//!   - FCEP-2 KeyPackage, Welcome, Commit relay (§11.4, §13, §15, §18)
//!   - Key master / backup base role (§11.4)

mod backlog_client;
mod backlog_server;
mod config;
mod database;
mod dll_bridge;
mod handler;
mod irc_client;
mod nat_helper;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use config::{AppConfig, DEFAULT_CONFIG_FILE};
use database::EncryptedStore;
use dll_bridge::DllBridge;
use irc_client::IrcClient;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "fish_11_mls_bot",
    version = VERSION,
    about = "FiSH-11 FCEP-2 MLS IRC Test Bot — Relay, Key Master & Backlog Server"
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_FILE)]
    config: PathBuf,

    /// Enable debug logging (overrides config file)
    #[arg(short, long)]
    debug: bool,

    /// Run in foreground (do not daemonize)
    #[arg(short = 'F', long)]
    foreground: bool,

    /// Write logs to file (overrides config)
    #[arg(short = 'l', long)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MLS test bot (IRC + backlog + database)
    Run,
    /// Run as a background daemon process
    Daemon,
    /// Initialize local device identity via DLL
    InitDevice {
        /// Device label
        #[arg(default_value = "MLS_Bot")]
        label: String,
    },
    /// Generate a signed KeyPackage via DLL
    GenKp,
    /// Query group/device status via DLL
    Status {
        /// Channel name (e.g. #fish11-test)
        #[arg(default_value = "#fish11-test")]
        channel: String,
    },
    /// List connected backlog peers
    ListPeers,
    /// Export encrypted backup of all stored data
    ExportBackup {
        /// Output file path
        #[arg(default_value = "mls_bot_backup.json")]
        output: PathBuf,
    },
}

// ── Entry Point ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = AppConfig::load_or_create(&cli.config)?;
    config.validate()?;

    // Initialize logging
    let log_level = if cli.debug {
        "debug"
    } else {
        &config.logging.level
    };
    let log_file = cli.log_file.as_ref()
        .or_else(|| {
            let f = &config.logging.file;
            if f.is_empty() { None } else { Some(PathBuf::from(f)) }
        });

    init_logging(log_level, log_file.as_deref());

    info!("FiSH-11 FCEP-2 MLS Test Bot v{} starting...", VERSION);

    // Create DLL bridge
    let bridge = DllBridge::new();

    // Handle immediate commands that don't require full startup
    match &cli.command {
        Some(Commands::InitDevice { label }) => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_InitDevice", label)?;
            println!("{}", res);
            return Ok(());
        }
        Some(Commands::GenKp) => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_GenKeyPackage", "")?;
            println!("{}", res);
            return Ok(());
        }
        Some(Commands::Status { channel }) => {
            let res = bridge.call_dll_fn("FiSH11_FCEP2_GetGroupState", channel)?;
            println!("{}", res);
            return Ok(());
        }
        Some(Commands::ExportBackup { output }) => {
            // Export requires full database init
        }
        _ => {}
    }

    // Initialize encrypted database
    let enc_key = config.derive_storage_key()?;
    let store = EncryptedStore::open(&config.database.path, &enc_key)?;
    info!("Encrypted database opened at {}", config.database.path);

    // Initialize device identity via DLL
    let init_res = bridge.call_dll_fn("FiSH11_FCEP2_InitDevice", "MLS_Bot_CLI")?;
    info!("Device initialized: {}", init_res);

    // Handle export command
    if let Some(Commands::ExportBackup { output }) = &cli.command {
        return export_backup(&store, output).await;
    }

    // Handle daemon mode (Unix fork, Windows job object)
    if let Some(Commands::Daemon) = &cli.command {
        if !cli.foreground {
            daemonize()?;
        }
    }

    // ── Full bot startup ──────────────────────────────────────────────

    // Set up signal handling for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    setup_signal_handler(shutdown_tx).await;

    // Start backlog TCP server on port 31337
    let backlog_server = if config.backlog.enabled {
        let server = Arc::new(backlog_server::BacklogServer::new(&config.backlog));
        let backlog_rx = server.subscribe();

        // Spawn backlog message handler
        let backlog_store = store.clone();
        tokio::spawn(async move {
            let mut rx = backlog_rx;
            while let Ok(msg) = rx.recv().await {
                handler::handle_backlog_message(&backlog_store, &msg).await;
            }
        });

        // Spawn the TCP server
        let backlog_server_clone = server.clone();
        tokio::spawn(async move {
            if let Err(e) = backlog_server_clone.start().await {
                error!("Backlog server error: {}", e);
            }
        });

        info!(
            "Backlog server starting on {}:{} (NAT: {})",
            config.backlog.bind_address,
            config.backlog.listen_port,
            if config.backlog.external_address.is_empty() { "auto" } else { &config.backlog.external_address },
        );

        Some(server)
    } else {
        info!("Backlog server disabled");
        None
    };

    // Start periodic database persistence task
    let persist_store = store.clone();
    let persist_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = persist_store.flush() {
                warn!("Database flush warning: {}", e);
            }
        }
    });

    // Start IRC client
    let irc_client = IrcClient::new(config.clone(), bridge, store.clone());
    info!("Connecting to IRC server {}:{} ...", config.server.address, config.server.port);

    match irc_client.run(shutdown_rx).await {
        Ok(()) => info!("IRC client exited normally"),
        Err(e) => error!("IRC client error: {}", e),
    }

    // Graceful shutdown
    info!("Shutting down...");
    if let Some(server) = backlog_server {
        info!("Backlog server had {} peer(s)", server.peer_count().await);
    }
    if let Err(e) = store.flush() {
        warn!("Final database flush warning: {}", e);
    }
    if config.database.auto_compact {
        if let Err(e) = store.compact() {
            warn!("Database compaction warning: {}", e);
        }
    }
    persist_handle.abort();

    info!("FiSH-11 MLS Bot shutdown complete");
    Ok(())
}

// ── Logging ───────────────────────────────────────────────────────────────

/// Initialize tracing logging with optional file output.
fn init_logging(level: &str, log_file: Option<&std::path::Path>) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(env_filter);

    match log_file {
        Some(path) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let file_appender = tracing_appender::rolling::never(
                path.parent().unwrap_or(std::path::Path::new(".")),
                path.file_name().unwrap_or_default(),
            );
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            // Leak the guard — it must live for the process lifetime
            let guard: &'static _ = Box::leak(Box::new(_guard));
            subscriber.with_writer(non_blocking).init();
            let _ = guard; // suppress unused warning
        }
        None => {
            subscriber.init();
        }
    }
}

// ── Signal Handling ───────────────────────────────────────────────────────

/// Set up OS signal handlers for graceful shutdown.
async fn setup_signal_handler(shutdown_tx: tokio::sync::mpsc::Sender<()>) {
    #[cfg(unix)]
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sigint) = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::interrupt()
            ) {
                sigint.recv().await;
                let _ = tx.send(()).await;
            }
        });
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Ok(mut sigterm) = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate()
            ) {
                sigterm.recv().await;
                let _ = tx.send(()).await;
            }
        });
    }
    #[cfg(windows)]
    {
        let _ = shutdown_tx;
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                // Ctrl-C handler registered below via the same channel clone
            }
        });
    }
}

// ── Daemonization ─────────────────────────────────────────────────────────

/// Daemonize the process (Unix only).
///
/// On Unix, forks and detaches from the terminal. On Windows, this is a
/// no-op (Windows services require a different mechanism).
#[cfg(unix)]
fn daemonize() -> Result<()> {
    use std::os::unix::process::CommandExt;
    let ret = unsafe { libc::fork() };
    if ret < 0 {
        return Err(anyhow!("fork() failed: errno={}", unsafe { *libc::__errno_location() }));
    }
    if ret > 0 {
        // Parent process exits
        info!("Daemonized: child PID={}", ret);
        std::process::exit(0);
    }
    // Child: create new session, detach from terminal
    unsafe {
        libc::setsid();
    }
    // Redirect stdio to /dev/null
    if let Ok(null) = std::fs::File::open("/dev/null") {
        use std::os::unix::io::FromRawFd;
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) };
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) };
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
    }
    info!("MLS Bot daemon started (PID={})", std::process::id());
    Ok(())
}

#[cfg(windows)]
fn daemonize() -> Result<()> {
    // On Windows, the bot runs as a regular process. For true background
    // operation, use `start /B fish_11_mls_bot.exe daemon` or register as
    // a Windows service (TODO).
    info!("Daemon mode requested on Windows. Running as background process.");
    info!("Use 'start /B fish_11_mls_bot daemon' from a command prompt.");
    Ok(())
}

// ── Backup Export ─────────────────────────────────────────────────────────

/// Export all stored data as an encrypted JSON backup.
async fn export_backup(store: &EncryptedStore, output: &std::path::Path) -> Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Backup {
        exported_at: String,
        version: String,
        collections: std::collections::HashMap<String, Vec<(String, serde_json::Value)>>,
    }

    let mut backup = Backup {
        exported_at: chrono::Utc::now().to_rfc3339(),
        version: VERSION.to_string(),
        collections: std::collections::HashMap::new(),
    };

    for coll in &[
        database::COLL_KEY_PACKAGES,
        database::COLL_WELCOMES,
        database::COLL_COMMIT_LOGS,
        database::COLL_GROUP_STATE,
        database::COLL_PEER_REGISTRY,
        database::COLL_OUTBOX,
    ] {
        let mut entries = Vec::new();
        if let Ok(items) = store.scan(coll).await {
            for (key, value) in items {
                let key_hex = hex::encode(&key);
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&value) {
                    entries.push((key_hex, json));
                } else {
                    entries.push((key_hex, serde_json::Value::String(hex::encode(&value))));
                }
            }
        }
        backup.collections.insert(coll.to_string(), entries);
    }

    let json = serde_json::to_string_pretty(&backup)?;
    std::fs::write(output, &json)?;
    info!("Exported backup to {}", output.display());
    println!("Backup exported to {}", output.display());
    Ok(())
}
