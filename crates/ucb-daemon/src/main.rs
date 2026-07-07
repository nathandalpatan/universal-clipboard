//! `ucb` — the Universal Clipboard daemon CLI.
//!
//! Subcommands: `init`, `pair`, `devices`, `revoke`, `run`. See ARCHITECTURE.md
//! for the surrounding design. This binary wires the finished library crates
//! together; all protocol logic lives in `ucb-sync` and below.

mod config;

use std::io::Write;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ucb_clipboard::{ArboardClipboard, ClipboardService};
use ucb_core::{DeviceInfo, Platform, PROTOCOL_VERSION};
use ucb_crypto::Identity;
use ucb_discovery::{Advertisement, Discovery};
use ucb_sync::{pair_dial, pair_listen, Allowlist, EngineConfig, SyncEngine};

use config::{build_keystore, Config, Keystore, Paths, DEFAULT_PORT};

#[derive(Parser)]
#[command(name = "ucb", version, about = "End-to-end encrypted LAN clipboard sync")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the config dir, generate a device identity, and print it.
    Init {
        /// Human-readable device name (defaults to the machine hostname).
        #[arg(long)]
        name: Option<String>,
        /// Store the private key in a plaintext 0600 file instead of the OS
        /// keyring (for headless Linux).
        #[arg(long)]
        file_keystore: bool,
    },
    /// Pair with another device (run `--listen` on one, `--connect` on the other).
    Pair {
        /// Wait for an incoming pairing connection on the configured port.
        #[arg(long, conflicts_with = "connect")]
        listen: bool,
        /// Dial a listening device at `ip:port`.
        #[arg(long, value_name = "IP:PORT")]
        connect: Option<String>,
    },
    /// List paired (trusted) devices.
    Devices,
    /// Revoke a paired device by device-id prefix.
    Revoke {
        /// A prefix of the device id (as shown by `ucb devices`).
        prefix: String,
    },
    /// Run the sync daemon until Ctrl-C.
    Run {
        /// Clipboard poll interval in milliseconds.
        #[arg(long, default_value_t = 300)]
        poll_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            name,
            file_keystore,
        } => cmd_init(name, file_keystore),
        Command::Pair { listen, connect } => cmd_pair(listen, connect).await,
        Command::Devices => cmd_devices(),
        Command::Revoke { prefix } => cmd_revoke(prefix),
        Command::Run { poll_ms } => cmd_run(poll_ms).await,
    }
}

fn cmd_init(name: Option<String>, file_keystore: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    std::fs::create_dir_all(&paths.config_dir)?;

    let name = name.unwrap_or_else(default_device_name);
    let keystore = if file_keystore {
        Keystore::File
    } else {
        Keystore::Keyring
    };
    let config = Config {
        name: name.clone(),
        listen_port: DEFAULT_PORT,
        keystore,
    };

    // Generating the identity persists it via the selected key store.
    let store = build_keystore(&config, &paths);
    let identity = Identity::load_or_generate(store.as_ref())
        .context("generating or loading the device identity")?;

    config.save(&paths)?;

    println!("Initialized universal-clipboard.");
    println!("  device name: {name}");
    println!("  device id:   {}", identity.device_id());
    println!("  short id:    {}", identity.device_id().short());
    println!("  keystore:    {keystore:?}");
    println!("  config:      {}", paths.config_file.display());
    Ok(())
}

async fn cmd_pair(listen: bool, connect: Option<String>) -> Result<()> {
    let paths = Paths::resolve()?;
    let config = Config::load(&paths)?;
    let store = build_keystore(&config, &paths);
    let identity = Identity::load_or_generate(store.as_ref())?;

    let confirm = |code: &str, peer: &DeviceInfo| -> bool {
        println!();
        println!("Pairing with: {} ({})", peer.name, peer.id.short());
        println!("Verification code: {code}");
        prompt_yes_no("Codes match? [y/N] ")
    };

    let trusted = if listen {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.listen_port))
            .await
            .with_context(|| format!("binding pairing listener on port {}", config.listen_port))?;
        println!(
            "Listening for a pairing connection on port {} (device id {})...",
            config.listen_port,
            identity.device_id().short()
        );
        pair_listen(
            listener,
            &identity,
            &paths.trusted_file,
            &config.name,
            Platform::current(),
            confirm,
        )
        .await?
    } else if let Some(addr) = connect {
        println!("Connecting to {addr} to pair...");
        pair_dial(
            &addr,
            &identity,
            &paths.trusted_file,
            &config.name,
            Platform::current(),
            confirm,
        )
        .await?
    } else {
        return Err(anyhow!("specify either --listen or --connect <ip:port>"));
    };

    println!(
        "Paired with {} ({}).",
        trusted.name,
        trusted.device_id.short()
    );
    Ok(())
}

fn cmd_devices() -> Result<()> {
    let paths = Paths::resolve()?;
    let allowlist = Allowlist::load(&paths.trusted_file)?;
    let devices = allowlist.list();
    if devices.is_empty() {
        println!("No paired devices. Run `ucb pair` to add one.");
        return Ok(());
    }
    println!("Paired devices ({}):", devices.len());
    for d in devices {
        println!("  {}  {}", d.device_id.short(), d.name);
        println!("      id: {}", d.device_id);
    }
    Ok(())
}

fn cmd_revoke(prefix: String) -> Result<()> {
    let paths = Paths::resolve()?;
    let mut allowlist = Allowlist::load(&paths.trusted_file)?;
    match allowlist.resolve_prefix(&prefix) {
        Some(id) => {
            let name = allowlist.name_of(&id).unwrap_or_default();
            allowlist.remove(&id);
            println!("Revoked {} ({}).", name, id.short());
            Ok(())
        }
        None => Err(anyhow!(
            "no unique device matches prefix {prefix:?} (see `ucb devices`)"
        )),
    }
}

async fn cmd_run(poll_ms: u64) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let paths = Paths::resolve()?;
    let config = Config::load(&paths)?;
    let store = build_keystore(&config, &paths);
    let identity = Identity::load_or_generate(store.as_ref())?;
    let device_id = identity.device_id();

    // Clipboard service.
    let clipboard = ArboardClipboard::new().context("opening the OS clipboard")?;
    let (writer, clip_rx) = ClipboardService::start(clipboard, Duration::from_millis(poll_ms));

    // Transport listener.
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.listen_port))
        .await
        .with_context(|| format!("binding sync listener on port {}", config.listen_port))?;

    // Discovery (advertise + browse). Keep the handle alive for the run.
    let (discovery, disc_rx) = Discovery::start(Advertisement {
        device_id,
        name: config.name.clone(),
        port: config.listen_port,
        version: PROTOCOL_VERSION,
    })
    .context("starting mDNS discovery")?;

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path: paths.trusted_file.clone(),
            device_name: config.name.clone(),
            platform: Platform::current(),
        },
        listener,
        writer,
        clip_rx,
        disc_rx,
    )
    .await?;

    tracing::info!(
        device = %device_id.short(),
        name = %config.name,
        port = config.listen_port,
        "universal-clipboard running; press Ctrl-C to stop"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    drop(engine); // aborts the engine's background tasks
    discovery.shutdown();
    Ok(())
}

/// Print `prompt` and read a yes/no answer from stdin (default no).
fn prompt_yes_no(prompt: &str) -> bool {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Best-effort machine name for the default device name.
fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "ucb-device".to_string())
}
