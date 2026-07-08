//! `ucb` — the Universal Clipboard daemon CLI.
//!
//! Subcommands: `init`, `pair`, `devices`, `revoke`, `peer`, `run`. See
//! ARCHITECTURE.md for the surrounding design. This binary wires the finished
//! library crates together; all protocol logic lives in `ucb-sync` and below.
//!
//! ## Test / automation flags
//!
//! Several flags exist to make the daemon fully sandboxable for the integration
//! test harness (see `--help`):
//!
//! * `--config-dir <dir>` (global) — put all state under `<dir>` instead of the
//!   platform config directory.
//! * `ucb init --print-id` — emit `{id, name, port}` as JSON on stdout.
//! * `ucb pair --listen --yes` / `--connect <addr> --yes` — auto-confirm the
//!   pairing code (prints it, skips the interactive prompt).
//! * `ucb run --headless-dir <dir>` — use a file-backed clipboard under `<dir>`
//!   instead of the OS clipboard (for the Docker harness).

mod config;
mod headless;

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ucb_clipboard::{ArboardClipboard, ClipboardService};
use ucb_core::{DeviceInfo, Platform, PROTOCOL_VERSION};
use ucb_crypto::Identity;
use ucb_discovery::{Advertisement, Discovery};
use ucb_sync::{pair_dial, pair_listen, Allowlist, EngineConfig, SyncEngine};

use config::{build_keystore, Config, Keystore, Paths, DEFAULT_PORT};
use headless::FileClipboard;

#[derive(Parser)]
#[command(name = "ucb", version, about = "End-to-end encrypted LAN clipboard sync")]
struct Cli {
    /// Store all state under this directory instead of the platform config dir.
    /// (Test/automation flag; makes the daemon fully sandboxable.)
    #[arg(long, global = true, value_name = "DIR")]
    config_dir: Option<PathBuf>,
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
        /// Machine-readable output: print `{id, name, port}` as JSON on stdout.
        /// (Test/automation flag.)
        #[arg(long)]
        print_id: bool,
    },
    /// Pair with another device (run `--listen` on one, `--connect` on the other).
    Pair {
        /// Wait for an incoming pairing connection on the configured port.
        #[arg(long, conflicts_with = "connect")]
        listen: bool,
        /// Dial a listening device at `ip:port`.
        #[arg(long, value_name = "IP:PORT")]
        connect: Option<String>,
        /// Auto-confirm the pairing code without prompting (prints the code).
        /// (Test/automation flag; skips the interactive verification.)
        #[arg(long)]
        yes: bool,
    },
    /// List paired (trusted) devices.
    Devices,
    /// Revoke a paired device by device-id prefix (PAIR-7).
    Revoke {
        /// A prefix of the device id (as shown by `ucb devices`).
        prefix: String,
        /// Clear an existing tombstone instead of revoking, allowing the device
        /// to be paired again in the future.
        #[arg(long)]
        forget: bool,
    },
    /// Manage manually-configured static peers (DISC-3).
    Peer {
        #[command(subcommand)]
        action: PeerAction,
    },
    /// Run the sync daemon until Ctrl-C.
    Run {
        /// Clipboard poll interval in milliseconds.
        #[arg(long, default_value_t = 300)]
        poll_ms: u64,
        /// Use a file-backed clipboard under this directory instead of the OS
        /// clipboard: reads `clip-in`, writes applied remote clips to `clip-out`
        /// and appends `clip-log.jsonl`. (Test/automation flag for the Docker
        /// integration harness.)
        #[arg(long, value_name = "DIR")]
        headless_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PeerAction {
    /// Add a static peer endpoint (`ip:port`).
    Add {
        #[arg(value_name = "IP:PORT")]
        addr: String,
    },
    /// Remove a static peer endpoint (`ip:port`).
    Remove {
        #[arg(value_name = "IP:PORT")]
        addr: String,
    },
    /// List configured static peers.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = Paths::resolve(cli.config_dir)?;
    match cli.command {
        Command::Init {
            name,
            file_keystore,
            print_id,
        } => cmd_init(&paths, name, file_keystore, print_id),
        Command::Pair {
            listen,
            connect,
            yes,
        } => cmd_pair(&paths, listen, connect, yes).await,
        Command::Devices => cmd_devices(&paths),
        Command::Revoke { prefix, forget } => cmd_revoke(&paths, prefix, forget),
        Command::Peer { action } => cmd_peer(&paths, action),
        Command::Run {
            poll_ms,
            headless_dir,
        } => cmd_run(&paths, poll_ms, headless_dir).await,
    }
}

fn cmd_init(
    paths: &Paths,
    name: Option<String>,
    file_keystore: bool,
    print_id: bool,
) -> Result<()> {
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
        static_peers: Vec::new(),
    };

    // Generating the identity persists it via the selected key store.
    let store = build_keystore(&config, paths);
    let identity = Identity::load_or_generate(store.as_ref())
        .context("generating or loading the device identity")?;

    config.save(paths)?;

    if print_id {
        // Machine-readable output for the test harness.
        let out = serde_json::json!({
            "id": identity.device_id().to_string(),
            "name": name,
            "port": config.listen_port,
        });
        println!("{}", serde_json::to_string(&out)?);
        return Ok(());
    }

    println!("Initialized universal-clipboard.");
    println!("  device name: {name}");
    println!("  device id:   {}", identity.device_id());
    println!("  short id:    {}", identity.device_id().short());
    println!("  keystore:    {keystore:?}");
    println!("  config:      {}", paths.config_file.display());
    Ok(())
}

async fn cmd_pair(
    paths: &Paths,
    listen: bool,
    connect: Option<String>,
    yes: bool,
) -> Result<()> {
    let config = Config::load(paths)?;
    let store = build_keystore(&config, paths);
    let identity = Identity::load_or_generate(store.as_ref())?;

    let confirm = |code: &str, peer: &DeviceInfo| -> bool {
        println!();
        println!("Pairing with: {} ({})", peer.name, peer.id.short());
        println!("Verification code: {code}");
        if yes {
            println!("Auto-confirming (--yes).");
            true
        } else {
            prompt_yes_no("Codes match? [y/N] ")
        }
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

fn cmd_devices(paths: &Paths) -> Result<()> {
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

fn cmd_revoke(paths: &Paths, prefix: String, forget: bool) -> Result<()> {
    let mut allowlist = Allowlist::load(&paths.trusted_file)?;
    if forget {
        match allowlist.resolve_tombstone_prefix(&prefix) {
            Some(id) => {
                allowlist.forget(&id)?;
                println!("Cleared tombstone for {}; it may be paired again.", id.short());
                Ok(())
            }
            None => Err(anyhow!(
                "no unique revoked device matches prefix {prefix:?}"
            )),
        }
    } else {
        match allowlist.resolve_prefix(&prefix) {
            Some(id) => {
                let name = allowlist.name_of(&id).unwrap_or_default();
                allowlist.revoke(id)?;
                println!("Revoked {} ({}); tombstoned to block re-pairing.", name, id.short());
                Ok(())
            }
            None => Err(anyhow!(
                "no unique device matches prefix {prefix:?} (see `ucb devices`)"
            )),
        }
    }
}

fn cmd_peer(paths: &Paths, action: PeerAction) -> Result<()> {
    match action {
        PeerAction::Add { addr } => {
            let mut config = Config::load(paths)?;
            if config.static_peers.iter().any(|p| p == &addr) {
                println!("Static peer {addr} already configured.");
            } else {
                config.static_peers.push(addr.clone());
                config.save(paths)?;
                println!("Added static peer {addr}.");
            }
            Ok(())
        }
        PeerAction::Remove { addr } => {
            let mut config = Config::load(paths)?;
            let before = config.static_peers.len();
            config.static_peers.retain(|p| p != &addr);
            if config.static_peers.len() == before {
                println!("No static peer {addr} configured.");
            } else {
                config.save(paths)?;
                println!("Removed static peer {addr}.");
            }
            Ok(())
        }
        PeerAction::List => {
            let config = Config::load(paths)?;
            if config.static_peers.is_empty() {
                println!("No static peers configured.");
            } else {
                println!("Static peers ({}):", config.static_peers.len());
                for p in &config.static_peers {
                    println!("  {p}");
                }
            }
            Ok(())
        }
    }
}

async fn cmd_run(paths: &Paths, poll_ms: u64, headless_dir: Option<PathBuf>) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(paths)?;
    let store = build_keystore(&config, paths);
    let identity = Identity::load_or_generate(store.as_ref())?;
    let device_id = identity.device_id();

    // Clipboard service: file-backed in headless mode, OS clipboard otherwise.
    let (writer, clip_rx) = match &headless_dir {
        Some(dir) => {
            let clipboard = FileClipboard::new(dir).context("setting up the headless clipboard")?;
            ClipboardService::start(clipboard, Duration::from_millis(poll_ms))
        }
        None => {
            let clipboard = ArboardClipboard::new().context("opening the OS clipboard")?;
            ClipboardService::start(clipboard, Duration::from_millis(poll_ms))
        }
    };

    // Transport listener.
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.listen_port))
        .await
        .with_context(|| format!("binding sync listener on port {}", config.listen_port))?;

    // Discovery (advertise + browse). In headless mode we skip mDNS (which may
    // not work inside a container) and rely on static peers instead.
    let discovery;
    let disc_rx;
    if headless_dir.is_some() {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        disc_rx = rx;
        discovery = None;
        tracing::info!("headless mode: mDNS discovery disabled; using static peers only");
    } else {
        let (d, rx) = Discovery::start(Advertisement {
            device_id,
            name: config.name.clone(),
            port: config.listen_port,
            version: PROTOCOL_VERSION,
        })
        .context("starting mDNS discovery")?;
        disc_rx = rx;
        discovery = Some(d);
    }

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path: paths.trusted_file.clone(),
            device_name: config.name.clone(),
            platform: Platform::current(),
            static_peers: config.static_peers.clone(),
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
        static_peers = config.static_peers.len(),
        "universal-clipboard running; press Ctrl-C to stop"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    drop(engine); // aborts the engine's background tasks
    if let Some(d) = discovery {
        d.shutdown();
    }
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
