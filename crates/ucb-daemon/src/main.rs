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
mod ipc;
mod service;

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use ucb_clipboard::{ArboardClipboard, ClipboardService};
use ucb_core::{DeviceInfo, Platform, PROTOCOL_VERSION};
use ucb_crypto::Identity;
use ucb_discovery::{Advertisement, Discovery};
use ucb_history::{History, HistoryEntry, HistoryQuery};
use ucb_sync::{pair_dial, pair_listen, Allowlist, EngineConfig, SyncEngine};

use config::{build_keystore, Config, Keystore, Paths, DEFAULT_PORT};
use headless::FileClipboard;
use ipc::SendUpdate;

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
    /// Show peer connection state from the running daemon (UX-1).
    Status {
        /// Emit the raw status snapshot as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Send a file to a connected peer via the running daemon (FILE-1).
    Send {
        /// Path of the file to send.
        path: PathBuf,
        /// Device-id prefix of the target peer (as shown by `ucb status`).
        /// Omit to send to the single connected peer.
        #[arg(long, value_name = "PREFIX")]
        to: Option<String>,
    },
    /// Browse and manage the encrypted local clipboard history (HIST-3).
    History {
        #[command(subcommand)]
        action: HistoryAction,
    },
    /// Install or remove the background service that runs `ucb run` (BG-1/BG-6).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
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

#[derive(Subcommand)]
enum HistoryAction {
    /// List history entries, newest first.
    List {
        /// Case-sensitive substring to match against entry text.
        #[arg(long, value_name = "QUERY")]
        search: Option<String>,
        /// Restrict to clips originating from this device-id prefix.
        #[arg(long, value_name = "PREFIX")]
        device: Option<String>,
        /// Only show starred entries.
        #[arg(long)]
        starred: bool,
        /// Maximum number of entries to show.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Emit entries as a JSON array instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Star an entry (exempts it from retention).
    Star {
        /// Entry id (as shown by `ucb history list`).
        id: i64,
    },
    /// Remove the star from an entry.
    Unstar {
        id: i64,
    },
    /// Delete a single entry.
    Delete {
        id: i64,
    },
    /// Delete every entry (including starred).
    Clear {
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Write the service definition and print the activation command.
    Install {
        /// Also run the activation command (launchctl/systemctl) for you.
        #[arg(long)]
        activate: bool,
    },
    /// Remove the service definition and print the deactivation command.
    Uninstall {
        /// Also run the deactivation command for you.
        #[arg(long)]
        activate: bool,
    },
    /// Show whether the service definition is installed.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Keep the override so `ucb service install` can point the service at the
    // same state directory.
    let config_dir_override = cli.config_dir.clone();
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
        Command::Status { json } => cmd_status(&paths, json).await,
        Command::Send { path, to } => cmd_send(&paths, path, to).await,
        Command::History { action } => cmd_history(&paths, action),
        Command::Service { action } => cmd_service(&paths, config_dir_override, action),
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
        max_file_bytes: None,
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

    // History (HIST-1): open the encrypted store using the same keystore that
    // holds the device key. A failure here disables history but must not stop
    // clipboard sync.
    let history = match History::open(&paths.history_file, store.as_ref()) {
        Ok(h) => {
            tracing::info!(path = %paths.history_file.display(), "history enabled");
            Some(Arc::new(h))
        }
        Err(e) => {
            tracing::warn!(error = %e, "history disabled: could not open the history database");
            None
        }
    };

    let engine = SyncEngine::start(
        EngineConfig {
            identity,
            allowlist_path: paths.trusted_file.clone(),
            device_name: config.name.clone(),
            platform: Platform::current(),
            static_peers: config.static_peers.clone(),
            history: history.clone(),
            received_dir: paths.received_dir.clone(),
            max_file_bytes: config.max_file_bytes,
        },
        listener,
        writer,
        clip_rx,
        disc_rx,
    )
    .await?;
    let engine = Arc::new(engine);

    // Status/send IPC (UX-1): serve a unix socket in the config dir.
    let ipc_task = match ipc::bind(&paths.socket_file) {
        Ok(listener) => {
            tracing::info!(socket = %paths.socket_file.display(), "status IPC listening");
            Some(tokio::spawn(ipc::serve(listener, engine.clone())))
        }
        Err(e) => {
            tracing::warn!(error = %e, "status IPC disabled: could not bind the daemon socket");
            None
        }
    };

    tracing::info!(
        device = %device_id.short(),
        name = %config.name,
        port = config.listen_port,
        static_peers = config.static_peers.len(),
        "universal-clipboard running; press Ctrl-C to stop"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    if let Some(t) = ipc_task {
        t.abort();
    }
    let _ = std::fs::remove_file(&paths.socket_file);
    drop(engine); // aborts the engine's background tasks
    if let Some(d) = discovery {
        d.shutdown();
    }
    Ok(())
}

// --- status / send IPC clients (UX-1) ------------------------------------

async fn cmd_status(paths: &Paths, json: bool) -> Result<()> {
    let snapshot = ipc::request_status(&paths.socket_file).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }
    if snapshot.peers.is_empty() {
        println!("No trusted peers. Run `ucb pair` to add one.");
    } else {
        println!("Peers ({}):", snapshot.peers.len());
        for p in &snapshot.peers {
            let state = if p.connected { "connected" } else { "offline" };
            println!("  {:<10}  {:<24}  {}", p.id_short, p.name, state);
        }
    }
    println!("daemon v{} (protocol v{})", snapshot.version, snapshot.protocol);
    Ok(())
}

async fn cmd_send(paths: &Paths, path: PathBuf, to: Option<String>) -> Result<()> {
    // Resolve to an absolute path client-side so the daemon (a different
    // process, possibly a different cwd) opens the right file.
    let abs = std::fs::canonicalize(&path)
        .with_context(|| format!("no such file: {}", path.display()))?;
    let abs = abs.to_string_lossy().into_owned();

    let mut last_percent = u64::MAX;
    let terminal = ipc::request_send(&paths.socket_file, &abs, to.as_deref(), |update| {
        if let SendUpdate::Progress { percent, .. } = update {
            if *percent != last_percent {
                last_percent = *percent;
                println!("  {percent}%");
            }
        }
    })
    .await?;

    match terminal {
        SendUpdate::Result {
            ok: true,
            name,
            bytes,
            ..
        } => {
            println!("Sent {name} ({bytes} bytes).");
            Ok(())
        }
        SendUpdate::Result { ok: false, detail, .. } => {
            Err(anyhow!("send failed: {detail}"))
        }
        SendUpdate::Error { message } => Err(anyhow!(message)),
        SendUpdate::Progress { .. } => Err(anyhow!("daemon ended without a result")),
    }
}

// --- history (HIST-3) ----------------------------------------------------

fn cmd_history(paths: &Paths, action: HistoryAction) -> Result<()> {
    let config = Config::load(paths)?;
    let store = build_keystore(&config, paths);
    let history = History::open(&paths.history_file, store.as_ref())
        .context("opening the history database")?;

    match action {
        HistoryAction::List {
            search,
            device,
            starred,
            limit,
            json,
        } => history_list(&history, search, device, starred, limit, json),
        HistoryAction::Star { id } => {
            if history.set_starred(id, true)? {
                println!("Starred entry {id}.");
            } else {
                return Err(anyhow!("no history entry with id {id}"));
            }
            Ok(())
        }
        HistoryAction::Unstar { id } => {
            if history.set_starred(id, false)? {
                println!("Unstarred entry {id}.");
            } else {
                return Err(anyhow!("no history entry with id {id}"));
            }
            Ok(())
        }
        HistoryAction::Delete { id } => {
            if history.delete(id)? {
                println!("Deleted entry {id}.");
            } else {
                return Err(anyhow!("no history entry with id {id}"));
            }
            Ok(())
        }
        HistoryAction::Clear { yes } => {
            if !yes && !prompt_yes_no("Delete ALL history entries, including starred? [y/N] ") {
                println!("Aborted.");
                return Ok(());
            }
            let n = history.delete_all()?;
            println!("Deleted {n} history entries.");
            Ok(())
        }
    }
}

fn history_list(
    history: &History,
    search: Option<String>,
    device: Option<String>,
    starred: bool,
    limit: usize,
    json: bool,
) -> Result<()> {
    // When filtering by device prefix we over-fetch, filter in Rust, then
    // truncate — the store filters by full origin id only.
    let query = HistoryQuery {
        text_search: search,
        origin: None,
        starred_only: starred,
        limit: if device.is_some() { 100_000 } else { limit },
        before_ts: None,
    };
    let mut entries = history.list(query)?;
    if let Some(prefix) = &device {
        entries.retain(|e| e.origin_id.starts_with(prefix));
        entries.truncate(limit);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    if entries.is_empty() {
        println!("No matching history entries.");
        return Ok(());
    }
    println!(
        "{:>6}  {:<19}  {:<10}  {:<6}  CONTENT",
        "ID", "TIME (UTC)", "ORIGIN", "KIND"
    );
    for e in &entries {
        let star = if e.starred { "*" } else { " " };
        println!(
            "{:>5}{}  {:<19}  {:<10}  {:<6}  {}",
            e.id,
            star,
            format_epoch_ms(e.ts_ms),
            short_origin(&e.origin_id),
            e.kind,
            preview(e),
        );
    }
    Ok(())
}

/// First 8 hex chars of a full origin device id, for the table.
fn short_origin(origin_id: &str) -> String {
    origin_id.chars().take(8).collect()
}

/// A single-line, escaped preview of an entry's content (first 60 chars).
fn preview(e: &HistoryEntry) -> String {
    let raw = match &e.content {
        Some(c) => c.clone(),
        None => match (e.width, e.height) {
            (Some(w), Some(h)) => format!("[image {w}x{h}]"),
            _ => "[binary]".to_string(),
        },
    };
    let mut out = String::new();
    for ch in raw.chars().take(60) {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('.'),
            c => out.push(c),
        }
    }
    if raw.chars().count() > 60 {
        out.push('\u{2026}'); // ellipsis
    }
    out
}

/// Format epoch milliseconds as `YYYY-MM-DD HH:MM:SS` in UTC, no extra deps.
fn format_epoch_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

/// Convert a day count since the Unix epoch to a civil (year, month, day).
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// --- service (BG-1/BG-6) -------------------------------------------------

fn cmd_service(
    paths: &Paths,
    config_dir_override: Option<PathBuf>,
    action: ServiceAction,
) -> Result<()> {
    let _ = paths; // reserved for future per-service state
    let home = service::home_dir()?;
    let program = std::env::current_exe()
        .context("resolving the current executable path")?
        .to_string_lossy()
        .into_owned();
    let args = service::run_args(config_dir_override.as_deref());

    match action {
        ServiceAction::Install { activate } => {
            let def = service::definition_for_current(&home, &program, &args)?;
            service::write_definition(&def)?;
            println!("Installed {:?} service definition:", def.kind);
            println!("  {}", def.path.display());
            if activate {
                run_shell(&def.activate_cmd)?;
                println!("Activated: {}", def.activate_cmd);
            } else {
                println!("To activate it now, run:");
                println!("  {}", def.activate_cmd);
            }
            Ok(())
        }
        ServiceAction::Uninstall { activate } => {
            let def = service::definition_for_current(&home, &program, &args)?;
            if activate {
                // Deactivate before removing the file (best-effort).
                let _ = run_shell(&def.deactivate_cmd);
                println!("Deactivated: {}", def.deactivate_cmd);
            }
            if def.path.exists() {
                std::fs::remove_file(&def.path)
                    .with_context(|| format!("removing {}", def.path.display()))?;
                println!("Removed {}", def.path.display());
            } else {
                println!("No service definition at {}", def.path.display());
            }
            if !activate {
                println!("If it is still loaded, deactivate it with:");
                println!("  {}", def.deactivate_cmd);
            }
            Ok(())
        }
        ServiceAction::Status => {
            let def = service::definition_for_current(&home, &program, &args)?;
            if def.path.exists() {
                println!("Service definition installed ({:?}):", def.kind);
                println!("  {}", def.path.display());
            } else {
                println!("Service not installed ({:?}).", def.kind);
                println!("  expected at {}", def.path.display());
                println!("Install it with `ucb service install`.");
            }
            Ok(())
        }
    }
}

/// Run a shell command line (used only behind `--activate`).
fn run_shell(cmd: &str) -> Result<()> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .with_context(|| format!("running: {cmd}"))?;
    if !status.success() {
        return Err(anyhow!("command failed ({status}): {cmd}"));
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
