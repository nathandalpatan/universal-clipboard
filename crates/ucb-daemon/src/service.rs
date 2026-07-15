//! Desktop background service integration (BG-1/BG-6): generate and manage a
//! launchd agent (macOS) or systemd user unit (Linux) that runs `ucb run`.
//!
//! The plist / unit *content* is produced by the pure functions
//! [`launchd_plist`] and [`systemd_unit`] (unit-tested below). Installation only
//! writes the file and prints the activation command — this code never runs
//! `launchctl`/`systemctl` itself unless the user passes `--activate`.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

#[cfg(not(windows))]
use anyhow::{anyhow, Context, Result};

/// launchd label / systemd unit stem (matches the config dir vendor id).
#[cfg(not(windows))]
pub const SERVICE_LABEL: &str = "dev.ucb.universal-clipboard";

/// Windows service key name (`sc`/SCM identifier) and human-readable label.
/// Kept available on all platforms so the pure logic can be unit-tested
/// cross-platform (the SCM calls themselves live in the `windows` module).
/// Off Windows these are only referenced by the cross-platform test.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_SERVICE_NAME: &str = "ucb";
/// Display name shown in the Windows Services console.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_DISPLAY_NAME: &str = "Universal Clipboard";
/// Service description registered with the SCM.
#[cfg_attr(not(windows), allow(dead_code))]
pub const SERVICE_DESCRIPTION: &str =
    "End-to-end encrypted LAN clipboard sync daemon (ucb run).";

/// Which init system this platform uses.
///
/// Both variants are constructed via [`ServiceKind::current`] on their
/// respective platforms (and in unit tests), so `dead_code` is allowed for the
/// variant that the current build target never selects.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ServiceKind {
    Launchd,
    Systemd,
}

#[cfg(not(windows))]
impl ServiceKind {
    /// The init system for the host platform, or `None` on unsupported ones
    /// (e.g. Windows — deferred, see ARCHITECTURE.md).
    pub fn current() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            Some(ServiceKind::Launchd)
        }
        #[cfg(target_os = "linux")]
        {
            Some(ServiceKind::Systemd)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

/// Escape a string for inclusion in an XML text node (launchd plists are XML).
#[cfg(not(windows))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a launchd user-agent plist that runs `program` with `args`,
/// keep-alive and run-at-load enabled (BG-1). Pure function — unit-tested.
#[cfg(not(windows))]
pub fn launchd_plist(program: &str, args: &[String]) -> String {
    let mut program_args = String::new();
    // argv[0] is the program itself, followed by the passed args.
    program_args.push_str(&format!(
        "\t\t<string>{}</string>\n",
        xml_escape(program)
    ));
    for a in args {
        program_args.push_str(&format!("\t\t<string>{}</string>\n", xml_escape(a)));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>Label</key>\n\
\t<string>{label}</string>\n\
\t<key>ProgramArguments</key>\n\
\t<array>\n{program_args}\t</array>\n\
\t<key>RunAtLoad</key>\n\
\t<true/>\n\
\t<key>KeepAlive</key>\n\
\t<true/>\n\
</dict>\n\
</plist>\n",
        label = SERVICE_LABEL,
        program_args = program_args,
    )
}

/// Render a systemd user unit that runs `exec_start` (a fully-quoted command
/// line) as a restart-on-failure service (BG-1). Pure function — unit-tested.
#[cfg(not(windows))]
pub fn systemd_unit(exec_start: &str) -> String {
    format!(
        "[Unit]\n\
Description=Universal Clipboard sync daemon\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
Restart=on-failure\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        exec_start = exec_start,
    )
}

/// Quote one argument for a systemd `ExecStart` line (space/quote-safe).
#[cfg(not(windows))]
fn systemd_quote(arg: &str) -> String {
    if arg.is_empty() || arg.contains([' ', '\t', '"', '\\', '\'']) {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// Build a systemd `ExecStart` command line from a program + args.
#[cfg(not(windows))]
pub fn systemd_exec_start(program: &str, args: &[String]) -> String {
    let mut parts = vec![systemd_quote(program)];
    parts.extend(args.iter().map(|a| systemd_quote(a)));
    parts.join(" ")
}

/// Absolute path where the service definition is written for `kind`.
#[cfg(not(windows))]
pub fn definition_path(kind: ServiceKind, home: &Path) -> PathBuf {
    match kind {
        ServiceKind::Launchd => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{SERVICE_LABEL}.plist")),
        ServiceKind::Systemd => home
            .join(".config")
            .join("systemd")
            .join("user")
            .join(format!("{SERVICE_LABEL}.service")),
    }
}

/// The `ucb run` argument vector the service should launch, honoring an active
/// `--config-dir` override so the installed service targets the same state.
pub fn run_args(config_dir_override: Option<&Path>) -> Vec<String> {
    match config_dir_override {
        Some(dir) => vec![
            "--config-dir".to_string(),
            dir.display().to_string(),
            "run".to_string(),
        ],
        None => vec!["run".to_string()],
    }
}

/// Rendered service definition (content + destination path + activation hint)
/// for the current host platform.
#[cfg(not(windows))]
pub struct Definition {
    pub kind: ServiceKind,
    pub path: PathBuf,
    pub content: String,
    /// Shell command that activates the service.
    pub activate_cmd: String,
    /// Shell command that deactivates the service.
    pub deactivate_cmd: String,
}

/// Compute the service definition for the current platform, launching
/// `program` with `args`.
#[cfg(not(windows))]
pub fn definition_for_current(
    home: &Path,
    program: &str,
    args: &[String],
) -> Result<Definition> {
    let kind = ServiceKind::current().ok_or_else(|| {
        anyhow!("background-service install is not supported on this platform yet (Windows is deferred; see ARCHITECTURE.md)")
    })?;
    let path = definition_path(kind, home);
    let (content, activate_cmd, deactivate_cmd) = match kind {
        ServiceKind::Launchd => (
            launchd_plist(program, args),
            format!("launchctl load -w {}", path.display()),
            format!("launchctl unload -w {}", path.display()),
        ),
        ServiceKind::Systemd => (
            systemd_unit(&systemd_exec_start(program, args)),
            format!("systemctl --user enable --now {SERVICE_LABEL}.service"),
            format!("systemctl --user disable --now {SERVICE_LABEL}.service"),
        ),
    };
    Ok(Definition {
        kind,
        path,
        content,
        activate_cmd,
        deactivate_cmd,
    })
}

/// Best-effort home directory for the current user.
#[cfg(not(windows))]
pub fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .ok_or_else(|| anyhow!("could not determine the current user's home directory"))
}

/// Write `def.content` to `def.path`, creating parent dirs.
#[cfg(not(windows))]
pub fn write_definition(def: &Definition) -> Result<()> {
    if let Some(parent) = def.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&def.path, &def.content)
        .with_context(|| format!("writing service definition to {}", def.path.display()))?;
    Ok(())
}

/// Windows service integration (BG-1): register/remove/query the ucb daemon as
/// a Windows service via the SCM, using the `windows-service` crate.
///
/// The service is registered to launch `ucb run` (honoring any active
/// `--config-dir` override, via [`run_args`]) as an auto-start LocalSystem
/// service. Note: a service started by the SCM must speak the service-control
/// protocol; this module handles registration/management — a production install
/// would pair it with a service entry point. The management surface here mirrors
/// the launchd/systemd flow so `ucb service {install,uninstall,status}` works on
/// Windows instead of returning the previous "unsupported" error.
#[cfg(windows)]
pub mod windows {
    use std::ffi::OsString;
    use std::path::Path;

    use anyhow::{Context, Result};
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{SERVICE_DESCRIPTION, WINDOWS_DISPLAY_NAME, WINDOWS_SERVICE_NAME};

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access)
            .context("opening the Windows service manager (run as Administrator)")
    }

    /// Register the ucb service with the SCM, launching `program` with `args`
    /// (`ucb run`). Optionally start it immediately.
    pub fn install(program: &Path, args: &[String], start_now: bool) -> Result<()> {
        let manager =
            manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: OsString::from(WINDOWS_SERVICE_NAME),
            display_name: OsString::from(WINDOWS_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: program.to_path_buf(),
            launch_arguments: args.iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("creating the ucb Windows service")?;
        let _ = service.set_description(SERVICE_DESCRIPTION);
        println!("Installed Windows service '{WINDOWS_SERVICE_NAME}' ({WINDOWS_DISPLAY_NAME}).");
        println!("  {} {}", program.display(), args.join(" "));
        if start_now {
            let no_args: [OsString; 0] = [];
            service
                .start(&no_args)
                .context("starting the ucb Windows service")?;
            println!("Started service '{WINDOWS_SERVICE_NAME}'.");
        } else {
            println!("It is set to start automatically at boot. To start it now, run:");
            println!("  sc start {WINDOWS_SERVICE_NAME}");
        }
        Ok(())
    }

    /// Remove the ucb service from the SCM, optionally stopping it first.
    pub fn uninstall(stop_first: bool) -> Result<()> {
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .context("opening the ucb Windows service (is it installed?)")?;
        if stop_first {
            if let Ok(status) = service.query_status() {
                if status.current_state != ServiceState::Stopped {
                    let _ = service.stop();
                    println!("Stop requested for service '{WINDOWS_SERVICE_NAME}'.");
                }
            }
        }
        service
            .delete()
            .context("deleting the ucb Windows service")?;
        println!("Removed Windows service '{WINDOWS_SERVICE_NAME}'.");
        if !stop_first {
            println!("If it is still running, stop it with: sc stop {WINDOWS_SERVICE_NAME}");
        }
        Ok(())
    }

    /// Report whether the ucb service is registered and its current state.
    pub fn status() -> Result<()> {
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        match manager.open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                let status = service
                    .query_status()
                    .context("querying the ucb Windows service status")?;
                println!(
                    "Windows service '{WINDOWS_SERVICE_NAME}' is installed; state: {:?}",
                    status.current_state
                );
            }
            Err(_) => {
                println!("Windows service '{WINDOWS_SERVICE_NAME}' is not installed.");
                println!("Install it with `ucb service install`.");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[cfg(not(windows))]
    #[test]
    fn launchd_plist_contains_label_and_args() {
        let plist = launchd_plist("/usr/local/bin/ucb", &["run".to_string()]);
        assert!(plist.contains("<?xml"));
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains(&format!("<string>{SERVICE_LABEL}</string>")));
        assert!(plist.contains("<string>/usr/local/bin/ucb</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        // ProgramArguments array order: program first, then args.
        let prog = plist.find("/usr/local/bin/ucb").unwrap();
        let run = plist.find("<string>run</string>").unwrap();
        assert!(prog < run, "program must precede its args in the array");
    }

    #[cfg(not(windows))]
    #[test]
    fn launchd_plist_escapes_xml() {
        let plist = launchd_plist("/opt/ucb & co/ucb", &["run".to_string()]);
        assert!(plist.contains("/opt/ucb &amp; co/ucb"));
        assert!(!plist.contains("ucb & co"));
    }

    #[cfg(not(windows))]
    #[test]
    fn systemd_unit_contains_execstart_and_install() {
        let exec = systemd_exec_start("/usr/bin/ucb", &["run".to_string()]);
        let unit = systemd_unit(&exec);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("ExecStart=/usr/bin/ucb run"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[cfg(not(windows))]
    #[test]
    fn systemd_exec_start_quotes_spaces() {
        let exec = systemd_exec_start(
            "/opt/my apps/ucb",
            &["--config-dir".to_string(), "/tmp/a b".to_string(), "run".to_string()],
        );
        assert_eq!(exec, "\"/opt/my apps/ucb\" --config-dir \"/tmp/a b\" run");
    }

    #[test]
    fn run_args_honors_config_dir_override() {
        assert_eq!(run_args(None), vec!["run".to_string()]);
        let with = run_args(Some(Path::new("/tmp/ucb-state")));
        assert_eq!(
            with,
            vec![
                "--config-dir".to_string(),
                "/tmp/ucb-state".to_string(),
                "run".to_string()
            ]
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn definition_paths_are_platform_correct() {
        let home = Path::new("/home/tester");
        assert_eq!(
            definition_path(ServiceKind::Launchd, home),
            Path::new("/home/tester/Library/LaunchAgents/dev.ucb.universal-clipboard.plist")
        );
        assert_eq!(
            definition_path(ServiceKind::Systemd, home),
            Path::new("/home/tester/.config/systemd/user/dev.ucb.universal-clipboard.service")
        );
    }

    // Cross-platform coverage for the Windows service registration inputs: the
    // SCM launch arguments are exactly the `ucb run` argv (with any config-dir
    // override), and the identifiers are stable. This exercises the pure logic
    // the `windows` module feeds to the SCM without needing a Windows host.
    #[test]
    fn windows_service_identifiers_and_launch_args() {
        assert_eq!(WINDOWS_SERVICE_NAME, "ucb");
        assert_eq!(WINDOWS_DISPLAY_NAME, "Universal Clipboard");
        assert!(SERVICE_DESCRIPTION.contains("clipboard"));

        // Default: the service runs plain `ucb run`.
        assert_eq!(run_args(None), vec!["run".to_string()]);

        // With a sandboxed config dir, the override is carried through so the
        // service targets the same state directory.
        let launch = run_args(Some(Path::new("/opt/ucb-state")));
        assert_eq!(
            launch,
            vec![
                "--config-dir".to_string(),
                "/opt/ucb-state".to_string(),
                "run".to_string()
            ]
        );
        // These are what the SCM would receive as `launch_arguments`.
        let os_args: Vec<std::ffi::OsString> =
            launch.iter().map(std::ffi::OsString::from).collect();
        assert_eq!(os_args.len(), 3);
        assert_eq!(os_args[2], std::ffi::OsString::from("run"));
    }
}
