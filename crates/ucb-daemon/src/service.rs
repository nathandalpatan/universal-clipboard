//! Desktop background service integration (BG-1/BG-6): generate and manage a
//! launchd agent (macOS) or systemd user unit (Linux) that runs `ucb run`.
//!
//! The plist / unit *content* is produced by the pure functions
//! [`launchd_plist`] and [`systemd_unit`] (unit-tested below). Installation only
//! writes the file and prints the activation command — this code never runs
//! `launchctl`/`systemctl` itself unless the user passes `--activate`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// launchd label / systemd unit stem (matches the config dir vendor id).
pub const SERVICE_LABEL: &str = "dev.ucb.universal-clipboard";

/// Which init system this platform uses.
///
/// Both variants are constructed via [`ServiceKind::current`] on their
/// respective platforms (and in unit tests), so `dead_code` is allowed for the
/// variant that the current build target never selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ServiceKind {
    Launchd,
    Systemd,
}

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
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render a launchd user-agent plist that runs `program` with `args`,
/// keep-alive and run-at-load enabled (BG-1). Pure function — unit-tested.
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
fn systemd_quote(arg: &str) -> String {
    if arg.is_empty() || arg.contains([' ', '\t', '"', '\\', '\'']) {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// Build a systemd `ExecStart` command line from a program + args.
pub fn systemd_exec_start(program: &str, args: &[String]) -> String {
    let mut parts = vec![systemd_quote(program)];
    parts.extend(args.iter().map(|a| systemd_quote(a)));
    parts.join(" ")
}

/// Absolute path where the service definition is written for `kind`.
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
pub fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .ok_or_else(|| anyhow!("could not determine the current user's home directory"))
}

/// Write `def.content` to `def.path`, creating parent dirs.
pub fn write_definition(def: &Definition) -> Result<()> {
    if let Some(parent) = def.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&def.path, &def.content)
        .with_context(|| format!("writing service definition to {}", def.path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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

    #[test]
    fn launchd_plist_escapes_xml() {
        let plist = launchd_plist("/opt/ucb & co/ucb", &["run".to_string()]);
        assert!(plist.contains("/opt/ucb &amp; co/ucb"));
        assert!(!plist.contains("ucb & co"));
    }

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
}
