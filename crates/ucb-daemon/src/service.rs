//! Desktop background service integration (BG-1/BG-6): generate and manage a
//! launchd agent (macOS), systemd user unit (Linux) or per-user login `Run`
//! entry (Windows) that runs `ucb run`.
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

/// Windows (BG-1): the daemon autostarts at login from a per-user entry under
/// this HKCU key. A Windows Service can't be used: services run in session 0 and
/// can't reach the signed-in user's clipboard, need Administrator rights to
/// install, and run as another account with its own config dir.
/// Kept on all platforms so the pure helpers below are unit-tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Value name of the login entry under [`WINDOWS_RUN_KEY`].
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_RUN_VALUE: &str = "UniversalClipboard";
/// The windowless launcher (`src/bin/ucbw.rs`) the login entry starts, so no
/// console window opens. Shipped next to `ucb.exe`.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_LAUNCHER: &str = "ucbw.exe";

/// Quote one argument by the MSVC / `CommandLineToArgvW` rules, so the stored
/// command line splits back into exactly `arg`.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Backslashes before the closing quote must be doubled.
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The command line stored in the Windows login entry: `launcher` then `args`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_run_command(launcher: &str, args: &[String]) -> String {
    std::iter::once(launcher)
        .chain(args.iter().map(String::as_str))
        .map(windows_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

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
    /// The init system for the host platform, or `None` on unsupported ones.
    /// (Windows uses a login `Run` entry instead; see the `windows` module.)
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
        anyhow!("background-service install is not supported on this platform yet")
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

/// Windows login autostart (BG-1): a per-user `HKCU\...\Run` entry that starts
/// the daemon through the windowless [`WINDOWS_LAUNCHER`] at sign-in. No
/// Administrator rights; the daemon runs in the user's session with the user's
/// config dir, so it can reach the clipboard.
#[cfg(windows)]
pub mod windows {
    use std::path::Path;
    use std::process::{Command, Stdio};

    use anyhow::{bail, Context, Result};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
        RRF_RT_REG_SZ,
    };

    use super::{windows_run_command, WINDOWS_LAUNCHER, WINDOWS_RUN_KEY, WINDOWS_RUN_VALUE};

    /// NUL-terminated UTF-16 for the Win32 `W` APIs.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_run_value(command: &str) -> Result<()> {
        let (key, name, data) = (wide(WINDOWS_RUN_KEY), wide(WINDOWS_RUN_VALUE), wide(command));
        let bytes = u32::try_from(data.len() * 2).context("login command line too long")?;
        // SAFETY: every pointer is a NUL-terminated UTF-16 buffer that outlives
        // the call, and `bytes` is `data`'s size in bytes including the NUL.
        let rc = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                REG_SZ,
                data.as_ptr().cast(),
                bytes,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("writing HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE} failed (Win32 error {rc})");
        }
        Ok(())
    }

    fn get_run_value() -> Result<Option<String>> {
        let (key, name) = (wide(WINDOWS_RUN_KEY), wide(WINDOWS_RUN_VALUE));
        let mut bytes: u32 = 0;
        // SAFETY: size query; a null data pointer asks only for the byte size.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            bail!("reading HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE} failed (Win32 error {rc})");
        }
        let mut buf = vec![0u16; (bytes as usize).div_ceil(2)];
        // SAFETY: `buf` holds at least `bytes` bytes, as reported by the query.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc != ERROR_SUCCESS {
            bail!("reading HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE} failed (Win32 error {rc})");
        }
        let len = (bytes as usize / 2).min(buf.len());
        Ok(Some(
            String::from_utf16_lossy(&buf[..len])
                .trim_end_matches('\0')
                .to_string(),
        ))
    }

    /// Remove the login entry. Returns whether it existed.
    fn delete_run_value() -> Result<bool> {
        let (key, name) = (wide(WINDOWS_RUN_KEY), wide(WINDOWS_RUN_VALUE));
        // SAFETY: both pointers are NUL-terminated UTF-16 buffers outliving the call.
        let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) };
        match rc {
            ERROR_SUCCESS => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            rc => bail!("removing HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE} failed (Win32 error {rc})"),
        }
    }

    /// Register the login entry for `ucbw.exe <args>` (next to `exe`), and with
    /// `start_now` also start the daemon immediately.
    pub fn install(exe: &Path, args: &[String], start_now: bool) -> Result<()> {
        let launcher = exe.with_file_name(WINDOWS_LAUNCHER);
        if !launcher.exists() {
            bail!(
                "{} not found next to {}; it is needed to run the daemon without a console window",
                launcher.display(),
                exe.display()
            );
        }
        let command = windows_run_command(&launcher.to_string_lossy(), args);
        set_run_value(&command)?;
        println!("Installed login autostart (HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE}):");
        println!("  {command}");
        if start_now {
            Command::new(&launcher)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("starting {}", launcher.display()))?;
            println!("Started the daemon in the background.");
        } else {
            println!("It starts at your next sign-in. To start it now, run:");
            println!("  {command}");
        }
        Ok(())
    }

    /// Remove the login entry. A daemon that is already running is left alone:
    /// there is no IPC shutdown command, and killing every `ucb.exe` could take
    /// out a GUI-managed one.
    pub fn uninstall() -> Result<()> {
        if delete_run_value()? {
            println!("Removed login autostart (HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE}).");
        } else {
            println!("Login autostart was not installed.");
        }
        println!("A daemon that is already running keeps syncing until you sign out.");
        Ok(())
    }

    /// Report whether the login entry exists and what it runs.
    pub fn status() -> Result<()> {
        match get_run_value()? {
            Some(command) => {
                println!("Login autostart installed (HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE}):");
                println!("  {command}");
            }
            None => {
                println!("Login autostart not installed.");
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

    // Cross-platform coverage for the Windows login entry: the stored command
    // line must split back into the launcher path + `ucb run` argv exactly
    // (CommandLineToArgvW rules), including paths with spaces.
    #[test]
    fn windows_run_command_plain_args_are_unquoted() {
        assert_eq!(
            windows_run_command(r"C:\ucb\ucbw.exe", &run_args(None)),
            r"C:\ucb\ucbw.exe run"
        );
    }

    #[test]
    fn windows_run_command_quotes_spaces_and_trailing_backslashes() {
        let args = run_args(Some(Path::new(r"C:\Users\a b\cfg\")));
        assert_eq!(
            windows_run_command(r"C:\Program Files\Universal Clipboard\ucbw.exe", &args),
            r#""C:\Program Files\Universal Clipboard\ucbw.exe" --config-dir "C:\Users\a b\cfg\\" run"#
        );
    }

    #[test]
    fn windows_quote_escapes_quotes_and_empty() {
        assert_eq!(windows_quote(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(windows_quote(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(windows_quote(""), r#""""#);
        assert_eq!(windows_quote(r"C:\no-spaces\x"), r"C:\no-spaces\x");
    }

    #[test]
    fn windows_run_entry_identifiers_are_stable() {
        assert_eq!(WINDOWS_RUN_KEY, r"Software\Microsoft\Windows\CurrentVersion\Run");
        assert_eq!(WINDOWS_RUN_VALUE, "UniversalClipboard");
        assert_eq!(WINDOWS_LAUNCHER, "ucbw.exe");
    }
}
