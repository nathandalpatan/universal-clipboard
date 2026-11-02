//! `ucbw`: windowless launcher for the background daemon on Windows (BG-1).
//!
//! `ucb.exe` is a console program, so starting it from the login `Run` entry
//! would open a console window that stops sync when closed. This
//! Windows-subsystem binary starts `ucb.exe` (from its own directory) with the
//! given arguments and no window, then exits.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, ExitCode, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Ok(exe) = std::env::current_exe() else {
        return ExitCode::FAILURE;
    };
    let spawned = Command::new(exe.with_file_name("ucb.exe"))
        .args(std::env::args_os().skip(1))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    // There is no console to report to; the exit code is all a caller sees.
    if spawned.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("ucbw is the Windows background launcher; run `ucb` directly on this platform.");
    std::process::exit(1);
}
