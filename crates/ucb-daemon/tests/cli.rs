//! CLI usability surface tests for `ucb info`, `ucb guide`, and the help text.
//!
//! Fully sandboxed: every invocation uses a temp `--config-dir` with a file
//! keystore (never the OS keychain) and never touches the network. These drive
//! the real `ucb` binary the same way a user would.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn ucb_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ucb")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from("/tmp").join(format!(
        "ucb-cli-{}-{}-{}",
        tag,
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `ucb init --file-keystore --print-id` in a sandbox; returns (cfg dir, id, name).
fn init_sandbox(tag: &str) -> (PathBuf, String, String) {
    let cfg = temp_dir(tag);
    let out = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["init", "--name", "Test Device", "--file-keystore", "--print-id"])
        .output()
        .expect("failed to run `ucb init`");
    assert!(out.status.success(), "init failed: {out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("init --print-id JSON");
    let id = v["id"].as_str().expect("id").to_string();
    let name = v["name"].as_str().expect("name").to_string();
    (cfg, id, name)
}

#[test]
fn info_before_init_errors_cleanly() {
    let cfg = temp_dir("noinit");
    let out = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .arg("info")
        .output()
        .expect("failed to run `ucb info`");
    assert!(!out.status.success(), "info must fail before init");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ucb init"),
        "error should point at `ucb init`: {stderr}"
    );
}

#[test]
fn info_after_init_shows_identity_and_daemon_not_running() {
    let (cfg, id, _name) = init_sandbox("info");
    let out = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .arg("info")
        .output()
        .expect("failed to run `ucb info`");
    assert!(out.status.success(), "info failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("Test Device"), "shows device name: {stdout}");
    // The short id is the first 8 hex chars of the full id.
    let short = &id[..8];
    assert!(stdout.contains(short), "shows short id {short}: {stdout}");
    assert!(stdout.contains(&id), "shows full id: {stdout}");
    assert!(stdout.contains("48521"), "shows the listen port: {stdout}");
    assert!(
        stdout.contains("not running"),
        "daemon-not-running line: {stdout}"
    );
}

#[test]
fn info_json_parses_with_expected_keys() {
    let (cfg, id, _name) = init_sandbox("infojson");
    let out = Command::new(ucb_bin())
        .args(["--config-dir", cfg.to_str().unwrap()])
        .args(["info", "--json"])
        .output()
        .expect("failed to run `ucb info --json`");
    assert!(out.status.success(), "info --json failed: {out:?}");
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("info --json emits one JSON object");

    assert_eq!(v["name"], serde_json::json!("Test Device"));
    assert_eq!(v["id"], serde_json::json!(id));
    assert_eq!(v["id_short"], serde_json::json!(&id[..8]));
    assert_eq!(v["listen_port"], serde_json::json!(48521));
    assert_eq!(v["daemon_running"], serde_json::json!(false));
    assert_eq!(v["paired_count"], serde_json::json!(0));
    assert_eq!(v["revoked_count"], serde_json::json!(0));
    // Present and typed as expected.
    assert!(v["platform"].as_str().is_some(), "platform: {v}");
    assert!(v["keystore"].as_str().is_some(), "keystore: {v}");
    assert!(v["config_dir"].as_str().is_some(), "config_dir: {v}");
    assert!(v["protocol_version"].as_u64().is_some(), "protocol_version: {v}");
    assert!(v["version"].as_str().is_some(), "version: {v}");
    assert_eq!(v["auto_file_sync"], serde_json::json!(false));
    assert!(v["max_auto_file_bytes"].as_u64().is_some(), "max_auto_file_bytes: {v}");
    assert!(v["max_auto_file_bytes_human"].as_str().is_some(), "human bytes: {v}");
    assert!(v["peers"].as_array().is_some(), "peers array: {v}");
    assert!(v["paired"].as_array().is_some(), "paired array: {v}");
}

#[test]
fn top_level_help_contains_quick_start() {
    let out = Command::new(ucb_bin())
        .arg("--help")
        .output()
        .expect("failed to run `ucb --help`");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("QUICK START"), "quick start block: {stdout}");
    assert!(stdout.contains("ucb guide"), "mentions guide: {stdout}");
    assert!(stdout.contains("ucb info"), "mentions info: {stdout}");
}

#[test]
fn pair_help_contains_examples() {
    let out = Command::new(ucb_bin())
        .args(["pair", "--help"])
        .output()
        .expect("failed to run `ucb pair --help`");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("EXAMPLES:"), "pair examples: {stdout}");
    assert!(stdout.contains("--listen"), "pair listen example: {stdout}");
    assert!(stdout.contains("--connect"), "pair connect example: {stdout}");
}

#[test]
fn history_help_contains_examples() {
    let out = Command::new(ucb_bin())
        .args(["history", "--help"])
        .output()
        .expect("failed to run `ucb history --help`");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("EXAMPLES:"), "history examples: {stdout}");
    assert!(stdout.contains("--search"), "history search example: {stdout}");
    assert!(stdout.contains("--starred"), "history starred example: {stdout}");
}

#[test]
fn guide_runs_and_contains_section_headings() {
    let out = Command::new(ucb_bin())
        .arg("guide")
        .output()
        .expect("failed to run `ucb guide`");
    assert!(out.status.success(), "guide failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for heading in [
        "FIRST-TIME SETUP",
        "PAIRING TWO MACHINES",
        "EVERYDAY USE",
        "HISTORY",
        "KEEPING IT RUNNING",
        "TROUBLESHOOTING",
    ] {
        assert!(stdout.contains(heading), "guide is missing '{heading}':\n{stdout}");
    }
    // macOS gotcha guidance is called out explicitly.
    assert!(stdout.contains("No route to host"), "macOS gotcha: {stdout}");
    assert!(stdout.contains("RUST_LOG=debug"), "debug log tip: {stdout}");
}
