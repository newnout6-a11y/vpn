//! Test helpers shared by the packages: the engines in `resources/`, throw-away directories and
//! the real-engine config checks (skipped quietly by the callers when a binary is absent).
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// `resources/` of the workspace (the bundled engines and rule sets on this machine).
pub(crate) fn resources() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"))
}

/// The bundled sing-box, when present.
pub(crate) fn singbox_exe() -> Option<PathBuf> {
    let exe = resources().join("sing-box.exe");
    exe.is_file().then_some(exe)
}

/// The bundled Xray, when present.
pub(crate) fn xray_exe() -> Option<PathBuf> {
    let exe = resources().join("xray.exe");
    exe.is_file().then_some(exe)
}

/// No console window for engines started by tests.
pub(crate) fn hidden(cmd: &mut Command) -> &mut Command {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW)
}

/// The test process stands in for the console-less app: a graceful stop attaches to the
/// engine's own console, which a process with a console of its own cannot do. Detaches from the
/// inherited one; `false` (stops then kill) when stdout / stderr is a terminal.
pub(crate) fn console_free() -> bool {
    let free = vpnte_winnet::process::detach_console();
    if !free {
        eprintln!("skipped: output is a terminal, the test process keeps its console");
    }
    free
}

/// A fresh directory under `%TEMP%`, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vpnte-engine-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `sing-box check -c stdin`: `Ok(true)` accepted, `Ok(false)` no binary, `Err` the engine's
/// complaint followed by the config.
pub(crate) fn singbox_check(config: &Value) -> Result<bool, String> {
    let Some(exe) = singbox_exe() else {
        return Ok(false);
    };
    let out = run_with_stdin(&exe, &["check", "-c", "stdin", "--disable-color"], config)?;
    if out.status.success() {
        return Ok(true);
    }
    Err(format!(
        "{}{}\n{config:#}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// `xray run -test -config stdin:` (builds the config without starting it): `Ok(true)`
/// "Configuration OK.", `Ok(false)` no binary, `Err` exit code and output.
pub(crate) fn xray_check(config: &Value) -> Result<bool, String> {
    let Some(exe) = xray_exe() else {
        return Ok(false);
    };
    let out = run_with_stdin(&exe, &["run", "-test", "-config", "stdin:"], config)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && stdout.contains("Configuration OK.") {
        return Ok(true);
    }
    Err(format!(
        "{:?}\n{stdout}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// Runs `exe args` with `config` on stdin (closing stdin ends the config) and collects output.
fn run_with_stdin(
    exe: &Path,
    args: &[&str],
    config: &Value,
) -> Result<std::process::Output, String> {
    let mut child = hidden(Command::new(exe).args(args))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", exe.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(config.to_string().as_bytes())
            .map_err(|e| format!("stdin: {e}"))?;
    }
    child.wait_with_output().map_err(|e| format!("wait: {e}"))
}
