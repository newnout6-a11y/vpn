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

/// The WP-12 lab engine mihomo (`cargo xtask engines` puts it in the dev drop), when present.
#[cfg(feature = "lab")]
pub(crate) fn mihomo_exe() -> Option<PathBuf> {
    let exe = resources().join("mihomo.exe");
    exe.is_file().then_some(exe)
}

/// An AmneziaWG profile with obviously fake keys: `interface` lines are added to `[Interface]`
/// (AWG parameters), the peer dials `endpoint`.
#[cfg(feature = "lab")]
pub(crate) fn awg_profile(interface: &str, endpoint: &str) -> vpnte_profiles::model::Profile {
    let conf = format!(
        "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.1.2/32\n\
         {interface}\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\
         Endpoint = {endpoint}\n"
    );
    vpnte_profiles::wg_ini::parse_wg_ini(&conf)
        .expect("a .conf")
        .expect("valid")
}

/// `[Interface]` AmneziaWG parameters of each generation (bounds of `awg::validate`).
#[cfg(feature = "lab")]
pub(crate) mod awg_samples {
    pub(crate) const V1_0: &str = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 18\nH1 = 1020325451\nH2 = 3288052141\nH3 = 2528465083\nH4 = 1766607858";
    const DNS_I1: &str = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>";
    const HPK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    pub(crate) fn v1_5() -> String {
        format!(
            "{V1_0}\nI1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>\nJ1 = <b 0xffffffff><c><b 0xf6ab><t><r 10>\nJ2 = <c><b 0xf6ab><t><wt 1000>\nItime = 60"
        )
    }

    pub(crate) fn v2_0() -> String {
        format!(
            "Jc = 5\nJmin = 500\nJmax = 501\nS1 = 30\nS2 = 40\nS3 = 50\nS4 = 8\nH1 = 100000-200000\nH2 = 300000-400000\nH3 = 500000-600000\nH4 = 700000-800000\nI1 = {DNS_I1}\nI2 = <b 0xf6ab3267fa><r 100>"
        )
    }

    pub(crate) fn v3_1() -> String {
        format!(
            "Jc = 5\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = {DNS_I1}\nHeaderProtectionKey = {HPK}\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\nRandomTrailers = on\nDisableCookies = on"
        )
    }
}

/// Fresh loopback endpoints of one mihomo run (SOCKS listener, hop, controller).
#[cfg(feature = "lab")]
pub(crate) fn mihomo_endpoints() -> (
    crate::slot::SlotEndpoint,
    crate::mihomo_config::HopEndpoint,
    crate::clash_api::ClashEndpoint,
) {
    let socks = crate::slot::SlotEndpoint::allocate(&[]).unwrap();
    let hop = crate::mihomo_config::HopEndpoint::allocate(&[socks.port()]).unwrap();
    let controller =
        crate::clash_api::ClashEndpoint::allocate(&[socks.port(), hop.port()]).unwrap();
    (socks, hop, controller)
}

/// Opens the lab gate of this test process with a complete record in a throw-away dir (tests
/// that need it closed use `lab::select` with an explicit gate instead).
#[cfg(feature = "lab")]
pub(crate) fn open_lab_gate() {
    let dir = TempDir::new("lab-gate");
    let path = crate::lab::record_path(dir.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "passed": crate::lab::REQUIRED,
        "by": "engine tests",
    });
    std::fs::write(path, record.to_string()).unwrap();
    crate::lab::activate(dir.path()).expect("complete record");
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
