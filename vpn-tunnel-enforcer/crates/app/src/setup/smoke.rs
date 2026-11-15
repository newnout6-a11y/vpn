//! `--smoke`: the installer / CI smoke test (`installer/PROGRESS.md`). Builds the backend as a
//! start does (data dir and its lock, log, legacy import, every store) without a window, checks
//! that the bundled engine files are there and drains the log. No network activity, no system
//! change, no elevation.
use crate::args::Args;
use crate::svc_core;

use super::system::app_err;

/// The engine files of the installed layout (`<exe dir>\resources`).
const ENGINE_FILES: [&str; 4] = ["sing-box.exe", "libcronet.dll", "xray.exe", "wintun.dll"];

/// `Ok` = the one stdout line; `Err` = the one stderr line.
pub fn smoke(args: &Args) -> Result<String, String> {
    let backend = svc_core::build(args)
        .map_err(|err| format!("Smoke test failed: backend not ready ({}).", app_err(&err)))?;
    let missing: Vec<&str> = ENGINE_FILES
        .into_iter()
        .filter(|name| !backend.dirs.resources.join(name).is_file())
        .collect();
    let result = if missing.is_empty() {
        Ok(format!(
            "VPN Tunnel Enforcer {} smoke ok",
            env!("CARGO_PKG_VERSION")
        ))
    } else {
        Err(format!(
            "Smoke test failed: engine files missing ({}).",
            missing.join(", ")
        ))
    };
    tracing::info!(ok = result.is_ok(), "smoke test finished");
    // Last: the log queue reaches the disk before the process ends.
    drop(backend.log.lock().take());
    result
}
