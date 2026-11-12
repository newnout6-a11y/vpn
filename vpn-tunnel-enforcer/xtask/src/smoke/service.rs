//! The helper service in the smoke run (CI's elevated runner, where Windows asks no prompt): after the install
//! and after the upgrade it is installed in Program Files, running and answering over its pipe; after the
//! uninstall (the last user's leave) there is no service, no folder — tombstones queued for the next restart
//! aside — and no WFP object of ours.
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};

const SERVICE: &str = "VpnTunnelEnforcerService";
const FOLDER: &str = "VPN Tunnel Enforcer Service";
/// `ERROR_SERVICE_DOES_NOT_EXIST`: `sc.exe query`'s exit code for a service that is not installed.
const NOT_INSTALLED: i32 = 1060;
/// Our WFP provider and sublayer keys (`vpnte_winnet::wfp::{PROVIDER_KEY, SUBLAYER_KEY}`: keep in step).
const WFP_KEYS: [&str; 2] = [
    "264e9b5c-78c7-42e7-abef-f2fdfd1e2f1c",
    "cd654d3d-0fd7-4f8e-b1a6-c424b2f5794a",
];

fn folder() -> Result<PathBuf> {
    Ok(PathBuf::from(env::var("ProgramFiles").context("ProgramFiles")?).join(FOLDER))
}

/// `sc.exe query`: `None` when the service is not installed, else its text.
fn query() -> Result<Option<String>> {
    let out = Command::new("sc.exe")
        .args(["query", SERVICE])
        .output()
        .context("run sc.exe")?;
    if out.status.code() == Some(NOT_INSTALLED) {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// Installed in Program Files, running, and answering over its pipe (the app's copy checks that the
/// pipe's server is the installed exe).
pub fn check_running(app_dir: &Path) -> Result<()> {
    let state = query()?.context("the helper service is not installed")?;
    ensure!(
        state.contains("RUNNING"),
        "the helper service is not running:\n{state}"
    );
    let exe = folder()?.join("vpnte-service.exe");
    ensure!(exe.is_file(), "{} is missing", exe.display());
    let out = Command::new(app_dir.join("vpnte-service.exe"))
        .arg("status")
        .output()
        .context("run vpnte-service status")?;
    let said = String::from_utf8_lossy(&out.stderr);
    ensure!(
        out.status.success() && said.contains("running"),
        "the helper service does not answer: {said}"
    );
    println!(
        "  helper service installed, running, answering ({})",
        said.trim()
    );
    Ok(())
}

/// No service, no folder (but tombstones for the next restart), no WFP object of ours.
pub fn check_removed() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while query()?.is_some() {
        ensure!(
            Instant::now() < deadline,
            "the helper service is still installed after the last user left"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let folder = folder()?;
    if folder.exists() {
        let left: Vec<String> = walk(&folder)?
            .into_iter()
            .filter(|f| !f.ends_with(".deleted"))
            .collect();
        ensure!(
            left.is_empty(),
            "the service folder keeps files:\n  {}",
            left.join("\n  ")
        );
    }
    let dump = env::temp_dir().join(format!("vpnte-smoke-wfp-{}.xml", std::process::id()));
    let shown = Command::new("netsh.exe")
        .args(["wfp", "show", "state"])
        .arg(format!("file={}", dump.display()))
        .output()
        .context("run netsh wfp show state")?;
    ensure!(shown.status.success(), "netsh wfp show state failed");
    let state = text(&fs::read(&dump).context("read the WFP state")?).to_ascii_lowercase();
    let _ = fs::remove_file(&dump);
    for key in WFP_KEYS {
        ensure!(!state.contains(key), "a WFP object of ours is left: {key}");
    }
    println!("  helper service, its folder and its WFP objects removed");
    Ok(())
}

/// Every file under `dir`, as text.
fn walk(dir: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(walk(&path)?);
        } else {
            files.push(path.display().to_string());
        }
    }
    Ok(files)
}

/// The dump as text: UTF-16 with its byte-order mark, else UTF-8.
fn text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => {
            let (pairs, _) = rest.as_chunks::<2>();
            let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wfp_dump_reads_in_both_encodings() {
        assert_eq!(text(b"<a>x</a>"), "<a>x</a>");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<a>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(text(&utf16), "<a>");
    }
}
