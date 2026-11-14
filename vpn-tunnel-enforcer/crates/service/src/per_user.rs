//! What the per-user side runs against the service: the product's one elevated step, asked of
//! Windows (`install` through `ShellExecuteEx("runas")`: Windows shows its own prompt; the
//! installer and the app never elevate themselves), the same for `uninstall` when Settings >
//! Apps removes the service (it starts the entry's command unelevated), and the per-user
//! uninstaller's leave (`ForgetMe` over the pipe, no prompt).
use std::path::Path;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{HSTRING, PCWSTR, w};

use crate::pipe::client::{CallError, Client, ServerCheck};
use crate::proto::{Reply, Request};
use crate::scm::manage;
use crate::sddl;
use crate::update::swap::{self, SwapFiles};

/// How the elevated install ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevated {
    /// The verb ran; its exit code (0 = installed, see `vpnte-service.exe`'s exit codes).
    Exited(u32),
    /// Nobody approved the prompt (declined, or no administrator account to approve it).
    Declined,
}

/// The `install` verb's arguments: `--resources` quoted (a path holds no `"`).
fn install_args(resources: Option<&Path>) -> String {
    match resources {
        Some(dir) => format!("install --resources \"{}\"", dir.display()),
        None => "install".to_owned(),
    }
}

/// Runs `exe install [--resources <dir>]` elevated and waits for it: one prompt from Windows.
/// Blocking (call it from a blocking thread).
pub fn request_install(exe: &Path, resources: Option<&Path>) -> std::io::Result<Elevated> {
    run_elevated(exe, &install_args(resources))
}

/// Runs `exe uninstall` elevated and waits for it: one prompt from Windows (the command of the
/// service's entry in Settings > Apps). Blocking.
pub fn request_uninstall(exe: &Path) -> std::io::Result<Elevated> {
    run_elevated(exe, "uninstall")
}

fn run_elevated(exe: &Path, params: &str) -> std::io::Result<Elevated> {
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(params);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: `info` is initialised, its strings outlive the call.
    if let Err(err) = unsafe { ShellExecuteExW(&mut info) } {
        if err.code() == ERROR_CANCELLED.to_hresult() {
            return Ok(Elevated::Declined);
        }
        return Err(std::io::Error::other(err));
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err(std::io::Error::other(
            "no process handle from ShellExecuteEx",
        ));
    }
    let mut code = 0u32;
    // SAFETY: a process handle we own (SEE_MASK_NOCLOSEPROCESS); closed once below.
    let exited = unsafe {
        WaitForSingleObject(process, INFINITE);
        let exited = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
        exited
    };
    exited.map_err(std::io::Error::other)?;
    Ok(Elevated::Exited(code))
}

/// The installed service is this very build, byte for byte, and settled: a reinstall of the
/// same version asks for no prompt.
pub fn is_current(exe: &Path) -> bool {
    let Ok(Some(installed)) = manage::installed_binary() else {
        return false;
    };
    same_settled(&installed, exe)
}

/// `installed` is `ours` byte for byte and no swap of it is on trial. A fresh exe that crashes
/// inside the SCM dispatch never reaches the start that counts its trial, so it would never roll
/// back: the release installer's install is its repair (svcupd-a9). The swap folder is readable
/// by users; a spent trial's record is settled (the previous exe is back).
fn same_settled(installed: &Path, ours: &Path) -> bool {
    let on_trial = swap::marker(&SwapFiles::new(installed)).is_some_and(|m| !m.spent());
    if on_trial {
        return false;
    }
    match (std::fs::read(installed), std::fs::read(ours)) {
        (Ok(installed), Ok(ours)) => installed == ours,
        _ => false,
    }
}

/// Our service answers over its pipe (CI's smoke run, diagnostics): its version. Another client
/// holding the controller slot still counts as an answer.
pub async fn status() -> Result<String, CallError> {
    let exe = match manage::installed_binary() {
        Ok(Some(exe)) => exe,
        Ok(None) => return Ok("not installed".into()),
        Err(err) => return Err(CallError::Pipe(vpnte_base::AppError::internal(err))),
    };
    let check = ServerCheck::Image(exe);
    let mut client = Client::connect(sddl::PIPE_NAME, &check, Duration::from_secs(10))
        .await
        .map_err(CallError::Pipe)?;
    match client.hello(env!("CARGO_PKG_VERSION")).await {
        Ok((_, version)) => Ok(format!("running {version}")),
        Err(CallError::Service(e)) if e.code == crate::proto::ErrorCode::Busy => {
            Ok("running (in use)".into())
        }
        Err(err) => Err(err),
    }
}

/// The per-user uninstaller's leave: `ForgetMe` as the first frame, to our service only.
/// `Ok(None)`: no service installed (nothing to tell); `Ok(Some(removing))`: done, `removing`
/// when this was the last user (the service removes itself). An `Err(Service(..))` with key
/// `service.uninstall.filtersKept` means the service stays to remove its filters later.
pub async fn forget_me() -> Result<Option<bool>, CallError> {
    let exe = match manage::installed_binary() {
        Ok(Some(exe)) => exe,
        Ok(None) => return Ok(None),
        Err(err) => return Err(CallError::Pipe(vpnte_base::AppError::internal(err))),
    };
    let check = ServerCheck::Image(exe);
    let mut client = Client::connect(sddl::PIPE_NAME, &check, Duration::from_secs(10))
        .await
        .map_err(CallError::Pipe)?;
    match client.call(Request::ForgetMe).await? {
        Reply::Done { removing } => Ok(Some(removing)),
        other => {
            tracing::warn!(?other, "unexpected reply to ForgetMe");
            Ok(Some(false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resources_folder_is_quoted() {
        assert_eq!(install_args(None), "install");
        let dir = Path::new(r"C:\Users\A B\AppData\Local\Programs\VPN Tunnel Enforcer\resources");
        assert_eq!(
            install_args(Some(dir)),
            format!("install --resources \"{}\"", dir.display())
        );
    }

    /// svcupd-a9 (p-follow3): the same bytes are current only while no swap of them is on
    /// trial (the installer's install repairs a fresh exe that crashes before its trial counts);
    /// a spent trial's record (the previous exe back) is settled.
    #[test]
    fn a_swap_on_trial_is_not_current() {
        use crate::update::swap::{Marker, TRIAL_STARTS};
        use vpnte_update::version::Version;
        let dir = std::env::temp_dir().join(format!("vpnte-per-user-{}", std::process::id()));
        let (installed, ours) = (dir.join("vpnte-service.exe"), dir.join("o.exe"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(&installed, b"service build").expect("installed");
        std::fs::write(&ours, b"service build").expect("ours");
        assert!(same_settled(&installed, &ours));
        let staging = SwapFiles::new(&installed).staging;
        std::fs::create_dir_all(&staging).expect("staging");
        let mark = |starts| {
            let m = Marker {
                from: Version(2, 0, 0),
                to: Version(2, 0, 1),
                starts,
            };
            let json = serde_json::to_vec(&m).expect("json");
            std::fs::write(staging.join("swap.json"), json).expect("marker");
        };
        mark(1);
        assert!(!same_settled(&installed, &ours), "on trial");
        mark(TRIAL_STARTS);
        assert!(same_settled(&installed, &ours), "a spent trial's record");
        std::fs::write(&ours, b"another build").expect("ours");
        assert!(!same_settled(&installed, &ours));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
