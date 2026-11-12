//! What the per-user side runs against the service: the product's one elevated step, asked of
//! Windows (`install` through `ShellExecuteEx("runas")`: Windows shows its own prompt; the
//! installer and the app never elevate themselves), and the per-user uninstaller's leave
//! (`ForgetMe` over the pipe, no prompt).
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
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(install_args(resources));
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

/// The installed service is this very build, byte for byte: a reinstall of the same version asks
/// for no prompt.
pub fn is_current(exe: &Path) -> bool {
    let Ok(Some(installed)) = manage::installed_binary() else {
        return false;
    };
    match (std::fs::read(&installed), std::fs::read(exe)) {
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
}
