//! What the per-user side runs against the service: the product's one elevated step, asked of
//! Windows (`install` through `ShellExecuteEx("runas")`: Windows shows its own prompt; the
//! installer and the app never elevate themselves), the same for `uninstall` when Settings >
//! Apps removes the service (it starts the entry's command unelevated), and the per-user
//! uninstaller's leave (`ForgetMe` over the pipe, no prompt).
use std::path::Path;
use std::time::Duration;

use vpnte_base::i18n::Lang;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED};
use windows::Win32::System::Console::FreeConsole;
use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::{
    MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MessageBoxW, SW_HIDE,
};
use windows::core::{HSTRING, PCWSTR, w};

use crate::install::entry;
use crate::install::flow::{EXIT_FILES_LEFT, EXIT_FILTERS_KEPT, FILES_LEFT};
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

/// The `uninstall` verb as Windows runs it after its prompt: it never asks again (were the run
/// still unelevated, it refuses instead of asking in a loop).
pub const APPROVED: &str = "--approved";

/// Runs `exe uninstall --approved` elevated and waits for it: one prompt from Windows (the
/// command of the service's entry in Settings > Apps, or `uninstall` run unelevated). Blocking.
pub fn request_uninstall(exe: &Path) -> std::io::Result<Elevated> {
    run_elevated(exe, &format!("uninstall {APPROVED}"))
}

/// Lets go of the console Windows opened for this exe: Settings starts the entry's command like
/// a program, and a console exe gets a window of its own, which then closes at once instead of
/// staying empty through the prompt and the removal (tailsa-b1).
pub fn leave_console() {
    // SAFETY: no arguments; a process without a console only gets an error back.
    let _ = unsafe { FreeConsole() };
}

/// One calm message to the user (`warning`: something did not work).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub text: String,
    pub warning: bool,
}

/// What the user who removed the service in Settings > Apps is told, in `lang`: nothing when it
/// is gone or nobody approved the prompt; one line when it stays to remove its network filters
/// later, when files another program holds stay in `folder`, or when the removal failed.
pub fn uninstall_message(
    asked: &std::io::Result<Elevated>,
    folder: &Path,
    lang: Lang,
) -> Option<Message> {
    let code = match asked {
        Ok(Elevated::Declined | Elevated::Exited(0)) => return None,
        Ok(Elevated::Exited(code)) => u8::try_from(*code).ok(),
        Err(_) => None,
    };
    let (key, warning) = match code {
        Some(EXIT_FILTERS_KEPT) => ("service.uninstall.notYet", false),
        Some(EXIT_FILES_LEFT) => (FILES_LEFT, false),
        _ => ("service.uninstall.failed", true),
    };
    let folder = folder.display().to_string();
    let text = entry::text(key, lang).replace("{{folder}}", &folder);
    Some(Message { text, warning })
}

/// Shows `message` in a message box titled with the service's name in `lang`.
pub fn tell(message: &Message, lang: Lang) {
    let title = HSTRING::from(entry::text(entry::DISPLAY_NAME, lang));
    let text = HSTRING::from(message.text.as_str());
    let icon = if message.warning {
        MB_ICONWARNING
    } else {
        MB_ICONINFORMATION
    };
    // SAFETY: two valid strings that outlive the call; no owner window.
    unsafe { MessageBoxW(None, &text, &title, MB_OK | MB_SETFOREGROUND | icon) };
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

    /// tailsa-b1: Settings > Apps' removal says how it went in one calm line in the user's
    /// language: nothing when the service is gone or nobody approved; the kept filters, the
    /// files left in the named folder, or a failure otherwise (also when the prompt itself could
    /// not be shown).
    #[test]
    fn the_removal_says_how_it_went() {
        let folder = Path::new(r"C:\Program Files\VPN Tunnel Enforcer Service");
        let said = |asked: std::io::Result<Elevated>, lang| uninstall_message(&asked, folder, lang);
        assert_eq!(said(Ok(Elevated::Exited(0)), Lang::Ru), None);
        assert_eq!(said(Ok(Elevated::Declined), Lang::Ru), None);
        let kept = said(Ok(Elevated::Exited(3)), Lang::En).expect("kept");
        assert!(
            !kept.warning && kept.text.contains("network filters"),
            "{kept:?}"
        );
        let left = said(Ok(Elevated::Exited(6)), Lang::Ru).expect("left");
        assert!(!left.warning && left.text.contains(&folder.display().to_string()));
        assert!(!left.text.contains("{{"), "{left:?}");
        for asked in [
            Ok(Elevated::Exited(1)),
            Err(std::io::Error::other("no shell")),
        ] {
            let failed = said(asked, Lang::Ru).expect("failed");
            assert!(failed.warning && failed.text.starts_with("Службу-помощник"));
        }
        assert_eq!(
            entry::text(entry::DISPLAY_NAME, Lang::En),
            "VPN Tunnel Enforcer — helper service"
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
