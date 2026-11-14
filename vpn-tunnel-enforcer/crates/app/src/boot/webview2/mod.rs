//! The WebView2 runtime at start (p-webview-runtime): the window needs it, and a clean Windows 10 or Windows
//! Sandbox has none. When it is missing, the app offers Microsoft's Evergreen bootstrapper shipped next to it
//! (`resources\`, pinned in `resources/engines.toml`; setup runs the same file). Started from this unelevated
//! process with CreateProcess, it installs the runtime for this user only: no administrator rights, no prompt
//! (an elevation request would fail instead of prompting). The window opens right after a successful install.
mod progress;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;

/// Exit code of a start that ended because the runtime is missing (the UI's own check uses the same).
pub const EXIT_NO_RUNTIME: u8 = 3;
/// The bootstrapper's file name in the resources folder (its install path in the manifest).
pub const BOOTSTRAPPER: &str = "MicrosoftEdgeWebview2Setup.exe";
/// Microsoft's command line; `/silent` must come first (the reverse fails, WebView2Feedback #555).
const ARGS: [&str; 2] = ["/silent", "/install"];
/// The bootstrapper can exit 0 before the runtime is registered (WebView2Feedback #1349, still open):
/// Microsoft's advice is to wait for the registration.
const SETTLE: Duration = Duration::from_secs(120);
/// Bounds a bootstrapper that never returns; a slow download is the user's to cancel.
const RUN_LIMIT: Duration = Duration::from_secs(15 * 60);
const POLL: Duration = Duration::from_millis(250);

/// How an offered install ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The runtime is there now.
    Ready,
    /// The user closed the progress window (the bootstrapper finishes on its own).
    Cancelled,
    /// Exit 0, or no exit in time, and the runtime is not registered yet.
    Pending,
    /// A WinHTTP / WinINet error: the download did not get through.
    Offline,
    /// Any other exit code, or the start error as an HRESULT.
    Failed(u32),
}

/// The outcome of a finished run whose runtime is still missing, from its exit code. Microsoft documents only
/// 0 = success; network failures come as HRESULT_FROM_WIN32 of a WinINet / WinHTTP error (12000..=12999).
pub(crate) fn classify(code: u32) -> Outcome {
    match code {
        0 => Outcome::Pending,
        c if c & 0xFFFF_0000 == 0x8007_0000 && (12_000..=12_999).contains(&(c & 0xFFFF)) => {
            Outcome::Offline
        }
        c => Outcome::Failed(c),
    }
}

/// What the check needs from Windows (a fake in tests).
pub(crate) trait Host {
    /// `true` when a WebView2 runtime is installed.
    fn runtime(&self) -> bool;
    /// The bootstrapper next to the app, when it is there.
    fn bootstrapper(&self) -> Option<PathBuf>;
    /// A Yes / No box; `true` = Yes.
    fn ask(&self, lines: &[Msg]) -> bool;
    /// Runs the bootstrapper under a progress window until the runtime is there or the run ended.
    fn install(&self, exe: &Path) -> Outcome;
    /// An OK box.
    fn tell(&self, lines: &[Msg]);
}

/// `true` when the window can open: the runtime is there, or the user just let the app install it. Otherwise
/// the user was told what to do and the start ends with [`EXIT_NO_RUNTIME`].
pub fn ensure(lang: Lang) -> bool {
    ensure_with(&Windows { lang })
}

pub(crate) fn ensure_with(host: &impl Host) -> bool {
    if host.runtime() {
        return true;
    }
    // A development build without `cargo xtask engines`: Microsoft's page is the way.
    let Some(exe) = host.bootstrapper() else {
        host.tell(&[Msg::new("ui.frame.webview2Missing")]);
        return false;
    };
    let offer = [
        Msg::new("app.main.webview2.missing"),
        Msg::new("app.main.webview2.offer"),
    ];
    if !host.ask(&offer) {
        return false;
    }
    let line = match host.install(&exe) {
        Outcome::Ready => return true,
        Outcome::Cancelled => return false,
        Outcome::Pending => Msg::new("app.main.webview2.pending"),
        Outcome::Offline => Msg::new("app.main.webview2.offline"),
        Outcome::Failed(code) => {
            Msg::new("app.main.webview2.failed").arg("code", format!("0x{code:08X}"))
        }
    };
    host.tell(&[line]);
    false
}

/// The bootstrapper in the resources folder `resources`, when it is there.
fn bootstrapper_in(resources: &Path) -> Option<PathBuf> {
    Some(resources.join(BOOTSTRAPPER)).filter(|exe| exe.is_file())
}

/// HRESULT_FROM_WIN32 of a start error (E_FAIL when Windows gave no code).
fn hresult(err: &std::io::Error) -> u32 {
    err.raw_os_error()
        .map_or(0x8000_4005, |code| 0x8007_0000 | (code as u32 & 0xFFFF))
}

/// The real host: wry's runtime check (the one the window itself makes), the app's resources folder,
/// message boxes in `lang`.
struct Windows {
    lang: Lang,
}

impl Host for Windows {
    fn runtime(&self) -> bool {
        dioxus::desktop::wry::webview_version().is_ok()
    }

    fn bootstrapper(&self) -> Option<PathBuf> {
        bootstrapper_in(&vpnte_core::paths::DataDirs::resolve().ok()?.resources)
    }

    fn ask(&self, lines: &[Msg]) -> bool {
        use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONINFORMATION, MB_YESNO};
        super::message_box(lines, self.lang, MB_YESNO | MB_ICONINFORMATION) == IDYES
    }

    fn install(&self, exe: &Path) -> Outcome {
        let line = Msg::new("app.main.webview2.installing").render(self.lang);
        let progress = progress::Progress::show(vpnte_ui::launch::APP_NAME, &line);
        let mut child = match Command::new(exe).args(ARGS).spawn() {
            Ok(child) => child,
            Err(err) => return Outcome::Failed(hresult(&err)),
        };
        let started = Instant::now();
        let code = loop {
            if progress.cancelled() {
                return Outcome::Cancelled;
            }
            match child.try_wait() {
                // The exit code is an HRESULT: keep its bits.
                Ok(Some(status)) => break status.code().map_or(0x8000_4005, |c| c as u32),
                Ok(None) if started.elapsed() > RUN_LIMIT => return Outcome::Pending,
                Ok(None) => std::thread::sleep(POLL),
                Err(err) => return Outcome::Failed(hresult(&err)),
            }
        };
        if code == 0 {
            let settled = Instant::now() + SETTLE;
            while !self.runtime() && Instant::now() < settled {
                if progress.cancelled() {
                    return Outcome::Cancelled;
                }
                std::thread::sleep(POLL);
            }
        }
        if self.runtime() {
            Outcome::Ready
        } else {
            classify(code)
        }
    }

    fn tell(&self, lines: &[Msg]) {
        use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
        super::message_box(lines, self.lang, MB_ICONINFORMATION);
    }
}

#[cfg(test)]
mod tests;
