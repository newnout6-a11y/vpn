//! Hand a web link, a folder or a Windows settings page to the user's default handler.
use std::path::Path;

use vpnte_base::{AppError, AppResult, Msg};
use windows::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HSTRING, PCWSTR, w};

use crate::win::{self, Apartment, Com};

/// Opens an `http(s)` link in the default browser; any other scheme is refused.
pub async fn open_url(url: &str) -> AppResult<()> {
    check_url(url)?;
    shell_open(HSTRING::from(url)).await
}

/// Opens an existing folder (absolute path) in Explorer.
pub async fn open_folder(path: &Path) -> AppResult<()> {
    if !path.is_absolute() || !tokio::fs::metadata(path).await.is_ok_and(|m| m.is_dir()) {
        return Err(AppError::validation(Msg::new("winnet.shell.noFolder")));
    }
    shell_open(HSTRING::from(path.as_os_str())).await
}

/// Opens the Windows notification settings page (where the user unblocks our toasts).
pub async fn open_notification_settings() -> AppResult<()> {
    shell_open(HSTRING::from("ms-settings:notifications")).await
}

/// Only web links reach the shell: links can come from subscription providers (a profile web
/// page header), and `ms-settings:`, `file:`, `javascript:` or a custom protocol handler would
/// let them start local programs.
fn check_url(url: &str) -> AppResult<()> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    let has_host = rest.is_some_and(|r| !r.is_empty() && !r.starts_with(['/', '?', '#']));
    // A real URL has no raw spaces, quotes or control characters; such text is an attempt to
    // smuggle extra arguments to the handler's command line.
    let clean = !url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '"');
    if has_host && clean {
        Ok(())
    } else {
        Err(AppError::validation(Msg::new("winnet.shell.badUrl")))
    }
}

/// `ShellExecuteExW("open")` on the blocking pool: a slow handler must not stall async work.
async fn shell_open(target: HSTRING) -> AppResult<()> {
    tokio::task::spawn_blocking(move || open_blocking(&target))
        .await
        .map_err(AppError::internal)?
}

fn open_blocking(target: &HSTRING) -> AppResult<()> {
    // The shell may hand the target to shell extensions, which expect COM (STA) on this thread.
    let _com = Com::enter(Apartment::Sta);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        // NO_UI: report a failure to the caller instead of a shell error dialog.
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("open"),
        lpFile: PCWSTR(target.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised; `target` outlives the call.
    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| {
        AppError::msg(win::error_kind(&e), Msg::new("winnet.shell.openFailed")).with_source(e)
    })
}

#[cfg(test)]
mod tests {
    use vpnte_base::ErrorKind;

    use super::*;

    /// Navigation policy: only http(s) links are handed to the OS browser.
    #[test]
    fn only_web_links_pass() {
        for ok in [
            "https://example.com",
            "https://example.com/path?q=1#top",
            "HTTP://EXAMPLE.COM",
            "http://127.0.0.1:9090/ui",
        ] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "example.com",
            "ms-settings:notifications",
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "vpnte://import",
            "ftp://example.com",
            "https://",
            "http:///path",
            "https://exa mple.com",
            "https://example.com/\" --new-window",
            "https://example.com/\nmore",
        ] {
            let err = check_url(bad).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Validation, "{bad:?}");
            assert_eq!(err.user_msg().key, "winnet.shell.badUrl");
        }
    }

    /// Missing or relative folders are refused before anything is launched.
    #[tokio::test]
    async fn folder_must_exist_and_be_absolute() {
        let missing = std::env::temp_dir().join("vpnte-test-no-such-folder-7f3a");
        let err = open_folder(&missing).await.unwrap_err();
        assert_eq!(err.user_msg().key, "winnet.shell.noFolder");
        let err = open_folder(Path::new("relative\\dir")).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Validation);
        let file = std::env::current_exe().unwrap();
        let err = open_folder(&file).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Validation);
    }
}
