//! Process image paths by PID, and ordinal case-insensitive path comparison (how Windows
//! compares file names).
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{Owned, PWSTR};

use crate::win::eq_ignore_case;

/// Exit code reported by `GetExitCodeProcess` while a process still runs.
pub(super) const STILL_ACTIVE: u32 = 259;

/// Why an image path could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// No such process: it exited since it was listed (also PID 0, the idle pseudo-process).
    #[error("process is gone")]
    Gone,
    /// The OS refused access (protected or more privileged process).
    #[error("access to the process denied")]
    Denied,
    /// Any other failure.
    #[error(transparent)]
    Os(#[from] windows::core::Error),
}

/// Full Win32 image path of a running process (`QueryFullProcessImageNameW`).
pub fn image_path(pid: u32) -> Result<PathBuf, ImageError> {
    let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    query_image(*process).map_err(classify)
}

/// Opens a process; the handle closes on drop.
pub(super) fn open(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> Result<Owned<HANDLE>, ImageError> {
    if pid == 0 {
        return Err(ImageError::Gone);
    }
    // SAFETY: plain call without pointers.
    let handle = unsafe { OpenProcess(rights, false, pid) }.map_err(classify)?;
    // SAFETY: the handle was just returned to us and is closed only by `Owned`.
    Ok(unsafe { Owned::new(handle) })
}

/// Maps the errors that matter for ownership decisions; ERROR_INVALID_PARAMETER from
/// `OpenProcess` means the PID no longer exists.
fn classify(err: windows::core::Error) -> ImageError {
    match WIN32_ERROR::from_error(&err) {
        Some(ERROR_INVALID_PARAMETER) => ImageError::Gone,
        Some(ERROR_ACCESS_DENIED) => ImageError::Denied,
        _ => ImageError::Os(err),
    }
}

/// Image path of an open process (`PROCESS_QUERY_LIMITED_INFORMATION` suffices).
pub(super) fn query_image(process: HANDLE) -> windows::core::Result<PathBuf> {
    // Paths can exceed MAX_PATH (long-path aware installs): grow up to the 32K Win32 limit.
    let mut buf = vec![0u16; 1024];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` UTF-16 units; on success `len` is the length written (no NUL).
        let res = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        match res {
            Ok(()) => return Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize]))),
            Err(e)
                if WIN32_ERROR::from_error(&e) == Some(ERROR_INSUFFICIENT_BUFFER)
                    && buf.len() < 32_768 =>
            {
                buf.resize(buf.len() * 4, 0);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Exit code of an open process, `None` when unreadable ([`STILL_ACTIVE`] while running).
pub(super) fn exit_code(process: HANDLE) -> Option<u32> {
    let mut code = 0u32;
    // SAFETY: `code` is a valid out pointer for the duration of the call.
    unsafe { GetExitCodeProcess(process, &mut code) }
        .ok()
        .map(|()| code)
}

/// True when `path` lies below `dir`, which must end with a backslash: `C:\X\runtime-evil\a.exe`
/// is not below `C:\X\runtime\`.
pub(super) fn is_under(path: &[u16], dir: &[u16]) -> bool {
    path.len() > dir.len() && eq_ignore_case(&path[..dir.len()], dir)
}

#[cfg(test)]
mod tests {
    use std::os::windows::ffi::OsStrExt;

    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn own_image_path_is_the_running_exe() {
        let path = image_path(std::process::id()).unwrap();
        let exe = std::env::current_exe().unwrap();
        let (a, b): (Vec<u16>, Vec<u16>) = (
            path.as_os_str().encode_wide().collect(),
            exe.as_os_str().encode_wide().collect(),
        );
        assert!(eq_ignore_case(&a, &b), "{path:?} vs {exe:?}");
    }

    #[test]
    fn missing_processes_are_gone() {
        assert!(matches!(image_path(0), Err(ImageError::Gone)));
        // PIDs are multiples of four and never this large.
        assert!(matches!(image_path(u32::MAX - 3), Err(ImageError::Gone)));
    }

    /// AT-02-009 (ownedRuntimePidCore.test.ts): below the prefix, any case, subdirectories included.
    #[test]
    fn prefix_match_is_ordinal_ignore_case_and_needs_the_separator() {
        let dir = w(r"C:\VPNTE\runtime\");
        assert!(is_under(
            &w(r"c:\vpnte\RUNTIME\subdir\vpnte-sing-box.exe"),
            &dir
        ));
        assert!(is_under(&w(r"C:\VPNTE\runtime\vpnte-xray.exe"), &dir));
        assert!(!is_under(
            &w(r"C:\VPNTE\runtime-evil\vpnte-sing-box.exe"),
            &dir
        ));
        assert!(!is_under(&w(r"C:\Foreign\vpnte-sing-box.exe"), &dir));
        assert!(!is_under(&w(r"C:\VPNTE\runtime\"), &dir));
        // Non-ASCII user folders compare like the file system does.
        assert!(is_under(
            &w(r"c:\пользователи\владимир\engines\vpnte-xray.exe"),
            &w(r"C:\Пользователи\Владимир\engines\")
        ));
    }
}
