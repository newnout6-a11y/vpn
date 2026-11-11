//! Process elevation: the token check (once per process) and the UAC relaunch.
use std::ffi::{OsStr, c_void};
use std::iter::repeat_n;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::ERROR_CANCELLED;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

use crate::win::{self, Apartment, Com};

/// `true` when the process token is elevated; read once per process (a token never changes).
pub fn is_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(token_is_elevated)
}

fn token_is_elevated() -> bool {
    let Ok(token) = win::process_token() else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of exactly the size passed; the token has TOKEN_QUERY.
    let read = unsafe {
        GetTokenInformation(
            *token,
            TokenElevation,
            Some((&raw mut elevation).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    read.is_ok() && elevation.TokenIsElevated != 0
}

/// Starts an elevated copy of this exe with `args` through the UAC prompt (verb `runas`).
///
/// On `Ok` the caller exits at once, before taking the single-instance mutex and without any
/// cleanup: the old app ran its whole shutdown in the non-elevated parent and raced the child
/// for the instance lock. A refused prompt is `Permission` with `winnet.elevation.declined`.
pub fn relaunch_elevated<S: AsRef<OsStr>>(args: &[S]) -> AppResult<()> {
    let exe = std::env::current_exe()?;
    let file = win::wide_os(&exe);
    let params = command_line(args);
    // ShellExecuteEx documents COM (STA) as a precondition: it may delegate to shell extensions.
    let _com = Com::enter(Apartment::Sta);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        // The caller exits right after this call: the launch must be finished by then.
        fMask: SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised; its strings are NUL-terminated and outlive the call.
    unsafe { ShellExecuteExW(&mut info) }.map_err(relaunch_error)
}

fn relaunch_error(err: windows::core::Error) -> AppError {
    let (kind, key) = if err.code() == ERROR_CANCELLED.to_hresult() {
        (ErrorKind::Permission, "winnet.elevation.declined")
    } else {
        (ErrorKind::Internal, "winnet.elevation.relaunchFailed")
    };
    AppError::msg(kind, Msg::new(key)).with_source(err)
}

/// Joins `args` into one NUL-terminated command line (CommandLineToArgvW quoting rules).
fn command_line<S: AsRef<OsStr>>(args: &[S]) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            out.push(u16::from(b' '));
        }
        quote_into(&mut out, arg.as_ref());
    }
    out.push(0);
    out
}

fn quote_into(out: &mut Vec<u16>, arg: &OsStr) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let units: Vec<u16> = arg.encode_wide().collect();
    let plain = !units.is_empty()
        && !units
            .iter()
            .any(|&c| c == u16::from(b' ') || c == u16::from(b'\t') || c == QUOTE);
    if plain {
        out.extend_from_slice(&units);
        return;
    }
    out.push(QUOTE);
    let mut backslashes = 0;
    for &c in &units {
        match c {
            BACKSLASH => backslashes += 1,
            QUOTE => {
                out.extend(repeat_n(BACKSLASH, backslashes * 2 + 1));
                out.push(QUOTE);
                backslashes = 0;
            }
            _ => {
                out.extend(repeat_n(BACKSLASH, backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(repeat_n(BACKSLASH, backslashes * 2));
    out.push(QUOTE);
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HLOCAL, LocalFree};
    use windows::Win32::UI::Shell::CommandLineToArgvW;

    use super::*;

    fn line(args: &[&str]) -> String {
        let wide = command_line(args);
        String::from_utf16(&wide[..wide.len() - 1]).unwrap()
    }

    /// Splits a command line the way the relaunched process will (a dummy program name first,
    /// because CommandLineToArgvW parses argv[0] with different rules).
    fn parse(params: &[u16]) -> Vec<String> {
        let mut full: Vec<u16> = "app.exe ".encode_utf16().collect();
        full.extend_from_slice(params);
        let mut argc = 0;
        // SAFETY: `full` is NUL-terminated (`params` carries the terminator); the result is freed below.
        let argv = unsafe { CommandLineToArgvW(PCWSTR(full.as_ptr()), &mut argc) };
        assert!(!argv.is_null());
        // SAFETY: CommandLineToArgvW returned `argc` valid strings.
        let out = (1..argc as usize)
            .map(|i| unsafe { (*argv.add(i)).to_string() }.unwrap())
            .collect();
        // SAFETY: the array was allocated by CommandLineToArgvW with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(argv.cast()))) };
        out
    }

    /// Spike vectors: plain flags stay bare, spaces / quotes / trailing backslashes are quoted.
    #[test]
    fn quoting_follows_the_argv_rules() {
        assert_eq!(line(&["--x"]), "--x");
        assert_eq!(line(&["a b"]), "\"a b\"");
        assert_eq!(line(&[r#"say "hi""#]), r#""say \"hi\"""#);
        assert_eq!(line(&[r"C:\dir with space\"]), r#""C:\dir with space\\""#);
        assert_eq!(line(&[""]), "\"\"");
        assert_eq!(line(&["--autostart", "a b"]), "--autostart \"a b\"");
        assert_eq!(line(&[]), "");
    }

    #[test]
    fn relaunched_process_sees_the_same_args() {
        let args = [
            "--autostart",
            "",
            r"C:\Program Files\VPN Tunnel Enforcer\",
            r#"quote " inside"#,
            r"back\\slash\",
            r#"slashes\\" then quote"#,
            "tab\there",
            "кириллица",
        ];
        assert_eq!(parse(&command_line(&args)), args);
    }

    /// AT-00-004: a refused UAC prompt (ERROR_CANCELLED 1223) is a permission error with the
    /// decided text; any other launch failure is internal.
    #[test]
    fn uac_refusal_maps_to_permission() {
        let e = relaunch_error(ERROR_CANCELLED.to_hresult().into());
        assert_eq!(e.kind, ErrorKind::Permission);
        assert_eq!(e.user_msg().key, "winnet.elevation.declined");
        let e = relaunch_error(ERROR_ACCESS_DENIED.to_hresult().into());
        assert_eq!(e.kind, ErrorKind::Internal);
        assert_eq!(e.user_msg().key, "winnet.elevation.relaunchFailed");
    }

    /// AT-00-004: the elevation check is performed once per process and agrees with the token.
    #[test]
    fn elevation_is_read_once_and_matches_the_token() {
        let first = is_elevated();
        assert_eq!(first, token_is_elevated());
        assert_eq!(first, is_elevated());
    }
}
