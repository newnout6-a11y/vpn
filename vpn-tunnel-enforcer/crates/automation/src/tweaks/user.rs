//! Who the per-user settings belong to (spec E3). With over-the-shoulder elevation (a standard
//! user types an administrator's password into UAC) the elevated process runs as that
//! administrator: its `HKCU` and profile are the admin's, so Soft mode would configure an account
//! nobody is using and report success. Soft mode and the dev targets refuse in that case.
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SESSION, WTS_INFO_CLASS, WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSUserName,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR, Result};

use super::journal::TweakError;

/// `Err(OtherUser)` when this process runs as another account than the user signed in to its
/// session. A failed lookup is logged and lets the caller go on: it says nothing about a mismatch.
pub fn ensure_session_user() -> std::result::Result<(), TweakError> {
    match (process_user(), session_user()) {
        (Ok((p_domain, p_name)), Ok((s_domain, s_name))) => {
            if p_name.eq_ignore_ascii_case(&s_name) && p_domain.eq_ignore_ascii_case(&s_domain) {
                Ok(())
            } else {
                tracing::warn!(
                    "process account differs from the session user; per-user tweaks refused"
                );
                Err(TweakError::OtherUser)
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(error = %e, "session user check failed; continuing");
            Ok(())
        }
    }
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `OpenProcessToken` and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// `(domain, name)` of this process's token user.
fn process_user() -> Result<(String, String)> {
    let mut handle = HANDLE::default();
    // SAFETY: the pseudo handle of the current process needs no closing; `handle` receives a
    // token handle owned by `Token` from here on.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) }?;
    let token = Token(handle);
    let mut len = 0u32;
    // SAFETY: a size query with no buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER by design.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    // `usize` elements keep the SID pointer inside TOKEN_USER aligned.
    let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>()).max(1)];
    let size = (buf.len() * size_of::<usize>()) as u32;
    // SAFETY: `buf` has `size` writable, pointer-aligned bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            size,
            &mut len,
        )
    }?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let (mut name_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: a size query; `sid` stays valid while `buf` lives.
    let _ = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers have the lengths passed with them.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }?;
    Ok((
        String::from_utf16_lossy(&domain[..domain_len as usize]),
        String::from_utf16_lossy(&name[..name_len as usize]),
    ))
}

/// `(domain, name)` of the user signed in to this process's session (empty in session 0).
fn session_user() -> Result<(String, String)> {
    Ok((session_string(WTSDomainName)?, session_string(WTSUserName)?))
}

fn session_string(class: WTS_INFO_CLASS) -> Result<String> {
    let mut buf = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: on success the API allocates a NUL-terminated string that we free below.
    unsafe { WTSQuerySessionInformationW(None, WTS_CURRENT_SESSION, class, &mut buf, &mut bytes) }?;
    // SAFETY: `buf` is the NUL-terminated string returned above.
    let text = unsafe { buf.to_string() }.unwrap_or_default();
    // SAFETY: frees the buffer allocated by WTSQuerySessionInformationW, once.
    unsafe { WTSFreeMemory(buf.0.cast()) };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run from a desktop session the tests are its user, so the check passes; under a service
    /// (session 0, no signed-in user) only the lookups are checked.
    #[test]
    fn this_process_runs_as_the_session_user() {
        let (_, name) = process_user().unwrap();
        assert!(!name.is_empty());
        let (_, session_name) = session_user().unwrap();
        if !session_name.is_empty() {
            assert!(ensure_session_user().is_ok());
        }
    }
}
