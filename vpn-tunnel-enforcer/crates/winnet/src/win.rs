//! Win32 plumbing shared by the modules: UTF-16 strings, COM apartments, the process token and
//! the error kind of an OS error.
use std::ffi::OsStr;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;

use vpnte_base::ErrorKind;
use windows::Win32::Foundation::{E_ACCESSDENIED, HANDLE};
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{Owned, PCWSTR};

/// NUL-terminated UTF-16 of `s` for a `PCWSTR` parameter.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// NUL-terminated UTF-16 of an OS string (a path keeps unpaired surrogates).
pub(crate) fn wide_os(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// A UTF-16 buffer up to its first NUL (or its end).
pub(crate) fn until_nul(buf: &[u16]) -> &[u16] {
    &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]
}

/// The text of a UTF-16 buffer up to its first NUL (or its end), decoded lossily.
pub(crate) fn from_wide(buf: &[u16]) -> String {
    String::from_utf16_lossy(until_nul(buf))
}

/// The text at a NUL-terminated UTF-16 pointer, decoded lossily; null reads as empty.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string that stays valid during the call.
pub(crate) unsafe fn read_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller: the string is NUL-terminated and alive.
    let units = unsafe { std::slice::from_raw_parts(p, PCWSTR(p).len()) };
    String::from_utf16_lossy(units)
}

/// Ordinal, case-insensitive equality of two UTF-16 strings (`CompareStringOrdinal`): how Windows
/// compares file names.
pub(crate) fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    // SAFETY: both slices are valid for their whole length.
    let order = unsafe { CompareStringOrdinal(a, b, true) };
    order == CSTR_EQUAL
}

/// `Permission` for an access-denied error, `Internal` for any other.
pub(crate) fn error_kind(e: &windows::core::Error) -> ErrorKind {
    if e.code() == E_ACCESSDENIED {
        ErrorKind::Permission
    } else {
        ErrorKind::Internal
    }
}

/// The COM apartment a [`Com`] scope joins.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Apartment {
    /// Single-threaded: shell objects (shortcuts, the handlers `ShellExecuteExW` may load).
    Sta,
    /// Multi-threaded: in-proc automation objects (Task Scheduler, firewall policy).
    Mta,
}

/// COM on the current thread while alive. A thread that is already in the other apartment (a UI
/// thread in STA) keeps it and can still use in-proc objects: then nothing is initialised and
/// nothing is undone.
pub(crate) struct Com {
    uninit: bool,
    /// `CoUninitialize` must run on the thread that initialised.
    _thread: PhantomData<*const ()>,
}

impl Com {
    /// Joins `apartment` on this thread for the lifetime of the guard.
    pub(crate) fn enter(apartment: Apartment) -> Self {
        let flags = match apartment {
            Apartment::Sta => COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
            Apartment::Mta => COINIT_MULTITHREADED,
        };
        // SAFETY: per-thread initialisation, balanced in `drop` whenever it succeeded (S_FALSE
        // included); RPC_E_CHANGED_MODE leaves the thread's apartment untouched.
        let hr = unsafe { CoInitializeEx(None, flags) };
        Self {
            uninit: hr.is_ok(),
            _thread: PhantomData,
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances the successful CoInitializeEx of `enter` on this same thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// This process's token, opened for queries.
pub(crate) fn process_token() -> windows::core::Result<Owned<HANDLE>> {
    let mut token = HANDLE::default();
    // SAFETY: the current-process pseudo-handle needs no closing; `token` is an out-pointer.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    // SAFETY: the call succeeded, so `token` is a handle we own.
    Ok(unsafe { Owned::new(token) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_round_trips() {
        assert_eq!(wide("aб"), [0x61, 0x431, 0]);
        assert_eq!(wide_os(r"C:\x"), [0x43, 0x3a, 0x5c, 0x78, 0]);
        assert_eq!(from_wide(&[0x61, 0x431, 0, 0x62]), "aб");
        assert_eq!(from_wide(&[0x61, 0x62]), "ab");
        assert_eq!(from_wide(&[0xd800, 0x61]), "\u{fffd}a");
        let text = wide("Wi-Fi");
        // SAFETY: a NUL-terminated buffer and a null pointer.
        assert_eq!(unsafe { read_wide(text.as_ptr()) }, "Wi-Fi");
        assert_eq!(unsafe { read_wide(std::ptr::null()) }, "");
    }

    #[test]
    fn access_denied_is_a_permission_error() {
        assert_eq!(error_kind(&E_ACCESSDENIED.into()), ErrorKind::Permission);
        let other = windows::Win32::Foundation::E_FAIL;
        assert_eq!(error_kind(&other.into()), ErrorKind::Internal);
    }

    #[test]
    fn com_scopes_nest_and_the_token_opens() {
        let outer = Com::enter(Apartment::Mta);
        // The thread is in the MTA now: an STA request fails and must not uninitialise it.
        let inner = Com::enter(Apartment::Sta);
        assert!(outer.uninit && !inner.uninit);
        drop(inner);
        drop(outer);
        assert!(process_token().is_ok());
    }
}
