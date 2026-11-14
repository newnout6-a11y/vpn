//! Who may talk over the command pipe, in both directions.
//!
//! The primary's pipe admits SYSTEM, administrators and the signed-in user at medium integrity:
//! Windows starts a clicked link's launch unelevated, and it must still reach a primary the user
//! started as administrator (TUN). Such a client may not make an elevated primary quit.
//! A later launch hands a link (a key, a subscription token) only to a server it verified: in its
//! own session and running this very exe. Pipe names share one global namespace, so another
//! signed-in user could create ours first and read whatever is written to it.
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{E_FAIL, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, PSECURITY_DESCRIPTOR,
    RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_USER, TokenIntegrityLevel, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, ImpersonateNamedPipeClient,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::{HSTRING, Owned, PWSTR};

use crate::win;

/// What a client asks for and what the user's ACE grants: read, write, message mode (attributes).
/// Never FILE_APPEND_DATA, which on a pipe means "create another instance of it".
pub(super) const CLIENT_ACCESS: u32 =
    FILE_GENERIC_READ.0 | FILE_WRITE_DATA.0 | FILE_WRITE_ATTRIBUTES.0;

/// The primary pipe's security descriptor (owner = the user, medium label), freed on drop.
pub(super) struct PipeSecurity(PSECURITY_DESCRIPTOR);

impl PipeSecurity {
    pub(super) fn new() -> windows::core::Result<Self> {
        let user = user_sid()?;
        // NW = no write up: a low-integrity process (a browser sandbox) still cannot write.
        let sddl = HSTRING::from(format!(
            "O:{user}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{CLIENT_ACCESS:x};;;{user})S:(ML;;NW;;;ME)"
        ));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: a valid SDDL string and out pointer; the descriptor is freed on drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl,
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }?;
        Ok(Self(sd))
    }

    /// Attributes for `CreateNamedPipeW`; valid while `self` lives.
    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW, freed once.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// The token information `class` of `token`, in an 8-aligned buffer.
fn token_info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> windows::core::Result<Vec<u64>> {
    let mut len = 0;
    // SAFETY: a size query without a buffer; it fails with ERROR_INSUFFICIENT_BUFFER by design.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes and is aligned for the structs that start it.
    unsafe { GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }?;
    Ok(buf)
}

/// This process's user as an SDDL SID string (`S-1-5-21-…`).
pub(super) fn user_sid() -> windows::core::Result<String> {
    let token = win::process_token()?;
    let buf = token_info(*token, TokenUser)?;
    // SAFETY: GetTokenInformation(TokenUser) filled `buf` starting with a TOKEN_USER whose SID
    // lives in `buf`.
    let sid = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() }.User.Sid;
    let mut text = PWSTR::null();
    // SAFETY: a valid SID; the string it returns is freed right below.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
    // SAFETY: a NUL-terminated string from ConvertSidToStringSidW, freed once afterwards.
    let sid = unsafe { text.to_string() };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    sid.map_err(|_| E_FAIL.into())
}

/// Integrity RID of `token` (0x2000 medium, 0x3000 high).
fn integrity(token: HANDLE) -> Option<u32> {
    let buf = token_info(token, TokenIntegrityLevel).ok()?;
    // SAFETY: filled with a TOKEN_MANDATORY_LABEL whose SID lives in `buf`.
    let sid = unsafe { &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() }
        .Label
        .Sid;
    // SAFETY: a valid SID: its count and its last sub-authority are readable.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        count
            .checked_sub(1)
            .map(|last| *GetSidSubAuthority(sid, u32::from(last)))
    }
}

/// Integrity of this process.
pub(super) fn own_integrity() -> Option<u32> {
    integrity(*win::process_token().ok()?)
}

/// Integrity of the client connected to `pipe` (identification-level impersonation).
pub(super) fn client_integrity(pipe: HANDLE) -> Option<u32> {
    // SAFETY: the client has written its message, so it can be impersonated; reverted below.
    unsafe { ImpersonateNamedPipeClient(pipe) }.ok()?;
    let mut token = HANDLE::default();
    // SAFETY: opened as self: an identification-level token cannot open itself.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    // SAFETY: ends the impersonation above whatever happened since.
    let _ = unsafe { RevertToSelf() };
    opened.ok()?;
    // SAFETY: a fresh handle that nothing else owns.
    let token = unsafe { Owned::new(token) };
    integrity(*token)
}

/// The process a later launch expects behind the pipe: its own session and its own exe.
#[derive(Debug, Clone)]
pub(super) struct Peer {
    pub(super) session: u32,
    pub(super) exe: PathBuf,
}

impl Peer {
    /// This process: the primary of the same install in the same session.
    pub(super) fn this_process() -> windows::core::Result<Self> {
        Ok(Self {
            session: super::current_session()?,
            exe: std::env::current_exe().map_err(|_| windows::core::Error::from(E_FAIL))?,
        })
    }
}

/// `true` when the server of the connected client handle `pipe` runs in `peer`'s session from
/// `peer`'s exe. Anything unreadable counts as a stranger.
pub(super) fn server_is(pipe: HANDLE, peer: &Peer) -> bool {
    let (mut session, mut pid) = (0, 0);
    // SAFETY: live client pipe handle; valid out pointers.
    let known = unsafe {
        GetNamedPipeServerSessionId(pipe, &mut session).is_ok()
            && GetNamedPipeServerProcessId(pipe, &mut pid).is_ok()
    };
    known
        && session == peer.session
        && crate::process::image_path(pid).is_ok_and(|image| same_file(&image, &peer.exe))
}

/// Both paths name one file (canonical forms compared as Windows compares names: `c:\users\…`
/// from a shortcut is the same exe as `C:\Users\…` from the registry).
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => win::eq_ignore_case(&win::wide_os(a), &win::wide_os(b)),
        _ => false,
    }
}
