//! Who is on the other end of a pipe connection.
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// The connected client as Windows reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    pub pid: u32,
    /// Windows session (0 = services; CI runners connect from there).
    pub session: u32,
    /// The client token's user SID (`S-1-5-21-…`): the identity of the users list.
    pub user: String,
    /// The client's image, for the log only: the app lives in a user-writable folder, so it is
    /// no trust anchor.
    pub image: Option<PathBuf>,
}

fn raw(pipe: &impl AsRawHandle) -> HANDLE {
    HANDLE(pipe.as_raw_handle())
}

/// Identifies the client of a server pipe end. Needs one frame read first: Windows refuses to
/// impersonate a client that has not written yet.
pub fn client(pipe: &impl AsRawHandle) -> windows::core::Result<ClientInfo> {
    let handle = raw(pipe);
    let (mut pid, mut session) = (0u32, 0u32);
    // SAFETY: `handle` is a connected server end; out pointers are locals.
    unsafe {
        GetNamedPipeClientProcessId(handle, &mut pid)?;
        GetNamedPipeClientSessionId(handle, &mut session)?;
    }
    let user = client_user(handle)?;
    Ok(ClientInfo {
        pid,
        session,
        user,
        image: vpnte_winnet::process::image_path(pid).ok(),
    })
}

/// The client's user SID: impersonate (identification level is enough to read the token),
/// read it, revert at once.
fn client_user(handle: HANDLE) -> windows::core::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: impersonation is reverted before this function returns, on every path.
    let opened = unsafe {
        ImpersonateNamedPipeClient(handle)?;
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token);
        if RevertToSelf().is_err() {
            // Microsoft's guidance: a thread that cannot drop the client's identity must not
            // run on; the SCM's recovery actions restart the service.
            std::process::abort();
        }
        opened
    };
    opened?;
    let user = token_user(token);
    // SAFETY: `token` was opened above and is closed once.
    unsafe {
        let _ = CloseHandle(token);
    }
    user
}

fn token_user(token: HANDLE) -> windows::core::Result<String> {
    let mut len = 0u32;
    // SAFETY: size query; the call fails with ERROR_INSUFFICIENT_BUFFER and sets `len`.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
    // u64 storage keeps TOKEN_USER (pointer-aligned) correctly aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds `len` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )?;
    }
    // SAFETY: the buffer now starts with a TOKEN_USER whose SID points into the buffer.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    crate::sddl::sid_string(sid).ok_or_else(windows::core::Error::from_thread)
}

/// The process id of the server end of a client pipe.
pub fn server_pid(pipe: &impl AsRawHandle) -> windows::core::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a connected client end; out pointer is a local.
    unsafe { GetNamedPipeServerProcessId(raw(pipe), &mut pid)? };
    Ok(pid)
}
