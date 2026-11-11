//! Discovery files of the control API: the bearer token and the endpoint JSON, both in the data
//! root (`%APPDATA%\VPN Tunnel Enforcer\`), where the CLI and automation clients look first.
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vpnte_base::types::{UnixMs, now_ms};

use crate::slot::{CONTROL_HOST, loopback_url};

/// Token file name: 64 lowercase hex characters and a newline.
pub const TOKEN_FILE: &str = "external-proxy-control-token";
/// Endpoint file name: [`Endpoint`] as pretty JSON.
pub const ENDPOINT_FILE: &str = "external-proxy-control-endpoint.json";

/// Bearer secret of the control API: 32 random bytes as hex, new on every app start.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlToken(String);

impl ControlToken {
    /// Draws a fresh token from the OS RNG.
    pub fn generate() -> io::Result<Self> {
        crate::token::generate().map(Self).map_err(rng_error)
    }

    /// A token with known text (tests only).
    #[cfg(test)]
    pub(crate) fn fixed(text: &str) -> Self {
        Self(text.into())
    }

    /// The token text (what clients send).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison with a token a client sent; an empty one never matches.
    pub fn matches(&self, provided: &str) -> bool {
        crate::token::matches(&self.0, provided)
    }
}

impl std::fmt::Debug for ControlToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlToken(..)")
    }
}

/// Contents of the endpoint file (field names are the old wire contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub host: String,
    /// The port actually bound (an ephemeral one after a fallback).
    pub port: u16,
    pub url: String,
    /// The token file in the same directory.
    pub token_file: PathBuf,
    pub updated_at: UnixMs,
}

impl Endpoint {
    /// The endpoint of a listener bound to `port`, with the token file in `dir`.
    pub fn new(dir: &Path, port: u16) -> Self {
        Self {
            host: CONTROL_HOST.into(),
            port,
            url: loopback_url(port),
            token_file: dir.join(TOKEN_FILE),
            updated_at: now_ms(),
        }
    }
}

/// Writes the token file into `dir`; returns its path.
pub fn write_token(dir: &Path, token: &ControlToken) -> io::Result<PathBuf> {
    let path = dir.join(TOKEN_FILE);
    write_private(&path, format!("{}\n", token.as_str()).as_bytes())?;
    Ok(path)
}

/// Writes the endpoint file into `dir`; returns its path.
pub fn write_endpoint(dir: &Path, endpoint: &Endpoint) -> io::Result<PathBuf> {
    let path = dir.join(ENDPOINT_FILE);
    let mut json = serde_json::to_string_pretty(endpoint).map_err(io::Error::other)?;
    json.push('\n');
    write_private(&path, json.as_bytes())?;
    Ok(path)
}

/// The token in a token file (trimmed), if the file exists and is not blank.
pub fn read_token(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let token = text.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Replaces `path` atomically with a file only the current user can open. The file is created
/// under a temporary name with a protected DACL already set (no window with inherited rights),
/// then renamed over the old one (a rename keeps the file's own DACL).
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut suffix = [0u8; 6];
    getrandom::fill(&mut suffix).map_err(rng_error)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temp = dir.join(format!(".{name}.{}.tmp", hex::encode(suffix)));
    let written = dacl::create_private(&temp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    let result = written.and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// `getrandom::Error` is not a `std` error without its `std` feature.
fn rng_error(e: getrandom::Error) -> io::Error {
    io::Error::other(format!("OS random source failed: {e}"))
}

/// Win32 side of [`write_private`].
mod dacl {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use std::path::Path;

    use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, Owned, PCWSTR, PWSTR};

    /// Creates a new file whose protected DACL grants full control to the current user only
    /// (ТЗ vol. 01 §6.1 item 1). The app and the CLI run as the same user, so they share that SID.
    pub(super) fn create_private(path: &Path) -> io::Result<File> {
        let sid = current_user_sid().map_err(io::Error::other)?;
        let sddl = HSTRING::from(format!("D:P(A;;FA;;;{sid})"));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is a NUL-terminated wide string; on success `sd` receives a
        // LocalAlloc'ed descriptor that is freed below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(io::Error::other)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let wide = HSTRING::from(path.as_os_str());
        // SAFETY: `wide` is NUL-terminated; `sa` and its descriptor outlive the call.
        let created = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                Some(&sa),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW and is no
        // longer used (the new file has its own copy).
        unsafe { LocalFree(Some(HLOCAL(sd.0))) };
        let handle = created.map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))?;
        // SAFETY: `handle` is a valid file handle that the `File` owns and closes from here on.
        Ok(unsafe { File::from_raw_handle(handle.0 as RawHandle) })
    }

    /// String SID (`S-1-5-21-…`) of this process's token user.
    fn current_user_sid() -> windows::core::Result<String> {
        let mut raw = HANDLE::default();
        // SAFETY: the pseudo handle of this process is always valid; `raw` receives a token
        // handle that `Owned` closes.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }?;
        // SAFETY: `raw` is a token handle we own from here on.
        let token = unsafe { Owned::new(raw) };
        let mut len = 0u32;
        // SAFETY: a size query without a buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER.
        let _ = unsafe { GetTokenInformation(*token, TokenUser, None, 0, &mut len) };
        // `usize` elements keep the SID pointer inside TOKEN_USER aligned.
        let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>()).max(1)];
        let size = (buf.len() * size_of::<usize>()) as u32;
        // SAFETY: `buf` has `size` writable, pointer-aligned bytes.
        unsafe {
            GetTokenInformation(
                *token,
                TokenUser,
                Some(buf.as_mut_ptr().cast()),
                size,
                &mut len,
            )
        }?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into `buf`.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text = PWSTR::null();
        // SAFETY: `sid` is valid while `buf` lives; `text` is LocalAlloc'ed and freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
        // SAFETY: `text` is a NUL-terminated wide string from ConvertSidToStringSidW.
        let out = unsafe { text.to_string() };
        // SAFETY: `text` is no longer used.
        unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
        out.map_err(|_| windows::Win32::Foundation::E_FAIL.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-22: a written file carries a protected DACL with exactly one entry (the current user),
    /// replaces the previous file and leaves no temporary file behind.
    #[test]
    fn private_files_have_a_protected_single_entry_dacl() {
        let dir = std::env::temp_dir().join(format!("vpnte-control-dacl-{}", std::process::id()));
        let path = dir.join(TOKEN_FILE);
        write_private(&path, b"one\n").unwrap();
        write_private(&path, b"two\n").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let entries = std::fs::read_dir(&dir).unwrap().count();
        let (protected, aces) = dacl_of(&path);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!((content.as_str(), entries), ("two\n", 1));
        assert!(protected, "inherited rights must not apply");
        assert_eq!(aces, 1, "only the current user");
    }

    /// (DACL protected?, number of entries) of a file.
    fn dacl_of(path: &Path) -> (bool, u16) {
        use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        };
        use windows::core::{HSTRING, PCWSTR};

        let wide = HSTRING::from(path.as_os_str());
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; on success `sd` is a LocalAlloc'ed descriptor that
        // `dacl` points into, freed below after the last use.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&raw mut dacl),
                None,
                &mut sd,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: `sd` is the valid descriptor returned above.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) }.unwrap();
        assert!(!dacl.is_null(), "a NULL DACL would grant everyone access");
        // SAFETY: `dacl` points into `sd`, which is still alive.
        let aces = unsafe { (*dacl).AceCount };
        // SAFETY: `sd` is not used after this.
        unsafe { LocalFree(Some(HLOCAL(sd.0))) };
        (control & SE_DACL_PROTECTED.0 != 0, aces)
    }
}
