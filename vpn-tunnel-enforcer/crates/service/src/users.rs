//! The Windows users that use the service (by SID), persisted in the service's private data
//! folder. The elevated `install` records the user whose session runs it, and a user of Tunnel
//! mode is recorded at his first `Hello` (he may use a service another user installed); his
//! per-user uninstaller removes him (`ForgetMe`), and the last one leaving removes the service.
//! Accounts Windows no longer knows do not count (review service-b5).
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use windows::Win32::Foundation::{ERROR_NONE_MAPPED, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{LookupAccountNameW, LookupAccountSidW, PSID, SID_NAME_USE};
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_INFO_CLASS, WTSDomainName, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSUserName,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

/// The users list (`users.json`: a JSON array of SID strings).
pub struct Users {
    path: PathBuf,
    list: Mutex<BTreeSet<String>>,
    /// Whether a SID still names an account.
    exists: fn(&str) -> bool,
}

impl Users {
    /// Loads `path` (missing or unreadable = nobody yet).
    pub fn open(path: &Path) -> Self {
        Self::with_lookup(path, account_exists)
    }

    fn with_lookup(path: &Path, exists: fn(&str) -> bool) -> Self {
        let list = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path: path.to_owned(),
            list: Mutex::new(list),
            exists,
        }
    }

    /// Records `sid` (no write when already known). Kept only once saved: after a failed save
    /// the next call tries again (review service-a8).
    pub fn add(&self, sid: &str) -> io::Result<()> {
        let mut list = self.list.lock();
        if list.contains(sid) {
            return Ok(());
        }
        let mut next = list.clone();
        next.insert(sid.to_owned());
        save(&self.path, &next)?;
        *list = next;
        Ok(())
    }

    /// Forgets `sid` and every account Windows no longer knows; `true` when `sid` was recorded
    /// and nobody is left. A failed save changes nothing, so a retry sees the same list.
    pub fn remove(&self, sid: &str) -> io::Result<bool> {
        let mut list = self.list.lock();
        let was_known = list.contains(sid);
        let next: BTreeSet<String> = list
            .iter()
            .filter(|s| s.as_str() != sid && (self.exists)(s))
            .cloned()
            .collect();
        save(&self.path, &next)?;
        *list = next;
        Ok(was_known && list.is_empty())
    }

    /// How many users are recorded.
    pub fn len(&self) -> usize {
        self.list.lock().len()
    }

    /// Nobody is recorded.
    pub fn is_empty(&self) -> bool {
        self.list.lock().is_empty()
    }
}

/// Atomic replace: write a sibling (on disk before the rename), then rename over the old file.
fn save(path: &Path, list: &BTreeSet<String>) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    io::Write::write_all(
        &mut file,
        &serde_json::to_vec(list).map_err(io::Error::other)?,
    )?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// `false` only when Windows says the SID names no account (deleted): a lookup that cannot run
/// (no domain controller in reach) keeps the user.
fn account_exists(sid: &str) -> bool {
    let mut psid = PSID::default();
    // SAFETY: valid string; the SID is LocalAlloc'd and freed below.
    if unsafe { ConvertStringSidToSidW(&HSTRING::from(sid), &mut psid) }.is_err() {
        return false;
    }
    let (mut name, mut domain, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size query with no buffers; it fails, and the error tells whether the SID maps.
    let lookup = unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            psid,
            None,
            &mut name,
            None,
            &mut domain,
            &mut kind,
        )
    };
    // SAFETY: allocated by ConvertStringSidToSidW, freed once.
    unsafe { LocalFree(Some(HLOCAL(psid.0))) };
    !matches!(lookup, Err(e) if e.code() == ERROR_NONE_MAPPED.to_hresult())
}

/// The user of the Windows session this process runs in (the person who started the install,
/// also when an administrator's credentials elevated it); `None` without one (session 0).
pub fn session_user() -> Option<String> {
    let user = session_text(WTSUserName)?;
    let domain = session_text(WTSDomainName)?;
    if user.is_empty() {
        return None;
    }
    let account = HSTRING::from(format!("{domain}\\{user}"));
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size query with no buffers.
    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            &account,
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8).max(1)];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    let psid = PSID(sid.as_mut_ptr().cast());
    // SAFETY: buffers of the sizes the query returned (`sid` is u64-aligned).
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            &account,
            Some(psid),
            &mut sid_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }
    .ok()?;
    crate::sddl::sid_string(psid)
}

fn session_text(class: WTS_INFO_CLASS) -> Option<String> {
    let (mut text, mut len) = (PWSTR::null(), 0u32);
    // SAFETY: out pointers are locals; the buffer is freed with WTSFreeMemory below.
    unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            WTS_CURRENT_SESSION,
            class,
            &mut text,
            &mut len,
        )
        .ok()?;
        let value = text.to_string().ok();
        WTSFreeMemory(text.0.cast());
        value
    }
}

#[cfg(test)]
mod tests;
