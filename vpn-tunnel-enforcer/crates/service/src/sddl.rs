//! Security descriptors of the service's objects and the trusted-folder check.
//!
//! Pipe: `ProtectedPrefix\Administrators\` lets only administrators and SYSTEM create a pipe of
//! that name (Windows 10 1709+), and the DACL gives interactive users read / write *without*
//! `FILE_CREATE_PIPE_INSTANCE` (`0x0012019b` = generic read + write minus `FILE_APPEND_DATA`):
//! `GRGW` would let any user open a second instance and pose as the service (pipe squatting).
use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows::core::{BOOL, HSTRING, PWSTR};

/// The service's pipe.
pub const PIPE_NAME: &str = r"\\.\pipe\ProtectedPrefix\Administrators\VpnTunnelEnforcer\Service";

/// Pipe DACL: SYSTEM and Administrators full, interactive users read / write only.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)";

/// Service object: Administrators manage it; interactive users may query it and start it (it is
/// automatic anyway) but never stop, pause, reconfigure or delete it.
pub const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)\
(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)";

/// The install folder and the data folder: owned by Administrators, SYSTEM and Administrators
/// full, Users read and execute, inheritance from the parent cut.
pub const ADMIN_ONLY_DIR_SDDL: &str =
    "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// SIDs that may write where the service runs code from: SYSTEM, Administrators and
/// TrustedInstaller.
const TRUSTED_WRITERS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Rights that change a file or a folder's content, names or security: write / append (add
/// file / subfolder), extended attributes, delete child, attributes, delete, DACL, owner,
/// generic write, generic all.
const WRITE_RIGHTS: u32 =
    0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;

/// A self-relative security descriptor made from SDDL (freed on drop).
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable heap block owned by this value.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above; nothing mutates it after creation.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Parses `sddl`.
    pub fn from_sddl(sddl: &str) -> windows::core::Result<Self> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid string and out pointer; the result is freed by Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
        }
        Ok(Self(sd))
    }

    /// The raw descriptor (valid while `self` lives).
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    /// `SECURITY_ATTRIBUTES` pointing at this descriptor (valid while `self` lives).
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: BOOL(0),
        }
    }

    /// Only SYSTEM, Administrators and TrustedInstaller own the object and may change it.
    pub fn admin_only_writes(&self) -> bool {
        let mut owner = PSID::default();
        let mut defaulted = BOOL(0);
        // SAFETY: `self.0` is a valid descriptor; out pointers are locals.
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) }.is_err() {
            return false;
        }
        let mut present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            .is_err()
        {
            return false;
        }
        // No owner, or no DACL at all (everyone has full access): not ours.
        if owner.is_invalid() || !present.as_bool() || dacl.is_null() {
            return false;
        }
        trusted(owner) && dacl_admin_only(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW (LocalAlloc).
        unsafe {
            LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// `ACCESS_ALLOWED_ACE_TYPE`, and the ACE types that grant nothing (denied, audit, alarm,
/// mandatory label, resource attribute, scoped policy, trust label).
const ALLOWED: u8 = 0;
const GRANTS_NOTHING: [u8; 7] = [1, 2, 3, 0x11, 0x12, 0x13, 0x14];

/// The owner and DACL of `path` (file or folder) admit writes by SYSTEM, Administrators and
/// TrustedInstaller only (`false` when unreadable).
pub fn path_admin_only(path: &Path) -> bool {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid path string and out pointer; the descriptor is LocalAlloc'd and owned by the
    // SecurityDescriptor below, whose Drop frees it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status.is_err() || sd.is_invalid() {
        return false;
    }
    SecurityDescriptor(sd).admin_only_writes()
}

fn dacl_admin_only(dacl: *mut ACL) -> bool {
    // SAFETY: `dacl` points into a valid descriptor that outlives this call.
    let count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: index < AceCount; `ace` receives a pointer into the ACL.
        if unsafe { GetAce(dacl, index, &mut ace) }.is_err() || ace.is_null() {
            return false;
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *(ace as *const ACE_HEADER) };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
            || GRANTS_NOTHING.contains(&header.AceType)
        {
            continue;
        }
        if header.AceType != ALLOWED {
            return false;
        }
        // SAFETY: type 0 is an ACCESS_ALLOWED_ACE; its SID starts at `SidStart`.
        let (mask, sid) = unsafe {
            let allowed = ace as *const ACCESS_ALLOWED_ACE;
            (
                (*allowed).Mask,
                PSID(&raw const (*allowed).SidStart as *mut c_void),
            )
        };
        if mask & WRITE_RIGHTS != 0 && !trusted(sid) {
            return false;
        }
    }
    true
}

fn trusted(sid: PSID) -> bool {
    sid_string(sid).is_some_and(|s| TRUSTED_WRITERS.contains(&s.as_str()))
}

/// `S-1-5-…` form of `sid`.
pub fn sid_string(sid: PSID) -> Option<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` is a valid SID; the string is LocalAlloc'd and freed below.
    unsafe {
        ConvertSidToStringSidW(sid, &mut text).ok()?;
        let out = text.to_string().ok();
        LocalFree(Some(HLOCAL(text.0.cast())));
        out
    }
}

/// Owner only: the DACL is not present, so the new file inherits its folder's ACEs.
const ADMIN_OWNER_SDDL: &str = "O:BA";

/// Creates `path` (which must not exist) owned by Administrators, with its folder's inherited
/// DACL, opened for writing with no sharing. Needs a token that may assign Administrators as
/// owner (elevated, or SYSTEM).
pub fn create_admin_owned(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };

    let sd = SecurityDescriptor::from_sddl(ADMIN_OWNER_SDDL).map_err(std::io::Error::other)?;
    let attributes = sd.attributes();
    // SAFETY: valid path and attributes (pointing at `sd`, alive for the call); the handle is
    // owned by the returned File right away.
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(path.as_os_str()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(&attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(std::io::Error::other)?;
    // SAFETY: a fresh handle that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) })
}

/// Why `path` is not admin-only (`None` when it is): what the service logs and the install verb
/// reports, so a refused folder says which file and which owner or grant.
pub fn untrusted_reason(path: &Path) -> Option<String> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: as in path_admin_only; freed by the SecurityDescriptor below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if status.is_err() || sd.is_invalid() {
        return Some(format!("{}: unreadable ({status:?})", path.display()));
    }
    let sd = SecurityDescriptor(sd);
    if sd.admin_only_writes() {
        return None;
    }
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    // SAFETY: a valid descriptor; out pointers are locals.
    let owner = unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) }
        .ok()
        .and_then(|()| sid_string(owner))
        .unwrap_or_else(|| "none".into());
    Some(format!(
        "{}: owner {owner} or a grant to another account may change it",
        path.display()
    ))
}

#[cfg(test)]
mod tests;
