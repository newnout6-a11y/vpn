//! Minimal trust check for the old app's machine-wide journals (spec §2.2): only files an
//! administrator or SYSTEM wrote may drive an elevated restore, because `%ProgramData%` lets
//! ordinary users create folders and a planted journal could otherwise point an adapter's DNS
//! at a server of the attacker's choosing. Rules: no reparse point, the expected type, owner
//! SYSTEM or Administrators, a protected DACL whose Allow entries name only those two.
use std::path::Path;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SE_DACL_PROTECTED, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW,
    INVALID_FILE_ATTRIBUTES,
};
use windows::core::{HSTRING, PCWSTR};

// winnt.h ACE types (the `SystemServices` feature that carries them is not enabled here).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// Why a path is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Untrusted {
    Missing,
    ReparsePoint,
    WrongType,
    Owner,
    NotProtected,
    NoDacl,
    ForeignAce,
    Unreadable,
}

impl Untrusted {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Untrusted::Missing => "missing",
            Untrusted::ReparsePoint => "reparse point",
            Untrusted::WrongType => "unexpected type",
            Untrusted::Owner => "owner is not SYSTEM or Administrators",
            Untrusted::NotProtected => "DACL inherits",
            Untrusted::NoDacl => "no DACL",
            Untrusted::ForeignAce => "access granted to other accounts",
            Untrusted::Unreadable => "security descriptor unreadable",
        }
    }
}

/// What a SID is, as far as the check cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sid {
    System,
    Admins,
    Other,
}

/// An access control entry, reduced to its kind and trustee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ace {
    Allow(Sid),
    Deny,
    /// Object / callback / audit entries: never written by the old app.
    Other,
}

/// The rule itself, separate from the Win32 reads.
pub(crate) fn judge(owner: Sid, protected: bool, aces: Option<&[Ace]>) -> Result<(), Untrusted> {
    if owner == Sid::Other {
        return Err(Untrusted::Owner);
    }
    if !protected {
        return Err(Untrusted::NotProtected);
    }
    let aces = aces.ok_or(Untrusted::NoDacl)?;
    let foreign = |a: &Ace| matches!(a, Ace::Allow(Sid::Other) | Ace::Other);
    if aces.iter().any(foreign) {
        return Err(Untrusted::ForeignAce);
    }
    Ok(())
}

/// Checks a real directory (`dir`) or file against [`judge`].
pub(crate) fn check(path: &Path, dir: bool) -> Result<(), Untrusted> {
    let wide = HSTRING::from(path.as_os_str());
    // SAFETY: NUL-terminated path that outlives the call.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(Untrusted::Missing);
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Untrusted::ReparsePoint);
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != dir {
        return Err(Untrusted::WrongType);
    }
    let sd = Descriptor::read(&wide)?;
    judge(sd.owner(), sd.protected()?, sd.aces().as_deref())
}

/// A security descriptor from `GetNamedSecurityInfoW` (freed with `LocalFree`).
struct Descriptor {
    sd: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl Descriptor {
    fn read(path: &HSTRING) -> Result<Self, Untrusted> {
        let mut out = Descriptor {
            sd: PSECURITY_DESCRIPTOR::default(),
            owner: PSID::default(),
            dacl: std::ptr::null_mut(),
        };
        // SAFETY: valid path; the out-pointers point into `out`, whose descriptor block owns
        // the returned owner / DACL pointers until `Drop` frees it.
        let code = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut out.owner),
                None,
                Some(&mut out.dacl),
                None,
                &mut out.sd,
            )
        };
        if code.is_err() || out.sd.0.is_null() || out.owner.0.is_null() {
            return Err(Untrusted::Unreadable);
        }
        Ok(out)
    }

    fn owner(&self) -> Sid {
        classify(self.owner)
    }

    fn protected(&self) -> Result<bool, Untrusted> {
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: `sd` is a live descriptor; both out-pointers are locals.
        unsafe { GetSecurityDescriptorControl(self.sd, &mut control, &mut revision) }
            .map_err(|_| Untrusted::Unreadable)?;
        Ok(control & SE_DACL_PROTECTED.0 != 0)
    }

    /// `None` for a NULL DACL (everyone has full access).
    fn aces(&self) -> Option<Vec<Ace>> {
        if self.dacl.is_null() {
            return None;
        }
        // SAFETY: a non-null DACL inside the live descriptor block.
        let count = unsafe { (*self.dacl).AceCount };
        let mut out = Vec::with_capacity(count.into());
        for index in 0..u32::from(count) {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            // SAFETY: index < AceCount of a valid ACL; `ace` points into the same block.
            if unsafe { GetAce(self.dacl, index, &mut ace) }.is_err() || ace.is_null() {
                out.push(Ace::Other);
                continue;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let kind = unsafe { (*(ace as *const ACE_HEADER)).AceType };
            out.push(match kind {
                ACCESS_ALLOWED_ACE_TYPE => {
                    // SAFETY: an ACCESS_ALLOWED_ACE stores its SID in place, from `SidStart`.
                    let sid = unsafe { &raw mut (*(ace as *mut ACCESS_ALLOWED_ACE)).SidStart };
                    Ace::Allow(classify(PSID(sid.cast())))
                }
                ACCESS_DENIED_ACE_TYPE => Ace::Deny,
                _ => Ace::Other,
            });
        }
        Some(out)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the block came from GetNamedSecurityInfoW and is freed once.
        unsafe { LocalFree(Some(HLOCAL(self.sd.0))) };
    }
}

fn classify(sid: PSID) -> Sid {
    // SAFETY (both calls): `sid` points to a valid SID inside a live security descriptor.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool() {
        Sid::System
    } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool() {
        Sid::Admins
    } else {
        Sid::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// AT-03-002: owner SYSTEM / Administrators, protected DACL, Allow entries only for them.
    #[test]
    fn judge_follows_the_old_rule() {
        let admins_only = [Ace::Allow(Sid::System), Ace::Allow(Sid::Admins), Ace::Deny];
        assert_eq!(judge(Sid::Admins, true, Some(&admins_only)), Ok(()));
        assert_eq!(judge(Sid::System, true, Some(&[])), Ok(()));
        assert_eq!(
            judge(Sid::Other, true, Some(&admins_only)),
            Err(Untrusted::Owner)
        );
        assert_eq!(
            judge(Sid::Admins, false, Some(&admins_only)),
            Err(Untrusted::NotProtected)
        );
        assert_eq!(judge(Sid::Admins, true, None), Err(Untrusted::NoDacl));
        let users = [Ace::Allow(Sid::Admins), Ace::Allow(Sid::Other)];
        assert_eq!(
            judge(Sid::Admins, true, Some(&users)),
            Err(Untrusted::ForeignAce)
        );
        assert_eq!(
            judge(Sid::Admins, true, Some(&[Ace::Other])),
            Err(Untrusted::ForeignAce)
        );
    }

    /// A file a test creates in `%TEMP%` is never trusted. Unelevated it is owned by the user;
    /// elevated on Windows Server (the CI runners) the default owner of new objects is
    /// BUILTIN\Administrators, and the inherited (unprotected) DACL rejects it instead.
    #[test]
    fn user_created_paths_are_untrusted() {
        let dir = TempDir::new("trust");
        let file = dir.write("firewall.json", b"{}");
        assert_eq!(check(dir.path(), false), Err(Untrusted::WrongType));
        assert_eq!(check(&file, true), Err(Untrusted::WrongType));
        let file_check = check(&file, false);
        assert!(
            matches!(file_check, Err(Untrusted::Owner | Untrusted::NotProtected)),
            "{file_check:?}"
        );
        if !vpnte_winnet::elevation::is_elevated() {
            assert_eq!(file_check, Err(Untrusted::Owner));
        }
        assert_eq!(
            check(&dir.path().join("absent.json"), false),
            Err(Untrusted::Missing)
        );
    }
}
