//! Where hardening reads and writes: the [`System`] trait (the journal's [`Backend`] for registry
//! targets plus what detection and the guards need) and its Windows implementation [`WinSystem`]
//! over `vpnte_winnet::registry`.
use std::io;
use std::path::Path;

use vpnte_winnet::registry::{self, Access, Hive, Key, Value, View};

use crate::tweaks::env::os_error;
use crate::tweaks::journal::{Backend, RegHive, Target, TweakError, Val};
use crate::tweaks::user;

/// The machine as hardening sees it. Production: [`WinSystem`]; tests: an in-memory fake.
/// Blocking: call it from a blocking thread.
pub trait System: Backend {
    /// Whether `path` is an existing directory (browser user-data folders).
    fn dir_exists(&self, path: &Path) -> bool;
    /// Whether this process may write machine policies (it runs elevated).
    fn elevated(&self) -> bool;
    /// `Err(OtherUser)` when per-user values would land in another account's profile (spec E3).
    fn check_user(&self) -> Result<(), TweakError>;
}

/// The real registry. [`WinSystem::under`] moves every key below a throw-away `HKCU` key, so the
/// whole write / read-back / prune path runs in tests without elevation.
#[derive(Debug, Clone, Default)]
pub struct WinSystem {
    sandbox: Option<String>,
}

impl WinSystem {
    /// The registry of this machine and of the account the process runs as.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every key mapped below `HKCU\<root>\HKLM\…` / `HKCU\<root>\HKCU\…` (tests). Such a system
    /// counts as elevated and skips the session-user check.
    pub fn under(root: impl Into<String>) -> Self {
        Self {
            sandbox: Some(root.into()),
        }
    }

    fn place(&self, hive: RegHive, key: &str) -> (Hive, String) {
        match (&self.sandbox, hive) {
            (None, RegHive::Hklm) => (Hive::LocalMachine, key.to_owned()),
            (None, RegHive::Hkcu) => (Hive::CurrentUser, key.to_owned()),
            (Some(root), RegHive::Hklm) => (Hive::CurrentUser, format!(r"{root}\HKLM\{key}")),
            (Some(root), RegHive::Hkcu) => (Hive::CurrentUser, format!(r"{root}\HKCU\{key}")),
        }
    }
}

fn reg(target: &Target) -> io::Result<(RegHive, &str, &str)> {
    match target {
        Target::Reg { hive, key, name } => Ok((*hive, key, name)),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a registry target",
        )),
    }
}

impl Backend for WinSystem {
    fn read(&self, target: &Target) -> io::Result<Val> {
        let (hive, key, name) = reg(target)?;
        let (hive, path) = self.place(hive, key);
        let Some(key) = Key::open(hive, &path, Access::Read, View::Native).map_err(os_error)?
        else {
            return Ok(Val::Absent);
        };
        match key.value(name).map_err(os_error)? {
            None => Ok(Val::Absent),
            Some(Value::Sz(s)) => Ok(Val::Sz(s)),
            Some(Value::ExpandSz(s)) => Ok(Val::ExpandSz(s)),
            Some(Value::Dword(v)) => Ok(Val::Dword(v)),
            // A type the journal cannot hold could not be put back: unreadable, nothing written.
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported registry value type",
            )),
        }
    }

    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        let (hive, key, name) = reg(target)?;
        let (hive, path) = self.place(hive, key);
        let data = match value {
            Val::Absent => {
                if let Some(key) =
                    Key::open(hive, &path, Access::ReadWrite, View::Native).map_err(os_error)?
                {
                    key.delete_value(name).map_err(os_error)?;
                }
                return Ok(false);
            }
            Val::Sz(s) => Value::Sz(s.clone()),
            Val::ExpandSz(s) => Value::ExpandSz(s.clone()),
            Val::Dword(v) => Value::Dword(*v),
            Val::Text(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a registry value",
                ));
            }
        };
        let (key, created) = Key::create(hive, &path, View::Native).map_err(os_error)?;
        key.set(name, &data).map_err(os_error)?;
        Ok(created)
    }

    fn prune(&self, target: &Target) -> io::Result<()> {
        let (hive, key, _) = reg(target)?;
        // Creating `…\BraveSoftware\Brave` may have created `…\BraveSoftware` too: remove each
        // empty key upwards, but never the first two levels (`SOFTWARE\Policies`,
        // `Software\Microsoft`), which belong to Windows.
        let parts: Vec<&str> = key.split('\\').collect();
        for depth in (3..=parts.len()).rev() {
            let (hive, path) = self.place(hive, &parts[..depth].join("\\"));
            let Some(open) =
                Key::open(hive, &path, Access::Read, View::Native).map_err(os_error)?
            else {
                break;
            };
            if !open.is_empty().map_err(os_error)? {
                break;
            }
            drop(open);
            registry::delete_key(hive, &path, View::Native).map_err(os_error)?;
        }
        Ok(())
    }
}

impl System for WinSystem {
    fn dir_exists(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn elevated(&self) -> bool {
        self.sandbox.is_some() || vpnte_winnet::elevation::is_elevated()
    }

    fn check_user(&self) -> Result<(), TweakError> {
        match self.sandbox {
            Some(_) => Ok(()),
            None => user::ensure_session_user(),
        }
    }
}

#[cfg(test)]
mod tests;
