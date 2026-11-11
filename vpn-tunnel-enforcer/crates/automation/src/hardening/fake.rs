//! In-memory machine for the tests: registry values by target, keys, directories, and injected
//! faults. Nothing here touches the real registry.
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use super::system::System;
use crate::tweaks::journal::{Backend, RegHive, Target, TweakError, Val};

#[derive(Default)]
pub struct Fake {
    pub values: Mutex<HashMap<Target, Val>>,
    pub keys: Mutex<HashSet<(RegHive, String)>>,
    pub dirs: Mutex<HashSet<PathBuf>>,
    pub fail_read: Mutex<HashSet<Target>>,
    pub fail_write: Mutex<HashSet<Target>>,
    /// Writes to these store something else (read-back mismatch).
    pub garble: Mutex<HashSet<Target>>,
    pub writes: Mutex<Vec<(Target, Val)>>,
    pub pruned: Mutex<Vec<Target>>,
    pub unelevated: bool,
    pub other_user: bool,
}

/// A registry target.
pub fn reg(hive: RegHive, key: &str, name: &str) -> Target {
    Target::Reg {
        hive,
        key: key.to_owned(),
        name: name.to_owned(),
    }
}

fn parts(target: &Target) -> (RegHive, String) {
    match target {
        Target::Reg { hive, key, .. } => (*hive, key.clone()),
        other => panic!("not a registry target: {other:?}"),
    }
}

impl Fake {
    pub fn get(&self, t: &Target) -> Val {
        self.values.lock().get(t).cloned().unwrap_or(Val::Absent)
    }

    /// Sets a value as if someone else wrote it (creates its key).
    pub fn set(&self, t: &Target, v: Val) {
        self.keys.lock().insert(parts(t));
        self.values.lock().insert(t.clone(), v);
    }

    pub fn write_count(&self) -> usize {
        self.writes.lock().len()
    }

    /// Registers `exe` under the 64-bit `HKLM` App Paths with the given install path.
    pub fn app_path(&self, exe: &str, path: &str) {
        let key = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
        self.set(&reg(RegHive::Hklm, &key, ""), Val::Sz(path.to_owned()));
    }
}

impl Backend for Fake {
    fn read(&self, target: &Target) -> io::Result<Val> {
        if self.fail_read.lock().contains(target) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(self.get(target))
    }

    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        if self.fail_write.lock().contains(target) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        self.writes.lock().push((target.clone(), value.clone()));
        if *value == Val::Absent {
            self.values.lock().remove(target);
            return Ok(false);
        }
        let created = self.keys.lock().insert(parts(target));
        let stored = if self.garble.lock().contains(target) {
            Val::Sz("garbled".into())
        } else {
            value.clone()
        };
        self.values.lock().insert(target.clone(), stored);
        Ok(created)
    }

    fn prune(&self, target: &Target) -> io::Result<()> {
        let key = parts(target);
        let empty = !self.values.lock().keys().any(|t| parts(t) == key);
        if empty {
            self.keys.lock().remove(&key);
        }
        self.pruned.lock().push(target.clone());
        Ok(())
    }
}

impl System for Fake {
    fn dir_exists(&self, path: &Path) -> bool {
        self.dirs.lock().contains(path)
    }

    fn elevated(&self) -> bool {
        !self.unelevated
    }

    fn check_user(&self) -> Result<(), TweakError> {
        if self.other_user {
            Err(TweakError::OtherUser)
        } else {
            Ok(())
        }
    }
}
