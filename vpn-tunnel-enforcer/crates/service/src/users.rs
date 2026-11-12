//! The Windows users that use the service (by SID), persisted in the service's data folder. A
//! user is added at his first `Hello` and removed by his per-user uninstaller (`ForgetMe`); the
//! last one leaving removes the service.
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

/// The users list (`users.json`: a JSON array of SID strings).
pub struct Users {
    path: PathBuf,
    list: Mutex<BTreeSet<String>>,
}

impl Users {
    /// Loads `path` (missing or unreadable = nobody yet).
    pub fn open(path: &Path) -> Self {
        let list = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path: path.to_owned(),
            list: Mutex::new(list),
        }
    }

    /// Records `sid` (no write when already known).
    pub fn add(&self, sid: &str) -> io::Result<()> {
        let mut list = self.list.lock();
        if list.insert(sid.to_owned()) {
            save(&self.path, &list)?;
        }
        Ok(())
    }

    /// Forgets `sid`; `true` when nobody is left afterwards (and somebody was there before).
    pub fn remove(&self, sid: &str) -> io::Result<bool> {
        let mut list = self.list.lock();
        let was_known = list.remove(sid);
        save(&self.path, &list)?;
        Ok(list.is_empty() && was_known)
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

/// Atomic replace: write a sibling, then rename over the old file.
fn save(path: &Path, list: &BTreeSet<String>) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(list).map_err(io::Error::other)?)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_user_leaving_is_reported_once() {
        let dir = std::env::temp_dir().join(format!("vpnte-users-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("users.json");
        let users = Users::open(&path);
        assert!(users.is_empty());
        users.add("S-1-5-21-1-2-3-1001").expect("add");
        users.add("S-1-5-21-1-2-3-1002").expect("add");
        users.add("S-1-5-21-1-2-3-1002").expect("add twice");
        assert_eq!(Users::open(&path).len(), 2, "persisted");
        assert!(!users.remove("S-1-5-21-1-2-3-1001").expect("remove"));
        assert!(users.remove("S-1-5-21-1-2-3-1002").expect("remove"));
        assert!(
            !users.remove("S-1-5-21-1-2-3-1002").expect("unknown"),
            "only once"
        );
        assert!(Users::open(&path).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
