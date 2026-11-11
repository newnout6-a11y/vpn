//! Test helpers shared by the packages.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// A fresh directory under `%TEMP%` (`vpnte-tunnel-<tag>-<pid>-<n>`), removed on drop.
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("vpnte-tunnel-{tag}-{}-{n}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
