//! The journal's cross-process lock (`tweaks.lock` next to `tweaks.json`).
//!
//! Every process keeps its own copy of the document, and two of ours can work on the same journal
//! at once: the crash watcher rolling back a dead app's Soft session while the next start runs its
//! own recovery. So every change runs under this lock, on a copy read from disk under it. The OS
//! drops the lock with the handle, also when the holder dies.
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// File name of the lock under the data root.
pub const LOCK_FILE: &str = "tweaks.lock";
/// Far longer than a journal operation takes (a few values and one broadcast). A holder stuck past
/// it must not keep a rollback from running, so the work then goes on without the lock.
const WAIT: Duration = Duration::from_secs(10);
const STEP: Duration = Duration::from_millis(10);

/// Holds the lock until dropped (`None`: going on without it, already logged).
pub(super) struct Held {
    _file: Option<File>,
}

/// Takes the lock of the journal under `root`, waiting up to [`WAIT`] for another holder.
pub(super) fn hold(root: &Path) -> Held {
    match take(root, WAIT) {
        Ok(file) => Held { _file: Some(file) },
        Err(e) => {
            tracing::warn!(error = %e, "tweak journal lock not taken; going on without it");
            Held { _file: None }
        }
    }
}

fn take(root: &Path, wait: Duration) -> io::Result<File> {
    std::fs::create_dir_all(root)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join(LOCK_FILE))?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(STEP),
            Err(TryLockError::WouldBlock) => return Err(io::ErrorKind::TimedOut.into()),
            Err(TryLockError::Error(e)) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// A second holder waits for the first one and gets the lock once it is released; a holder
    /// that never lets go is waited for only up to the deadline.
    #[test]
    fn second_holder_waits_then_takes_over() {
        let dir = TempDir::new("tweaks-lock");
        let first = take(dir.path(), Duration::ZERO).unwrap();
        let err = take(dir.path(), Duration::from_millis(30)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let root = dir.path().to_path_buf();
        let waiter = std::thread::spawn(move || take(&root, Duration::from_secs(5)).is_ok());
        std::thread::sleep(Duration::from_millis(50));
        drop(first);
        assert!(waiter.join().unwrap());
    }
}
