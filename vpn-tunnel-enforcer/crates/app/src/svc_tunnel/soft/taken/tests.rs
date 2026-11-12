//! The system-proxy watch on a throw-away key (`HKCU\Software\VPNTE-Test-*`), never on the real
//! Internet Settings: a change wakes the read-back, again once re-armed, and the stop event ends
//! the thread.
use std::sync::mpsc;
use std::time::{Duration, Instant};

use vpnte_winnet::registry::{self, Hive, Key, View};

use super::*;

/// Removes the throw-away key on drop.
struct TestKey(String);

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = registry::delete_tree(Hive::CurrentUser, &self.0, View::Native);
    }
}

/// Writes to `key` until the watch reports a change. Each write stores a new number: Windows
/// signals nothing for a write of the data already there, and the first notification is armed
/// on the watch thread, so a write before that goes unseen.
fn change_until_seen(key: &Key, seen: &mpsc::Receiver<()>, value: &mut u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        *value += 1;
        key.set_dword("Probe", *value).unwrap();
        if seen.recv_timeout(Duration::from_millis(100)).is_ok() {
            return true;
        }
    }
    false
}

/// Signals the watch's stop event on drop, so a failed assertion cannot leave the scoped watch
/// thread waiting forever.
struct StopOnDrop(Owned<HANDLE>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        // SAFETY: the event is open until `self.0` drops right after.
        let _ = unsafe { SetEvent(*self.0) };
    }
}

#[test]
fn a_change_wakes_the_read_back_until_stopped() {
    let path = format!(
        r"Software\VPNTE-Test-proxy-watch-{}",
        uuid::Uuid::new_v4().simple()
    );
    let _cleanup = TestKey(path.clone());
    let (key, _) = Key::create(Hive::CurrentUser, &path, View::Native).unwrap();
    // SAFETY: an unnamed auto-reset event, owned at once.
    let stop = unsafe { Owned::new(CreateEventW(None, false, false, PCWSTR::null()).unwrap()) };
    let raw = (*stop).0 as usize;
    let (tx, seen) = mpsc::channel();
    std::thread::scope(|s| {
        let keys = [path.as_str()];
        let watcher = s.spawn(move || {
            watch_loop(HANDLE(raw as *mut _), &keys, move || {
                let _ = tx.send(());
            })
        });
        let stop = StopOnDrop(stop);
        let mut value = 0;
        assert!(
            change_until_seen(&key, &seen, &mut value),
            "first change seen"
        );
        std::thread::sleep(Duration::from_millis(300));
        while seen.try_recv().is_ok() {}
        assert!(
            change_until_seen(&key, &seen, &mut value),
            "seen again once re-armed"
        );
        drop(stop);
        watcher.join().unwrap();
    });
}

/// Ending the session clears the line, whatever the last read-back said.
#[test]
fn stop_clears_the_line() {
    let line = subscribe();
    publish(true);
    assert!(*line.borrow());
    stop();
    assert!(!*line.borrow());
}
