//! Notices another program taking the system proxy over while our session holds it (another VPN
//! client, a policy): Windows signals every change of the per-user Internet Settings and each one
//! gets our usual read-back. No timer: the thread sleeps in one wait until something changes.
use std::sync::LazyLock;
use std::thread::JoinHandle;

use parking_lot::Mutex;
use tokio::sync::watch;
use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, RegNotifyChangeKeyValue,
    RegOpenKeyExW,
};
use windows::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects};
use windows::core::{HSTRING, Owned, PCWSTR};

#[cfg(test)]
mod tests;

/// Where WinINet keeps the per-user setting: the values, and the binary blob under `Connections`.
const KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
];

/// `true` while another program holds the system proxy our session set.
static TAKEN: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::Sender::new(false));
/// The running watch: one per process, like the proxy session it belongs to.
static WATCH: Mutex<Option<Watch>> = Mutex::new(None);

/// The "taken by another program" fact for the start page.
pub(crate) fn subscribe() -> watch::Receiver<bool> {
    TAKEN.subscribe()
}

/// Publishes a read-back result (receivers wake only on a change).
pub(super) fn publish(taken: bool) {
    TAKEN.send_if_modified(|now| std::mem::replace(now, taken) != taken);
}

struct Watch {
    stop: Owned<HANDLE>,
    thread: JoinHandle<()>,
}

// SAFETY: an event handle may be signalled and closed from any thread.
unsafe impl Send for Watch {}

/// Starts the watch unless it runs; `check` does the read-back on the watch thread after every
/// change. Without a watch (Windows refused the notification) the read-backs at restarts remain.
pub(super) fn start(check: impl Fn() + Send + 'static) {
    let mut slot = WATCH.lock();
    if slot.as_ref().is_some_and(|w| !w.thread.is_finished()) {
        return;
    }
    // SAFETY: an unnamed auto-reset event, owned at once.
    let stop = match unsafe { CreateEventW(None, false, false, PCWSTR::null()) } {
        Ok(event) => unsafe { Owned::new(event) },
        Err(e) => {
            tracing::warn!(error = %e, "system proxy watch not started");
            return;
        }
    };
    let signal = *stop;
    // The raw value crosses the thread boundary; the handle stays open until the thread joined.
    let raw = signal.0 as usize;
    let thread = std::thread::Builder::new()
        .name("proxy-watch".into())
        .spawn(move || watch_loop(HANDLE(raw as *mut _), &KEYS, check));
    match thread {
        Ok(thread) => *slot = Some(Watch { stop, thread }),
        Err(e) => tracing::warn!(error = %e, "system proxy watch not started"),
    }
}

/// Stops the watch (the session's proxy is rolled back) and clears the line.
pub(super) fn stop() {
    let watch = WATCH.lock().take();
    if let Some(watch) = watch {
        // SAFETY: the event is open until `watch` drops below.
        if unsafe { SetEvent(*watch.stop) }.is_ok() && watch.thread.join().is_err() {
            tracing::warn!("system proxy watch ended with a panic");
        }
    }
    publish(false);
}

/// Watches `keys` (paths under HKCU) until `stop` is signalled; `check` runs after each change.
fn watch_loop(stop: HANDLE, keys: &[&str], check: impl Fn()) {
    let watched: Vec<(Owned<HKEY>, Owned<HANDLE>)> =
        keys.iter().filter_map(|path| arm_key(path)).collect();
    if watched.is_empty() {
        tracing::warn!("system proxy watch has nothing to watch");
        return;
    }
    let mut handles = vec![stop];
    handles.extend(watched.iter().map(|(_, event)| **event));
    loop {
        // SAFETY: every handle stays open for the whole loop.
        let hit = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
        let index = hit.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        let Some((key, event)) = index.checked_sub(1).and_then(|i| watched.get(i)) else {
            return; // the stop event, or the wait failed
        };
        // Re-armed before the read-back, so a change during it is not missed.
        if let Err(e) = notify(key, event) {
            tracing::warn!(error = %e, "system proxy watch stopped");
            return;
        }
        check();
    }
}

/// Opens `path` under HKCU for notifications and arms the first one.
fn arm_key(path: &str) -> Option<(Owned<HKEY>, Owned<HANDLE>)> {
    let mut key = HKEY::default();
    // SAFETY: a valid out-pointer; the key is owned at once.
    unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            &HSTRING::from(path),
            None,
            KEY_NOTIFY,
            &mut key,
        )
    }
    .ok()
    .ok()?;
    // SAFETY: the key RegOpenKeyExW just opened.
    let key = unsafe { Owned::new(key) };
    // SAFETY: an unnamed auto-reset event, owned at once.
    let event = unsafe { Owned::new(CreateEventW(None, false, false, PCWSTR::null()).ok()?) };
    notify(&key, &event).ok()?;
    Some((key, event))
}

/// One change notification of the key's values into `event` (asynchronous: returns at once).
fn notify(key: &Owned<HKEY>, event: &Owned<HANDLE>) -> windows::core::Result<()> {
    // SAFETY: both handles are open; the registering thread outlives the registration.
    unsafe {
        RegNotifyChangeKeyValue(
            **key,
            false,
            REG_NOTIFY_CHANGE_LAST_SET,
            Some(**event),
            true,
        )
    }
    .ok()
}
