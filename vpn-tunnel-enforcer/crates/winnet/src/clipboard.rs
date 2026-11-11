//! A clipboard for secrets (keys, URIs): marked so Windows keeps it out of clipboard history and
//! cloud sync, and emptied after 60 s unless something else was copied meanwhile.
//!
//! Ownership is the clipboard sequence number seen right after our write: if it changed, the
//! content is no longer ours (the user copied something, or another app added formats) and it is
//! never cleared. A newer copy replaces the ownership, so an old deadline cannot clear it.
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{E_FAIL, GlobalFree, HANDLE, HWND, LPARAM, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE, MSG,
    PostThreadMessageW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_QUIT,
};
use windows::core::{Error, PCWSTR, Result, w};

use crate::win;

/// How long a secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(60);
/// Pause before retrying a clear that could not open the clipboard.
pub const RETRY_AFTER: Duration = Duration::from_secs(5);

/// The clipboard operations the secret clipboard needs: the real one, or a fake in tests.
trait Clip: Send + Sync + 'static {
    /// Replaces the content with `text`, marked private. Returns the sequence number of our
    /// content, `0` when it cannot be known (then the content is never cleared).
    fn write(&self, text: &str) -> AppResult<u32>;
    /// Empties the clipboard if its sequence number is still `seq`; `Ok(false)` when it changed.
    fn clear_if(&self, seq: u32) -> windows::core::Result<bool>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owned {
    seq: u32,
    due: Instant,
}

/// The ownership state machine, driven by explicit instants so tests need no clock.
struct Core {
    clip: Box<dyn Clip>,
    /// Held during clipboard calls: it also serialises our own clipboard operations.
    owned: Mutex<Option<Owned>>,
    wake: Notify,
}

impl Core {
    fn copy(&self, text: &str, now: Instant) -> AppResult<Duration> {
        let mut owned = self.owned.lock();
        // A failed write returns here and leaves the previous ownership (and deadline) armed.
        let seq = self.clip.write(text)?;
        *owned = (seq != 0).then_some(Owned {
            seq,
            due: now + CLEAR_AFTER,
        });
        drop(owned);
        self.wake.notify_one();
        Ok(CLEAR_AFTER)
    }

    /// Clears our content once it is due; returns the next deadline to wake up for.
    fn tick(&self, now: Instant) -> Option<Instant> {
        let mut owned = self.owned.lock();
        let current = (*owned)?;
        if now < current.due {
            return Some(current.due);
        }
        match self.clip.clear_if(current.seq) {
            Ok(cleared) => {
                tracing::debug!(cleared, "secret clipboard deadline reached");
                *owned = None;
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "secret clipboard not cleared yet, retrying");
                let due = now + RETRY_AFTER;
                *owned = Some(Owned { due, ..current });
                Some(due)
            }
        }
    }

    /// Clears our content now if it is still ours (shutdown).
    fn clear_now(&self) {
        let mut owned = self.owned.lock();
        if let Some(current) = owned.take()
            && let Err(e) = self.clip.clear_if(current.seq)
        {
            tracing::warn!(error = %e, "secret clipboard could not be cleared at shutdown");
        }
    }
}

/// Copies secrets and clears them after [`CLEAR_AFTER`] if they are still on the clipboard.
pub struct SecretClipboard {
    core: Arc<Core>,
    stop: CancellationToken,
}

impl SecretClipboard {
    /// Starts the clearing task on the current tokio runtime (panics outside one) and the
    /// clipboard's private owner window.
    pub fn start() -> Self {
        Self::with_clip(Box::new(SystemClipboard::new()))
    }

    fn with_clip(clip: Box<dyn Clip>) -> Self {
        let core = Arc::new(Core {
            clip,
            owned: Mutex::new(None),
            wake: Notify::new(),
        });
        let stop = CancellationToken::new();
        tokio::spawn(drive(core.clone(), stop.clone()));
        Self { core, stop }
    }

    /// Copies `text` and returns how long it will stay. Blocking (up to ~0.2 s while another
    /// program holds the clipboard). On failure the previous secret keeps its deadline.
    pub fn copy(&self, text: &str) -> AppResult<Duration> {
        self.core.copy(text, Instant::now())
    }

    /// Clears our content now if it is still ours and stops the clearing task (app shutdown).
    pub fn shutdown(&self) {
        self.core.clear_now();
        self.stop.cancel();
    }
}

impl Drop for SecretClipboard {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Sleeps until the next deadline (or a new copy) and lets [`Core::tick`] act on it.
async fn drive(core: Arc<Core>, stop: CancellationToken) {
    let mut next = None;
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            () = core.wake.notified() => {}
            () = sleep_until(next) => {}
        }
        let tick_core = core.clone();
        // Clipboard calls block (OpenClipboard retries): keep them off the async workers.
        next = tokio::task::spawn_blocking(move || tick_core.tick(Instant::now()))
            .await
            .unwrap_or(None);
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

/// Formats that keep content out of clipboard history and cloud sync (Microsoft Learn,
/// "Cloud Clipboard and Clipboard History Formats"; spec B18).
const PRIVACY_FORMATS: [PCWSTR; 3] = [
    w!("ExcludeClipboardContentFromMonitorProcessing"),
    w!("CanIncludeInClipboardHistory"),
    w!("CanUploadToCloudClipboard"),
];

/// The Windows clipboard, owned by a private message-only window.
///
/// Microsoft documents that `SetClipboardData` fails without an owner window. `EmptyClipboard`
/// SENDS `WM_DESTROYCLIPBOARD` to the current owner and waits, so the owner lives on a thread that
/// only pumps messages: with the app's window as owner, a clear on a blocking thread would wait
/// for a UI thread that may be waiting in `copy()` (deadlock), and a destroyed window (exit,
/// close-to-tray) would make every `OpenClipboard` fail.
struct SystemClipboard {
    /// The owner window; `0` if it could not be created (the clipboard is opened without one).
    owner: isize,
    /// Thread id of the window's message pump.
    pump: u32,
}

impl SystemClipboard {
    fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("vpnte-clipboard".into())
            .spawn(move || pump_owner_window(&tx));
        match thread.map(|_| rx.recv()) {
            Ok(Ok(Ok((owner, pump)))) => Self { owner, pump },
            failed => {
                tracing::warn!(
                    ?failed,
                    "no clipboard owner window, opening the clipboard without one"
                );
                Self { owner: 0, pump: 0 }
            }
        }
    }
}

impl Drop for SystemClipboard {
    fn drop(&mut self) {
        if self.pump != 0 {
            // SAFETY: a plain post; the pump leaves its loop and destroys the window.
            let _ = unsafe { PostThreadMessageW(self.pump, WM_QUIT, WPARAM(0), LPARAM(0)) };
        }
    }
}

/// The owner thread: creates the window, reports `(hwnd, thread id)`, pumps messages until
/// `WM_QUIT`, then destroys the window.
fn pump_owner_window(created: &SyncSender<Result<(isize, u32)>>) {
    // SAFETY: a message-only window of the predefined STATIC class, destroyed on this thread.
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
    };
    let hwnd = match window {
        Ok(hwnd) => hwnd,
        Err(e) => {
            let _ = created.send(Err(e));
            return;
        }
    };
    // SAFETY: no preconditions.
    let _ = created.send(Ok((hwnd.0 as isize, unsafe { GetCurrentThreadId() })));
    let mut msg = MSG::default();
    // SAFETY: this thread's own queue; `GetMessageW` returns 0 for WM_QUIT and -1 on failure.
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.0 > 0 {
        // SAFETY: `msg` was filled by GetMessageW.
        unsafe { DispatchMessageW(&msg) };
    }
    // SAFETY: the window belongs to this thread.
    let _ = unsafe { DestroyWindow(hwnd) };
}

impl Clip for SystemClipboard {
    fn write(&self, text: &str) -> AppResult<u32> {
        let session = Session::open(self.owner).map_err(|e| {
            AppError::msg(ErrorKind::Conflict, Msg::new("winnet.clipboard.busy")).with_source(e)
        })?;
        let units = win::wide(text);
        let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
        let written = (|| {
            // SAFETY: the clipboard is open (`session`).
            unsafe { EmptyClipboard() }?;
            for name in PRIVACY_FORMATS {
                // DWORD 0 = "not allowed"; for the exclusion format any data works.
                set_data(registered(name)?, &0u32.to_le_bytes())?;
            }
            set_data(u32::from(CF_UNICODETEXT.0), &bytes)
        })();
        if written.is_err() {
            // Never leave the secret behind without its privacy markers.
            // SAFETY: the clipboard is still open (`session`).
            let _ = unsafe { EmptyClipboard() };
        }
        drop(session);
        written.map_err(|e: Error| {
            AppError::msg(ErrorKind::Internal, Msg::new("winnet.clipboard.failed")).with_source(e)
        })?;
        // Read after closing, as the spec does: whether `CloseClipboard` itself bumps the number
        // is undocumented. A change by someone else within these microseconds would be adopted
        // as ours (and cleared at the deadline).
        // SAFETY: no preconditions.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    fn clear_if(&self, seq: u32) -> Result<bool> {
        let _session = Session::open(self.owner)?;
        // While the clipboard is open nobody else can change it: compare, then empty.
        // SAFETY: no preconditions.
        if unsafe { GetClipboardSequenceNumber() } != seq {
            return Ok(false);
        }
        // SAFETY: the clipboard is open (`_session`).
        unsafe { EmptyClipboard() }?;
        Ok(true)
    }
}

/// The open clipboard, closed on drop.
struct Session;

impl Session {
    /// Another program may hold the clipboard for a moment: 10 attempts, 20 ms apart.
    fn open(owner: isize) -> Result<Self> {
        let hwnd = (owner != 0).then_some(HWND(owner as *mut c_void));
        let mut last = Error::from_hresult(E_FAIL);
        for attempt in 0..10 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
            // SAFETY: `hwnd` is our owner window or none; balanced by `drop` on this thread.
            match unsafe { OpenClipboard(hwnd) } {
                Ok(()) => return Ok(Session),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: this thread opened the clipboard in `Session::open`.
        let _ = unsafe { CloseClipboard() };
    }
}

fn registered(name: PCWSTR) -> Result<u32> {
    // SAFETY: `name` is a static NUL-terminated string.
    match unsafe { RegisterClipboardFormatW(name) } {
        0 => Err(Error::from_thread()),
        id => Ok(id),
    }
}

/// Puts `bytes` on the open clipboard as `format`; the system owns the memory afterwards.
fn set_data(format: u32, bytes: &[u8]) -> Result<()> {
    // SAFETY: a fresh movable block of at least `bytes.len()` bytes, locked only while we copy
    // into it; on success the clipboard takes ownership of it, on failure we free it.
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1))?;
        let ptr = GlobalLock(mem).cast::<u8>();
        if ptr.is_null() {
            let _ = GlobalFree(Some(mem));
            return Err(Error::from_thread());
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        // "Fails" with NO_ERROR once the lock count reaches zero: nothing to handle.
        let _ = GlobalUnlock(mem);
        if let Err(e) = SetClipboardData(format, Some(HANDLE(mem.0))) {
            let _ = GlobalFree(Some(mem));
            return Err(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
