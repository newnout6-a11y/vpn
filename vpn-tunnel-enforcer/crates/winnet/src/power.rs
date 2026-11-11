//! System events the app reacts to: wake from sleep, session unlock, light/dark switch.
//!
//! They arrive at a hidden *top-level* window on its own thread. Not a message-only window
//! (`HWND_MESSAGE`): those receive no broadcasts, and both `WM_SETTINGCHANGE` (theme) and the
//! classic `WM_POWERBROADCAST` are broadcasts. Modern-standby wakes are only reported to
//! windows that also register with `RegisterSuspendResumeNotification`, so we do both.
use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use vpnte_base::{AppError, AppResult};
use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Power::{
    HPOWERNOTIFY, RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
};
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DispatchMessageW, GetMessageW,
    MSG, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND, PostMessageW, PostQuitMessage, RegisterClassExW,
    WM_CLOSE, WM_DESTROY, WM_POWERBROADCAST, WM_SETTINGCHANGE, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP, WTS_SESSION_UNLOCK,
};
use windows::core::{PCWSTR, w};

use crate::registry::{Access, Hive, Key, View};

/// A system event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// The machine woke from sleep or hibernation.
    Resumed,
    /// The user unlocked this Windows session (also the only signal of some modern-standby wakes).
    SessionUnlocked,
    /// Windows apps switched between light and dark mode.
    ThemeChanged { dark: bool },
}

/// Both deliveries of one wake (registration and broadcast) land within this window.
const RESUME_DEDUP: Duration = Duration::from_secs(5);
const CLASS_NAME: PCWSTR = w!("VPNTE.PowerMonitor");
const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

/// Delivers [`PowerEvent`]s to subscribers until dropped.
pub struct PowerMonitor {
    /// The window handle as an integer (`HWND` is not `Send`).
    hwnd: usize,
    events: broadcast::Sender<PowerEvent>,
    thread: Option<JoinHandle<()>>,
}

impl PowerMonitor {
    /// Creates the event window on its own thread.
    pub fn start() -> AppResult<Self> {
        let (events, _) = broadcast::channel(16);
        let sender = events.clone();
        let (ready_tx, ready_rx) = std_mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("vpnte-power".into())
            .spawn(move || run(sender, &ready_tx))?;
        match ready_rx.recv() {
            Ok(Ok(hwnd)) => Ok(Self {
                hwnd,
                events,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(AppError::internal(std::io::Error::other(
                    "power event thread ended before its window existed",
                )))
            }
        }
    }

    /// A receiver for the events from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<PowerEvent> {
        self.events.subscribe()
    }

    fn window(&self) -> HWND {
        HWND(self.hwnd as *mut c_void)
    }
}

impl Drop for PowerMonitor {
    fn drop(&mut self) {
        // SAFETY: posting to our own window; WM_CLOSE destroys it and ends its message loop.
        let _ = unsafe { PostMessageW(Some(self.window()), WM_CLOSE, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `true` when Windows apps use dark mode (`AppsUseLightTheme` = 0); light when it is unset.
pub fn system_prefers_dark() -> bool {
    let key = Key::open(Hive::CurrentUser, PERSONALIZE, Access::Read, View::Native);
    let value = key.and_then(|key| key.map_or(Ok(None), |k| k.dword("AppsUseLightTheme")));
    matches!(value, Ok(Some(0)))
}

/// What the window remembers between messages (lives on the window's thread only).
struct WindowState {
    events: broadcast::Sender<PowerEvent>,
    dark: bool,
    last_resume: Option<Instant>,
    power_notify: Option<HPOWERNOTIFY>,
}

impl WindowState {
    fn resumed(&mut self, now: Instant) -> Option<PowerEvent> {
        if self
            .last_resume
            .is_some_and(|t| now.duration_since(t) < RESUME_DEDUP)
        {
            return None;
        }
        self.last_resume = Some(now);
        Some(PowerEvent::Resumed)
    }

    /// `ImmersiveColorSet` also fires for accent colour changes and often several times per
    /// switch: report only a real light/dark change.
    fn theme_read(&mut self, dark: bool) -> Option<PowerEvent> {
        (dark != self.dark).then(|| {
            self.dark = dark;
            PowerEvent::ThemeChanged { dark }
        })
    }
}

thread_local! {
    static STATE: RefCell<Option<WindowState>> = const { RefCell::new(None) };
}

fn run(events: broadcast::Sender<PowerEvent>, ready: &std_mpsc::Sender<AppResult<usize>>) {
    let hwnd = match create_window() {
        Ok(hwnd) => hwnd,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    // SAFETY: `hwnd` is our live window; both registrations are undone on WM_DESTROY.
    let power_notify =
        unsafe { RegisterSuspendResumeNotification(HANDLE(hwnd.0), DEVICE_NOTIFY_WINDOW_HANDLE) }
            .inspect_err(|e| tracing::debug!(error = %e, "power: no suspend/resume registration"))
            .ok();
    // SAFETY: as above. NOTIFY_FOR_THIS_SESSION: only our own session's lock / unlock arrive.
    if let Err(e) = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } {
        tracing::warn!(error = %e, "power: no session notifications");
    }
    STATE.with_borrow_mut(|state| {
        *state = Some(WindowState {
            events,
            dark: system_prefers_dark(),
            last_resume: None,
            power_notify,
        });
    });
    let _ = ready.send(Ok(hwnd.0 as usize));
    let mut msg = MSG::default();
    loop {
        // SAFETY: a standard message loop for the windows of this thread.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) }.0;
        if got == 0 || got == -1 {
            break;
        }
        // SAFETY: `msg` was filled by GetMessageW.
        unsafe { DispatchMessageW(&msg) };
    }
}

fn create_window() -> AppResult<HWND> {
    // SAFETY: plain calls; the class lives for the process, the window for this thread.
    unsafe {
        let instance = GetModuleHandleW(PCWSTR::null()).map_err(AppError::internal)?;
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        if RegisterClassExW(&class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(AppError::internal(windows::core::Error::from_thread()));
        }
        // Top-level (no parent) so broadcasts reach it; never shown, no taskbar or Alt+Tab entry.
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            CLASS_NAME,
            w!("VPN Tunnel Enforcer power events"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )
        .map_err(AppError::internal)
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_POWERBROADCAST if wparam.0 as u32 == PBT_APMRESUMEAUTOMATIC => {
            emit(|s| s.resumed(Instant::now()));
        }
        WM_POWERBROADCAST if wparam.0 as u32 == PBT_APMSUSPEND => {
            tracing::info!("power: system is suspending");
        }
        WM_WTSSESSION_CHANGE if wparam.0 as u32 == WTS_SESSION_UNLOCK => {
            emit(|_| Some(PowerEvent::SessionUnlocked));
        }
        // SAFETY: for WM_SETTINGCHANGE a non-null lParam is a NUL-terminated string.
        WM_SETTINGCHANGE if unsafe { is_color_set(lparam) } => {
            let dark = system_prefers_dark();
            emit(|s| s.theme_read(dark));
        }
        WM_DESTROY => {
            STATE.with_borrow_mut(|state| {
                if let Some(notify) = state.take().and_then(|s| s.power_notify) {
                    // SAFETY: registered for this window in `run`.
                    let _ = unsafe { UnregisterSuspendResumeNotification(notify) };
                }
            });
            // SAFETY: `hwnd` is the window being destroyed; then end this thread's loop.
            unsafe {
                let _ = WTSUnRegisterSessionNotification(hwnd);
                PostQuitMessage(0);
            }
            return LRESULT(0);
        }
        _ => {}
    }
    // SAFETY: default handling for our own window (WM_CLOSE destroys it).
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn emit(decide: impl FnOnce(&mut WindowState) -> Option<PowerEvent>) {
    STATE.with_borrow_mut(|state| {
        if let Some(state) = state.as_mut()
            && let Some(event) = decide(state)
        {
            tracing::info!(?event, "power: system event");
            let _ = state.events.send(event);
        }
    });
}

/// # Safety
/// `lparam` is null or points to a NUL-terminated UTF-16 string.
unsafe fn is_color_set(lparam: LPARAM) -> bool {
    lparam.0 != 0
        // SAFETY: guaranteed by the caller.
        && unsafe { PCWSTR(lparam.0 as *const u16).to_string() }
            .is_ok_and(|area| area == "ImmersiveColorSet")
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast::error::TryRecvError;
    use windows::Win32::UI::WindowsAndMessaging::{SendMessageW, WTS_SESSION_LOCK};
    use windows::core::HSTRING;

    use super::*;

    fn state(dark: bool) -> WindowState {
        WindowState {
            events: broadcast::channel(4).0,
            dark,
            last_resume: None,
            power_notify: None,
        }
    }

    /// One wake can arrive twice (registration + broadcast): reported once.
    #[test]
    fn resume_is_reported_once_per_wake() {
        let mut s = state(false);
        let t = Instant::now();
        assert_eq!(s.resumed(t), Some(PowerEvent::Resumed));
        assert_eq!(s.resumed(t + Duration::from_secs(1)), None);
        assert_eq!(s.resumed(t + RESUME_DEDUP), Some(PowerEvent::Resumed));
    }

    /// Repeated `ImmersiveColorSet` broadcasts without a light/dark change stay silent.
    #[test]
    fn theme_change_is_reported_on_a_real_switch_only() {
        let mut s = state(false);
        assert_eq!(s.theme_read(false), None);
        assert_eq!(
            s.theme_read(true),
            Some(PowerEvent::ThemeChanged { dark: true })
        );
        assert_eq!(s.theme_read(true), None);
        assert_eq!(
            s.theme_read(false),
            Some(PowerEvent::ThemeChanged { dark: false })
        );
    }

    /// The real window: synthetic messages come out as events; dropping the monitor ends the
    /// thread and closes the channel.
    #[test]
    fn window_turns_messages_into_events() {
        let monitor = PowerMonitor::start().unwrap();
        let mut events = monitor.subscribe();
        let send = |msg: u32, wparam: usize, lparam: isize| {
            // SAFETY: our own live window; it is pumped by the monitor thread.
            unsafe {
                SendMessageW(
                    monitor.window(),
                    msg,
                    Some(WPARAM(wparam)),
                    Some(LPARAM(lparam)),
                )
            };
        };
        send(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize, 0);
        assert_eq!(events.try_recv(), Ok(PowerEvent::Resumed));
        send(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize, 0);
        send(WM_POWERBROADCAST, PBT_APMSUSPEND as usize, 0);
        assert_eq!(events.try_recv(), Err(TryRecvError::Empty));

        send(WM_WTSSESSION_CHANGE, WTS_SESSION_UNLOCK as usize, 1);
        assert_eq!(events.try_recv(), Ok(PowerEvent::SessionUnlocked));
        send(WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize, 1);
        assert_eq!(events.try_recv(), Err(TryRecvError::Empty));

        // The theme did not change during the test, so a colour broadcast emits nothing.
        let area = HSTRING::from("ImmersiveColorSet");
        send(WM_SETTINGCHANGE, 0, area.as_ptr() as isize);
        send(WM_SETTINGCHANGE, 0, 0);
        assert_eq!(events.try_recv(), Err(TryRecvError::Empty));

        drop(monitor);
        assert_eq!(events.try_recv(), Err(TryRecvError::Closed));
    }
}
