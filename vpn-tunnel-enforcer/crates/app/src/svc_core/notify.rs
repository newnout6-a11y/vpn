//! The notifier (lifecycle-app §3.18 with owner decision D-12): every notice reaches the log and
//! the in-app list; `desktop_notifications`, the per-category switches, the method and `sound`
//! decide only whether and how a Windows toast is shown. Toasts are blocking WinRT calls, so they
//! run on the notifier's own thread: `notify` never blocks and needs no tokio runtime.
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::broadcast;
use vpnte_base::types::{Level, Notice, UnixMs, now_ms};
use vpnte_base::{AppResult, Msg};
use vpnte_core::settings::{NotificationPrefs, NotifyMethod, Settings};
use vpnte_core::store::Store;
use vpnte_tunnel::lifecycle::NoticeKind;
use vpnte_winnet::toast::{self, NotifySetting, OnActivate, Toast};

/// Identical title + body within this window are delivered once: a crash-looping engine must
/// not stack five identical toasts.
pub const COALESCE: Duration = Duration::from_millis(1500);
/// How long a read of the Windows notification setting is trusted (one WinRT call per 30 s).
const OS_STATE_TTL: Duration = Duration::from_secs(30);
/// In-app notices buffered for a slow receiver.
const INAPP_CAPACITY: usize = 64;

/// User-toggleable category of a notice (`settings.notifications.*`); `None` = uncategorised,
/// gated only by `desktop_notifications`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoticeCategory {
    VpnConnect,
    VpnDisconnect,
    LeakDetected,
    ProfileRotation,
    ScheduleTriggered,
    ConnectionError,
}

impl NoticeCategory {
    /// The user's switch for this category.
    pub fn enabled(self, prefs: &NotificationPrefs) -> bool {
        match self {
            NoticeCategory::VpnConnect => prefs.vpn_connect,
            NoticeCategory::VpnDisconnect => prefs.vpn_disconnect,
            NoticeCategory::LeakDetected => prefs.leak_detected,
            NoticeCategory::ProfileRotation => prefs.profile_rotation,
            NoticeCategory::ScheduleTriggered => prefs.schedule_triggered,
            NoticeCategory::ConnectionError => prefs.connection_error,
        }
    }
}

impl From<NoticeKind> for NoticeCategory {
    fn from(kind: NoticeKind) -> Self {
        match kind {
            NoticeKind::VpnConnect => NoticeCategory::VpnConnect,
            NoticeKind::VpnDisconnect => NoticeCategory::VpnDisconnect,
            NoticeKind::ConnectionError => NoticeCategory::ConnectionError,
            NoticeKind::ProfileRotation => NoticeCategory::ProfileRotation,
        }
    }
}

/// One notice for the in-app list (every notice, in delivery order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InAppNotice {
    pub notice: Notice,
    pub category: Option<NoticeCategory>,
    pub at: UnixMs,
    /// Also pop it up in the window: no Windows toast was shown (method in-app, blocked or failed),
    /// the method is "both", or Windows' setting is unknown. `false` = list only (the user switched
    /// the category or desktop notifications off, or the toast is on screen).
    pub popup: bool,
}

/// Toasts with an in-app fallback; share it as `Arc<Notifier>`.
pub struct Notifier {
    settings: Arc<Store<Settings>>,
    inapp: broadcast::Sender<InAppNotice>,
    coalescer: Mutex<Coalescer>,
    jobs: mpsc::Sender<Job>,
    activate: Arc<OnceLock<OnActivate>>,
    /// Sees every delivered notice (p-logs: the event journal); set once at start.
    hook: OnceLock<NoticeHook>,
}

/// Called with every notice the app shows, whatever the toast switches say (p-logs).
pub type NoticeHook = Arc<dyn Fn(&Notice, Option<NoticeCategory>, UnixMs) + Send + Sync>;

impl Notifier {
    /// Starts the toast thread (it ends when the notifier is dropped).
    pub fn new(settings: Arc<Store<Settings>>) -> AppResult<Self> {
        let (inapp, _) = broadcast::channel(INAPP_CAPACITY);
        let (jobs, rx) = mpsc::channel();
        let activate = Arc::new(OnceLock::new());
        let (list, on_activate) = (inapp.clone(), activate.clone());
        std::thread::Builder::new()
            .name("notifier".into())
            .spawn(move || toast_worker(rx, list, on_activate))?;
        Ok(Self {
            settings,
            inapp,
            coalescer: Mutex::new(Coalescer::default()),
            jobs,
            activate,
            hook: OnceLock::new(),
        })
    }

    /// Hands every notice from now on to `hook` too (the event journal); the first call wins.
    pub fn set_hook(&self, hook: NoticeHook) {
        let _ = self.hook.set(hook);
    }

    /// Delivers `notice` under `category` (see the module doc); never blocks.
    pub fn notify(&self, notice: Notice, category: Option<NoticeCategory>) {
        if !self.coalescer.lock().admit(&notice, Instant::now()) {
            tracing::debug!(title = %notice.title.key, "duplicate notice coalesced");
            return;
        }
        let (desktop, prefs, lang) = self
            .settings
            .read(|s| (s.desktop_notifications, s.notifications.clone(), s.locale));
        tracing::info!(title = %notice.title.key, level = ?notice.level, "notice");
        let at = now_ms();
        if let Some(hook) = self.hook.get() {
            hook(&notice, category, at);
        }
        match route(desktop, &prefs, category) {
            Route::ListOnly => self.publish(notice, category, at, false),
            Route::InApp => self.publish(notice, category, at, true),
            Route::Toast { both } => {
                let lang = lang.unwrap_or_else(vpnte_ui::lang::os_lang);
                let toast = Toast {
                    title: notice.title.render(lang),
                    body: notice
                        .body
                        .as_ref()
                        .map(|b| b.render(lang))
                        .unwrap_or_default(),
                    sound: toast_sound(&prefs, notice.level),
                };
                let job = Job {
                    notice,
                    category,
                    at,
                    toast,
                    both,
                };
                if let Err(mpsc::SendError(job)) = self.jobs.send(job) {
                    // The toast thread is gone (it panicked): the window is the last resort.
                    self.publish(job.notice, job.category, job.at, true);
                }
            }
        }
    }

    /// The in-app list: every delivered notice (`popup` says whether to show it as a toast too).
    pub fn subscribe(&self) -> broadcast::Receiver<InAppNotice> {
        self.inapp.subscribe()
    }

    /// What a click on a toast does while it is on screen (show the main window); the first call
    /// wins.
    pub fn set_on_activate(&self, on_activate: OnActivate) {
        let _ = self.activate.set(on_activate);
    }

    fn publish(&self, notice: Notice, category: Option<NoticeCategory>, at: UnixMs, popup: bool) {
        // No receiver yet (the window is not up) is not an error: the log has the notice.
        let _ = self.inapp.send(InAppNotice {
            notice,
            category,
            at,
            popup,
        });
    }
}

impl vpnte_tunnel::lifecycle::Notifier for Notifier {
    fn notify(&self, notice: Notice, kind: NoticeKind) {
        Notifier::notify(self, notice, Some(kind.into()));
    }
}

/// A notice on its way to Windows.
struct Job {
    notice: Notice,
    category: Option<NoticeCategory>,
    at: UnixMs,
    toast: Toast,
    both: bool,
}

/// How one notice is delivered, decided before Windows' own setting is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// The user switched it off: the in-app list and the log only.
    ListOnly,
    /// Method "in-app": popped up in the window, never a Windows toast.
    InApp,
    /// A Windows toast (`both`: popped up in the window as well).
    Toast { both: bool },
}

fn route(desktop: bool, prefs: &NotificationPrefs, category: Option<NoticeCategory>) -> Route {
    if !desktop || category.is_some_and(|c| !c.enabled(prefs)) {
        return Route::ListOnly;
    }
    // An uncategorised notice ignores the per-category method, as in the old app.
    let method = match category {
        Some(_) => prefs.method,
        None => NotifyMethod::System,
    };
    match method {
        NotifyMethod::InApp => Route::InApp,
        NotifyMethod::System => Route::Toast { both: false },
        NotifyMethod::Both => Route::Toast { both: true },
    }
}

/// D-12: sound off silences every toast; sound on keeps info / success silent.
fn toast_sound(prefs: &NotificationPrefs, level: Level) -> bool {
    prefs.sound && matches!(level, Level::Warn | Level::Error)
}

/// Remembers the last delivered title + body.
#[derive(Debug, Default)]
struct Coalescer {
    last: Option<(Msg, Option<Msg>, Instant)>,
}

impl Coalescer {
    /// `false` = the same title and body were delivered less than [`COALESCE`] ago. A dropped
    /// duplicate does not extend the window.
    fn admit(&mut self, notice: &Notice, now: Instant) -> bool {
        if let Some((title, body, at)) = &self.last
            && *title == notice.title
            && *body == notice.body
            && now.saturating_duration_since(*at) < COALESCE
        {
            return false;
        }
        self.last = Some((notice.title.clone(), notice.body.clone(), now));
        true
    }
}

/// Shows toasts one at a time; reads Windows' setting at most every [`OS_STATE_TTL`].
fn toast_worker(
    jobs: mpsc::Receiver<Job>,
    inapp: broadcast::Sender<InAppNotice>,
    activate: Arc<OnceLock<OnActivate>>,
) {
    let aumid = toast::app_aumid();
    let mut cached: Option<(Instant, Option<NotifySetting>)> = None;
    for job in jobs {
        let setting = match cached {
            Some((read_at, setting)) if read_at.elapsed() < OS_STATE_TTL => setting,
            _ => {
                let setting = toast::notification_setting(aumid)
                    .inspect_err(|err| tracing::warn!(%err, "notification setting unreadable"))
                    .ok();
                cached = Some((Instant::now(), setting));
                setting
            }
        };
        let popup = match setting {
            // Windows blocks our toasts: the window is the only place left.
            Some(setting) if !setting.allows_toasts() => true,
            _ => match toast::show(aumid, &job.toast, activate.get().cloned()) {
                // Unregistered (no toast seen yet, no Start-menu link) or unreadable: the toast
                // may be swallowed silently, so the window shows it too.
                Ok(()) => job.both || setting != Some(NotifySetting::Enabled),
                Err(err) => {
                    tracing::warn!(%err, "toast failed; shown in the window");
                    true
                }
            },
        };
        let _ = inapp.send(InAppNotice {
            notice: job.notice,
            category: job.category,
            at: job.at,
            popup,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(title: &'static str, body: Option<&'static str>) -> Notice {
        let notice = Notice::new(Level::Warn, title);
        match body {
            Some(body) => notice.body(body),
            None => notice,
        }
    }

    /// lifecycle-app §3.18: identical title + body within 1.5 s are delivered once.
    #[test]
    fn coalesces_identical_notices_within_the_window() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        let crash = notice("tunnel.crash.title", Some("tunnel.crash.body"));
        assert!(c.admit(&crash, t0));
        assert!(!c.admit(&crash, t0 + Duration::from_millis(1499)));
        assert!(c.admit(&crash, t0 + COALESCE));
    }

    /// A dropped duplicate does not extend the window: it is measured from the last delivery.
    #[test]
    fn a_dropped_duplicate_does_not_extend_the_window() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        let crash = notice("a", Some("b"));
        assert!(c.admit(&crash, t0));
        assert!(!c.admit(&crash, t0 + Duration::from_millis(1000)));
        assert!(c.admit(&crash, t0 + Duration::from_millis(1600)));
    }

    /// Coalescing keys on title AND body (and their arguments); only the last delivery counts.
    #[test]
    fn different_title_body_or_arguments_are_delivered() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        assert!(c.admit(&notice("a", Some("b")), t0));
        assert!(c.admit(&notice("a", Some("c")), t0));
        assert!(c.admit(&notice("a", None), t0));
        assert!(c.admit(&notice("x", None), t0));
        let one = Notice::new(Level::Warn, Msg::new("n").arg("attempt", 1));
        let two = Notice::new(Level::Warn, Msg::new("n").arg("attempt", 2));
        assert!(c.admit(&one, t0));
        assert!(c.admit(&two, t0));
        // "a" was delivered before "x": it is not the last one any more.
        assert!(c.admit(&notice("a", Some("b")), t0));
    }

    /// AT-00-004 subset (§7.7) under owner decision D-12: switches decide only the OS toast.
    #[test]
    fn delivery_follows_the_preferences() {
        let mut prefs = NotificationPrefs::default();
        let connect = Some(NoticeCategory::VpnConnect);
        assert_eq!(route(true, &prefs, connect), Route::Toast { both: false });
        assert_eq!(route(false, &prefs, connect), Route::ListOnly);
        assert_eq!(route(false, &prefs, None), Route::ListOnly);
        prefs.vpn_connect = false;
        assert_eq!(route(true, &prefs, connect), Route::ListOnly);
        assert_eq!(
            route(true, &prefs, Some(NoticeCategory::VpnDisconnect)),
            Route::Toast { both: false }
        );
        prefs.method = NotifyMethod::InApp;
        assert_eq!(
            route(true, &prefs, Some(NoticeCategory::LeakDetected)),
            Route::InApp
        );
        // Uncategorised notices ignore the per-category method and switches.
        assert_eq!(route(true, &prefs, None), Route::Toast { both: false });
        prefs.method = NotifyMethod::Both;
        assert_eq!(
            route(true, &prefs, Some(NoticeCategory::ConnectionError)),
            Route::Toast { both: true }
        );
    }

    /// D-12: sound off silences every toast; sound on keeps info / success silent.
    #[test]
    fn toast_sound_follows_level_and_preference() {
        let mut prefs = NotificationPrefs::default();
        assert!(toast_sound(&prefs, Level::Error));
        assert!(toast_sound(&prefs, Level::Warn));
        assert!(!toast_sound(&prefs, Level::Info));
        assert!(!toast_sound(&prefs, Level::Success));
        prefs.sound = false;
        assert!(!toast_sound(&prefs, Level::Error));
    }

    /// Every notice reaches the in-app list; with desktop notifications off it is not popped up,
    /// and a duplicate within the window is dropped entirely (no toast path is exercised).
    #[test]
    fn notices_reach_the_in_app_list() {
        let dir =
            std::env::temp_dir().join(format!("vpnte-app-base-notify-{}", std::process::id()));
        let settings = Arc::new(Store::<Settings>::open(&dir));
        settings
            .update(|s| {
                s.desktop_notifications = false;
                s.notifications.method = NotifyMethod::InApp;
            })
            .unwrap();
        let notifier = Notifier::new(settings.clone()).unwrap();
        let mut list = notifier.subscribe();
        let crash = notice("t.crash", Some("t.body"));
        notifier.notify(crash.clone(), Some(NoticeCategory::ConnectionError));
        notifier.notify(crash.clone(), Some(NoticeCategory::ConnectionError));
        let first = list.try_recv().unwrap();
        assert_eq!((first.notice, first.popup), (crash, false));
        assert!(list.try_recv().is_err(), "the duplicate was coalesced");

        settings.update(|s| s.desktop_notifications = true).unwrap();
        notifier.notify(notice("t.other", None), Some(NoticeCategory::VpnConnect));
        let second = list.try_recv().unwrap();
        assert!(second.popup, "method in-app pops it up in the window");
        assert_eq!(second.category, Some(NoticeCategory::VpnConnect));
        drop(notifier);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lifecycle_kinds_map_to_their_categories() {
        assert_eq!(
            NoticeCategory::from(NoticeKind::VpnConnect),
            NoticeCategory::VpnConnect
        );
        assert_eq!(
            NoticeCategory::from(NoticeKind::ProfileRotation),
            NoticeCategory::ProfileRotation
        );
        let prefs = NotificationPrefs {
            schedule_triggered: false,
            ..Default::default()
        };
        assert!(!NoticeCategory::ScheduleTriggered.enabled(&prefs));
        assert!(NoticeCategory::ConnectionError.enabled(&prefs));
    }
}
