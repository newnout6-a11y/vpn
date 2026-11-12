//! Toasts from an unpackaged exe: the process AUMID, the Start-menu shortcut that makes the AUMID
//! known to the shell (Windows drops toasts for unknown AUMIDs, and the taskbar button takes its
//! icon and name from that shortcut), the WinRT toast itself, and the user's toast setting.
mod block;
mod shortcut;

use std::sync::{Arc, Once};

pub use block::{LEGACY_AUMIDS, ResetReport, reset_os_block};
pub use shortcut::{
    Shortcut, common_programs_dir, ensure_shortcut, read_shortcut, remove_hijacking_dev_shortcut,
    remove_shortcut, user_programs_dir,
};
use vpnte_base::{AppError, AppResult};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{
    NotificationSetting, ToastNotification, ToastNotificationManager,
};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::System::Com::{CoIncrementMTAUsage, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    GetCurrentProcessExplicitAppUserModelID, SetCurrentProcessExplicitAppUserModelID,
};
use windows::core::HSTRING;

/// AUMID of the installed app (taskbar grouping, toasts, Start-menu shortcut).
pub const AUMID: &str = "com.vpntunnelenforcer.app";
/// AUMID of debug builds, tests and demos: they must never touch the installed app's identity
/// (a dev shortcut that owned the production AUMID once gave the taskbar button a foreign icon).
pub const DEV_AUMID: &str = "com.vpntunnelenforcer.app.dev";

/// The AUMID this build uses: the production one only in release builds.
pub fn app_aumid() -> &'static str {
    if cfg!(debug_assertions) {
        DEV_AUMID
    } else {
        AUMID
    }
}

/// Sets the process AUMID. Call before any window exists, or the taskbar groups by exe path.
pub fn set_process_aumid(aumid: &str) -> AppResult<()> {
    // SAFETY: plain call with a valid string.
    unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(aumid)) }
        .map_err(AppError::internal)
}

/// The AUMID set on this process, if any.
pub fn process_aumid() -> Option<String> {
    // SAFETY: on success the string is CoTaskMem-allocated and owned by us; freed after copying.
    unsafe {
        let p = GetCurrentProcessExplicitAppUserModelID().ok()?;
        let aumid = p.to_string().ok();
        CoTaskMemFree(Some(p.0.cast_const().cast()));
        aumid
    }
}

/// One toast, already rendered in the UI language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// First (bold) line.
    pub title: String,
    /// Second line.
    pub body: String,
    /// `false` silences the toast whatever its level (decided: "sound off" means all).
    pub sound: bool,
}

/// Run when the user clicks the toast while it is on screen (the app shows its window).
pub type OnActivate = Arc<dyn Fn() + Send + Sync>;

/// Shows `toast` attributed to `aumid`. Blocking WinRT calls: run it off the UI thread.
pub fn show(aumid: &str, toast: &Toast, on_activate: Option<OnActivate>) -> AppResult<()> {
    hold_mta();
    show_inner(aumid, toast, on_activate).map_err(AppError::internal)
}

/// Holds one usage of the COM multithreaded apartment for the life of the process (once), before
/// any WinRT toast call. Callers reach these functions from threads that never initialise COM
/// (a toast thread, the blocking pool): they run in the implicit MTA, and windows-rs caches each
/// activation factory. When other code that joined the MTA explicitly leaves it last, COM tears
/// the MTA down and unloads the toast DLL under the cached factory, and the next toast jumps into
/// unmapped code (an access violation in `wpnapps.dll`, seen in the app review).
fn hold_mta() {
    static HELD: Once = Once::new();
    HELD.call_once(|| {
        // SAFETY: no arguments; the cookie is deliberately never released.
        if let Err(err) = unsafe { CoIncrementMTAUsage() } {
            tracing::warn!(%err, "COM multithreaded apartment not held");
        }
    });
}

fn show_inner(
    aumid: &str,
    toast: &Toast,
    on_activate: Option<OnActivate>,
) -> windows::core::Result<()> {
    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(toast_xml(toast)))?;
    let notification = ToastNotification::CreateToastNotification(&doc)?;
    if let Some(on_activate) = on_activate {
        notification.Activated(&TypedEventHandler::new(move |_, _| {
            on_activate();
            Ok(())
        }))?;
    }
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))?.Show(&notification)
}

fn toast_xml(toast: &Toast) -> String {
    let audio = if toast.sound {
        ""
    } else {
        r#"<audio silent="true"/>"#
    };
    format!(
        r#"<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual>{audio}</toast>"#,
        xml_escape(&toast.title),
        xml_escape(&toast.body)
    )
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Whether Windows lets `aumid` show toasts (per-app switch, global switch, policy, manifest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifySetting {
    /// Toasts are shown.
    Enabled,
    /// Windows has not seen a toast from this AUMID yet ("element not found" until the first
    /// one is shown). Not a block, but also what a missing Start-menu link looks like: the
    /// notifier treats it as "unknown" (toast plus in-app copy, spec §3.18).
    Unregistered,
    /// The user turned this app off (the registry reset can undo it).
    DisabledForApplication,
    /// The user turned all notifications off.
    DisabledForUser,
    /// A group policy forbids toasts.
    DisabledByGroupPolicy,
    /// The app manifest disallows toasts (packaged apps only).
    DisabledByManifest,
}

impl NotifySetting {
    /// `true` when no setting blocks a toast shown now (delivery is certain only for `Enabled`).
    pub fn allows_toasts(self) -> bool {
        matches!(self, NotifySetting::Enabled | NotifySetting::Unregistered)
    }
}

/// The toast setting for `aumid`, read from `ToastNotifier::Setting` (the exact OS view).
pub fn notification_setting(aumid: &str) -> AppResult<NotifySetting> {
    hold_mta();
    setting_from(
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))
            .and_then(|notifier| notifier.Setting()),
    )
}

fn setting_from(read: windows::core::Result<NotificationSetting>) -> AppResult<NotifySetting> {
    match read {
        Ok(NotificationSetting::Enabled) => Ok(NotifySetting::Enabled),
        Ok(NotificationSetting::DisabledForApplication) => {
            Ok(NotifySetting::DisabledForApplication)
        }
        Ok(NotificationSetting::DisabledForUser) => Ok(NotifySetting::DisabledForUser),
        Ok(NotificationSetting::DisabledByGroupPolicy) => Ok(NotifySetting::DisabledByGroupPolicy),
        Ok(NotificationSetting::DisabledByManifest) => Ok(NotifySetting::DisabledByManifest),
        Ok(other) => Err(AppError::internal(std::io::Error::other(format!(
            "unknown notification setting {}",
            other.0
        )))),
        Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(NotifySetting::Unregistered),
        Err(e) => Err(AppError::internal(e)),
    }
}

/// `true` when no setting blocks toasts of `aumid` (see [`NotifySetting::allows_toasts`]).
pub fn notifications_enabled(aumid: &str) -> AppResult<bool> {
    notification_setting(aumid).map(NotifySetting::allows_toasts)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn toast(sound: bool) -> Toast {
        Toast {
            title: "Защита включена".into(),
            body: r#"<b>"A & B"</b> it's"#.into(),
            sound,
        }
    }

    /// Title and body are escaped; `sound: false` adds a silent audio element.
    #[test]
    fn toast_xml_escapes_and_honours_sound() {
        let xml = toast_xml(&toast(false));
        assert!(xml.contains("<text>Защита включена</text>"));
        assert!(xml.contains("<text>&lt;b&gt;&quot;A &amp; B&quot;&lt;/b&gt; it&apos;s</text>"));
        assert!(xml.ends_with(r#"<audio silent="true"/></toast>"#));
        assert!(!toast_xml(&toast(true)).contains("<audio"));
        // The document must parse as the toast schema expects.
        let doc = XmlDocument::new().unwrap();
        doc.LoadXml(&HSTRING::from(xml)).unwrap();
    }

    /// Debug builds (tests included) never use the installed app's identity.
    #[test]
    fn debug_builds_use_the_dev_aumid() {
        assert_eq!(app_aumid(), DEV_AUMID);
    }

    #[test]
    fn process_aumid_round_trips() {
        set_process_aumid(DEV_AUMID).unwrap();
        assert_eq!(process_aumid().as_deref(), Some(DEV_AUMID));
    }

    /// Observed on Windows 11: `Setting()` fails with 0x80070490 until the first toast of an
    /// AUMID was shown. That is "not registered yet", never a block; other failures stay errors.
    #[test]
    fn setting_maps_os_values_and_unregistered() {
        let ok = |s| setting_from(Ok(s)).unwrap();
        assert_eq!(ok(NotificationSetting::Enabled), NotifySetting::Enabled);
        assert_eq!(
            ok(NotificationSetting::DisabledForApplication),
            NotifySetting::DisabledForApplication
        );
        assert_eq!(
            ok(NotificationSetting::DisabledForUser),
            NotifySetting::DisabledForUser
        );
        let unregistered = setting_from(Err(ERROR_NOT_FOUND.to_hresult().into())).unwrap();
        assert_eq!(unregistered, NotifySetting::Unregistered);
        assert!(unregistered.allows_toasts());
        assert!(!NotifySetting::DisabledByGroupPolicy.allows_toasts());
        let err = setting_from(Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_ACCESSDENIED,
        )))
        .unwrap_err();
        assert_eq!(err.kind, vpnte_base::ErrorKind::Internal);
        assert!(setting_from(Ok(NotificationSetting(42))).is_err());
    }

    /// Removes the test shortcut and our Action Center entries even when an assertion fails.
    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(history) = ToastNotificationManager::History() {
                let _ = history.ClearWithId(&HSTRING::from(DEV_AUMID));
            }
            let _ = remove_shortcut(&self.0);
        }
    }

    /// End to end with the dev AUMID: shortcut in the real Start menu, setting, one toast,
    /// then the shortcut and our Action Center entries are removed again.
    #[test]
    #[ignore = "shows a real toast and adds / removes a Start-menu shortcut"]
    fn real_toast_with_the_dev_aumid() {
        let link = user_programs_dir()
            .unwrap()
            .join("VPN Tunnel Enforcer (dev test).lnk");
        let cleanup = Cleanup(link.clone());
        let shortcut = Shortcut {
            aumid: DEV_AUMID.into(),
            target: std::env::current_exe().unwrap(),
            args: String::new(),
            description: "VPN Tunnel Enforcer test".into(),
        };
        ensure_shortcut(&link, &shortcut).unwrap();
        show(DEV_AUMID, &toast(false), None).unwrap();
        // The first toast registers the AUMID with the notification platform.
        let started = std::time::Instant::now();
        let setting = loop {
            match notification_setting(DEV_AUMID).unwrap() {
                NotifySetting::Unregistered if started.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                setting => break setting,
            }
        };
        assert_eq!(setting, NotifySetting::Enabled);
        std::thread::sleep(Duration::from_secs(1));
        let delivered = ToastNotificationManager::History()
            .and_then(|h| h.GetHistoryWithId(&HSTRING::from(DEV_AUMID)))
            .and_then(|h| h.Size())
            .unwrap();
        assert!(delivered >= 1);
        drop(cleanup);
        assert!(!link.exists());
    }
}
