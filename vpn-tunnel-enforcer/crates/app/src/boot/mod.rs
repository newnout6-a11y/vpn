//! Process start and end without Dioxus (work package `app-main`): the WebView2 environment of an
//! elevated run, the panic hook, the single instance, the app identity (AUMID), autostart sync,
//! start-up failure boxes, power events and the exit codes. The app never runs elevated on purpose
//! and never relaunches itself elevated (NOADMIN §0): `--no-elevate` / `--elevated-relaunch` are
//! accepted and mean nothing.
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{Level, Notice};
use vpnte_base::{AppError, Msg};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_winnet::power::{PowerEvent, PowerMonitor};
use vpnte_winnet::single_instance::{self, Acquire, Command, InstanceNames, Primary};

use crate::args::Args;
use crate::services::TunnelOps;
use crate::svc_core::notify::{NoticeCategory, Notifier};

/// Exit code that acknowledges `--shutdown-for-update` to the installer; no other path uses it.
pub const EXIT_UPDATE_ACK: u8 = 73;
/// Exit code of a start that failed before the window existed (a message box said why).
pub const EXIT_START_FAILED: u8 = 1;
/// How long a second launch waits for the running instance's pipe (it may still be starting).
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Removes the variables that redirect WebView2 when this process happens to be elevated
/// (development, CI): an elevated WebView2 must not honour another user's overrides. The shipped
/// app runs unelevated and keeps them (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` attaches CDP).
///
/// # Safety
/// Call as the first statement of `main`, before any other thread exists.
pub unsafe fn scrub_elevated_env() {
    if vpnte_winnet::elevation::is_elevated() {
        // SAFETY: the caller guarantees that no other thread exists yet.
        unsafe { vpnte_ui::launch::scrub_webview2_env() };
    }
}

/// Set by the panic hook for every panic off the UI thread, read by [`report_backend_panics`].
static BACKEND_PANICS: Notify = Notify::const_new();

/// Installs the app's panic hook. `svc_core::build` later puts the log's hook in front of it
/// (the panic is logged and flushed first). A panic on the UI thread is Dioxus' to handle (a
/// failed render becomes the page's error view; anything else ends the event loop); a panic on a
/// backend thread ends that task while the app goes on, so the user is told that the protection
/// state is no longer proven (lifecycle-app A-01).
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() != Some("main") {
            // Never blocks or allocates: safe whatever the panicking thread held.
            BACKEND_PANICS.notify_one();
        }
        previous(info);
    }));
}

/// Turns backend panics into one error notice each (the notifier coalesces bursts) until
/// `cancel` fires. Runs inside the tokio runtime.
pub async fn report_backend_panics(notifier: Arc<Notifier>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            () = BACKEND_PANICS.notified() => notifier.notify(
                Notice::new(Level::Error, Msg::new("app.main.internalError")),
                Some(NoticeCategory::ConnectionError),
            ),
        }
    }
}

/// What the single-instance check decided.
pub enum Instance {
    /// This process is the only instance: keep the guard for the life of the process.
    Primary(Primary),
    /// Exit at once with this code, touching nothing (lifecycle-app §3.7).
    Exit(ExitCode),
}

/// The single-instance check, before anything touches the data dir or the network. The lock is
/// per Windows session (owner decision 12): each signed-in user runs their own copy. A second
/// launch in the session hands `activate`, its link (`--open-link`) or `shutdown-for-update` to
/// the running instance and exits `0` silently (installer contract); a link the running copy did
/// not take is reported in a short box. `--shutdown-for-update` without a running instance starts
/// nothing; a link without one starts the app with it.
pub fn single_instance(args: &Args) -> Instance {
    match InstanceNames::production() {
        Ok(names) => single_instance_with(&names, args, link_not_taken),
        Err(err) => refuse_start(&err),
    }
}

fn single_instance_with(names: &InstanceNames, args: &Args, link_lost: impl FnOnce()) -> Instance {
    let command = match (&args.open_link, args.shutdown_for_update) {
        (_, true) => Command::ShutdownForUpdate,
        (Some(link), false) => Command::OpenLink(link.clone()),
        (None, false) => Command::Activate,
    };
    match single_instance::acquire(names) {
        Ok(Acquire::Primary(primary)) if command != Command::ShutdownForUpdate => {
            Instance::Primary(primary)
        }
        Ok(Acquire::Primary(_)) => Instance::Exit(ExitCode::SUCCESS),
        Ok(Acquire::Secondary) => {
            // No log exists yet (it belongs to the running instance). A link the running copy did
            // not take (it has no pipe, the pipe is not ours, the link is too long) is not retried
            // as a bare activation: a window without it would look like it was imported. The
            // user is told instead, so a clicked link never ends in nothing.
            let link = matches!(command, Command::OpenLink(_));
            if single_instance::send(&names.pipe, command, HANDOFF_TIMEOUT).is_err() && link {
                link_lost();
            }
            Instance::Exit(ExitCode::SUCCESS)
        }
        // An unexpected mutex failure: running unguarded could let two instances fight over
        // the same system proxy, so refuse to start.
        Err(err) => refuse_start(&err),
    }
}

/// The running copy did not take a clicked link: say so and how to add it by hand.
fn link_not_taken() {
    use windows::Win32::UI::WindowsAndMessaging::MB_ICONINFORMATION;
    let lang = vpnte_ui::lang::os_lang();
    message_box(
        &[Msg::new("app.phones.linkNotTaken")],
        lang,
        MB_ICONINFORMATION,
    );
}

fn refuse_start(err: &AppError) -> Instance {
    start_failed(err, vpnte_ui::lang::os_lang());
    Instance::Exit(ExitCode::from(EXIT_START_FAILED))
}

/// Gives the process its AppUserModelID before any window or toast exists (lifecycle-app §3.6):
/// the production id in release builds, the `.dev` id in debug builds, so a development run never
/// takes over the installed app's taskbar button or notification settings.
pub fn set_identity() {
    let aumid = vpnte_winnet::toast::app_aumid();
    match vpnte_winnet::toast::set_process_aumid(aumid) {
        Ok(()) => tracing::info!(aumid, "app identity set"),
        Err(err) => tracing::warn!(%err, aumid, "app identity not set"),
    }
}

/// Start-up chores of a shipped (release) build, on their own thread so the window never waits:
/// the per-user autostart `Run` value follows the setting (re-pointed at this exe; the 1.x logon
/// task goes), the link schemes are registered on this user's first start (later: ours re-pointed
/// at this exe), and a stale dev `Electron.lnk` that hijacks the taskbar identity is removed
/// (lifecycle-app §3.16, §3.24). A debug build skips all three: its exe is a build artifact, and
/// a development run must not rewrite the user's real `Run` value, link schemes or Start menu.
pub fn spawn_housekeeping(settings: &Store<Settings>) {
    if cfg!(debug_assertions) {
        tracing::info!(
            "autostart sync, link schemes and taskbar identity heal skipped in a debug build"
        );
        return;
    }
    let enabled = settings.read(|s| s.autostart);
    let spawned = std::thread::Builder::new()
        .name("housekeeping".into())
        .spawn(move || {
            sync_autostart(enabled);
            crate::setup::links::sync_at_start();
            heal_taskbar_identity();
        });
    if let Err(err) = spawned {
        tracing::warn!(%err, "start-up housekeeping not started");
    }
}

fn sync_autostart(enabled: bool) {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            tracing::warn!(%err, "autostart not synced: own path unknown");
            return;
        }
    };
    match vpnte_winnet::autostart::sync(&vpnte_winnet::autostart::RunValue { exe }, enabled) {
        Ok(acted) => tracing::info!(enabled, acted, "autostart synced"),
        Err(err) => tracing::warn!(%err, enabled, "autostart sync failed"),
    }
}

fn heal_taskbar_identity() {
    let removed = vpnte_winnet::toast::user_programs_dir()
        .and_then(|dir| vpnte_winnet::toast::remove_hijacking_dev_shortcut(&dir));
    match removed {
        Ok(true) => tracing::info!("stale dev Electron shortcut removed (taskbar identity)"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "taskbar identity check failed"),
    }
}

/// Forwards wake and unlock to the tunnel until `cancel` fires. The theme follows the OS through
/// the window itself, so `ThemeChanged` needs nothing here. Without its event window the app runs
/// on without these events (logged). Runs inside the tokio runtime.
pub fn spawn_power_events(tunnel: Arc<dyn TunnelOps>, cancel: CancellationToken) {
    let monitor = match PowerMonitor::start() {
        Ok(monitor) => monitor,
        Err(err) => {
            tracing::warn!(%err, "power events unavailable");
            return;
        }
    };
    let mut events = monitor.subscribe();
    tokio::spawn(async move {
        // Owned by the task: its window closes when the forwarding ends.
        let _monitor = monitor;
        loop {
            let event = tokio::select! {
                () = cancel.cancelled() => return,
                event = events.recv() => event,
            };
            match event {
                Ok(event @ (PowerEvent::Resumed | PowerEvent::SessionUnlocked)) => {
                    tracing::info!(?event, "system resumed");
                    tunnel.resumed();
                }
                Ok(PowerEvent::ThemeChanged { .. }) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            }
        }
    });
}

/// The box shown instead of a window when the start failed: what happened, the reason, and that
/// the saved data was left alone (lifecycle-app §3.12b).
pub fn start_failed(err: &AppError, lang: Lang) {
    tracing::error!(error = %err, "start-up failed; saved configuration retained");
    let text = [
        Msg::new("app.main.startFailed.title"),
        Msg::new("app.main.startFailed.message"),
        err.user_msg(),
    ];
    message_box(
        &text,
        lang,
        windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
    );
}

/// Ends the process with `code` now. The caller has run the bounded cleanup (which drained the
/// log); engines die with their kill-on-close job.
pub fn exit(code: u8) -> ! {
    std::process::exit(i32::from(code))
}

/// A blocking box for a launch that has no window: `lines` rendered in `lang` as paragraphs,
/// under the product name.
fn message_box(
    lines: &[Msg],
    lang: Lang,
    icon: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MB_SETFOREGROUND, MessageBoxW};
    // Idempotent: the window path registers the same layers before launch.
    vpnte_ui::lang::init_locales(&crate::svc_core::locale_layers());
    let text: Vec<String> = lines.iter().map(|line| line.render(lang)).collect();
    let text = windows::core::HSTRING::from(text.join("\n\n"));
    let caption = windows::core::HSTRING::from(vpnte_ui::launch::APP_NAME);
    // SAFETY: both strings are NUL-terminated HSTRINGs that outlive the call; no owner window.
    unsafe { MessageBoxW(None, &text, &caption, MB_OK | icon | MB_SETFOREGROUND) };
}

#[cfg(test)]
mod tests;
