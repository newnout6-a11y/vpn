//! The application (work package `app-main`): [`run`] wires the backend into the Dioxus shell
//! (bootstrap order of lifecycle-app §3.12 / §6.5 and `SERVICES.md`), and [`App`] is the root
//! component: tray, shell with the pages of this build, first-run wizard, toasts fed by the
//! backend's notices, commands of later launches and toast clicks.
use std::any::Any;
use std::cell::RefCell;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::Arc;

use dioxus::desktop::{DesktopContext, use_window};
use dioxus::prelude::*;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use vpnte_base::types::{Level, Notice};
use vpnte_core::paths::DataDirs;
use vpnte_ui::lang::tr_now;
use vpnte_ui::launch::LaunchOptions;
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;
use vpnte_ui::tray::{QuitMode, TrayApi, TrayHost, hide_to_tray, show_window};
use vpnte_ui::widgets::{ToastHost, ToastKind, Toasts};
use vpnte_winnet::single_instance::Command;

use crate::args::Args;
use crate::boot::{self, Instance};
use crate::services::Backend;
use crate::svc_core::notify::InAppNotice;
use crate::{
    api_dashboard, api_lists, api_maintenance, api_servers, api_settings, api_tools, svc_core,
    svc_tunnel,
};

/// The whole application. Returns only on the paths that end without a window (installer
/// helpers, a second launch, a failed start); otherwise the UI ends the process: `0` after the
/// tray's quit cleanup, `73` after the installer's `--shutdown-for-update`.
pub fn run(args: &Args) -> ExitCode {
    if let Some(code) = crate::setup::run(args) {
        return code;
    }
    boot::install_panic_hook();
    // Held (never dropped) for the life of the process: `launch` does not return.
    let mut primary = match boot::single_instance(args) {
        Instance::Primary(primary) => primary,
        Instance::Exit(code) => return code,
    };
    // One registration for the whole app: `svc_core::locale_layers` carries every crate's layers and
    // every app package's fragments, so no package has to chain another package's list. The first
    // registration wins, so this must stay the only call.
    vpnte_ui::lang::init_locales(&svc_core::locale_layers());
    let backend = match svc_core::build(args) {
        Ok(backend) => backend,
        Err(err) => {
            boot::start_failed(&err, vpnte_ui::lang::os_lang());
            return ExitCode::from(boot::EXIT_START_FAILED);
        }
    };
    boot::set_identity();
    boot::spawn_housekeeping(&backend.settings);
    let options = launch_options(&backend, args);
    let wiring = Wiring::new(backend, primary.take_commands());
    vpnte_ui::launch::launch(options, App, move || contexts(wiring))
}

/// What [`App`] takes over from [`run`] (one root context). The receivers are taken once by the
/// root's pumps; the notice list is subscribed before the window exists, so notices of the
/// tunnel's start-up recovery are not lost.
struct Wiring {
    backend: Arc<Backend>,
    /// Commands of later launches (`activate`, `shutdown-for-update`).
    commands: RefCell<Option<mpsc::UnboundedReceiver<Command>>>,
    /// The notifier's in-app list.
    notices: RefCell<Option<broadcast::Receiver<InAppNotice>>>,
    /// Clicks on a Windows toast while it is on screen.
    activations: RefCell<Option<mpsc::UnboundedReceiver<()>>>,
}

impl Wiring {
    fn new(backend: Arc<Backend>, commands: Option<mpsc::UnboundedReceiver<Command>>) -> Self {
        let (tx, activations) = mpsc::unbounded_channel();
        // The notifier calls this on its toast thread: hand the click to the UI thread.
        backend.notifier.set_on_activate(Arc::new(move || {
            let _ = tx.send(());
        }));
        Wiring {
            notices: RefCell::new(Some(backend.notifier.subscribe())),
            commands: RefCell::new(commands),
            activations: RefCell::new(Some(activations)),
            backend,
        }
    }
}

/// The root contexts, built inside the UI's tokio runtime: the tunnel first (every API reads
/// it), the background tasks this package owns, then the contexts of every `api_*` module and
/// the root's own wiring.
fn contexts(wiring: Wiring) -> Vec<Box<dyn Any>> {
    let backend = wiring.backend.clone();
    match svc_tunnel::build(&backend) {
        Ok(tunnel) => {
            let _ = backend.tunnel.set(tunnel.clone());
            boot::spawn_power_events(tunnel, backend.shutdown.child_token());
        }
        Err(err) => {
            boot::start_failed(&err, vpnte_ui::lang::os_lang());
            drop(backend.log.lock().take());
            boot::exit(boot::EXIT_START_FAILED);
        }
    }
    drop(
        backend
            .servers
            .spawn_scheduler(backend.refresh.clone(), backend.shutdown.child_token()),
    );
    tokio::spawn(boot::report_backend_panics(
        backend.notifier.clone(),
        backend.shutdown.child_token(),
    ));
    let mut out = api_dashboard::contexts(&backend);
    out.extend(api_servers::contexts(&backend));
    out.extend(api_settings::contexts(&backend));
    out.extend(api_maintenance::contexts(&backend));
    out.extend(api_tools::contexts(&backend));
    out.extend(api_lists::contexts(&backend));
    out.push(Box::new(Rc::new(wiring)));
    out
}

/// The first frame: the saved language (else Windows'), the saved theme, hidden in the tray for
/// an autostart with «Сворачивать в трей» (lifecycle-app §6.5).
fn launch_options(backend: &Backend, args: &Args) -> LaunchOptions {
    let settings = backend.settings.snapshot();
    let defaults = LaunchOptions::default();
    LaunchOptions {
        lang: settings.locale.unwrap_or_else(vpnte_ui::lang::os_lang),
        theme: backend
            .themes
            .read(|themes| themes.theme(&settings.active_theme_id)),
        start_hidden: args.autostart && settings.minimize_to_tray,
        data_dir: webview_dir(
            &backend.dirs,
            std::env::var_os("VPNTE_DATA_DIR").is_some(),
            backend.elevated,
            defaults.data_dir.clone(),
        ),
        ..defaults
    }
}

/// The WebView2 user-data folder: the local default (`%LOCALAPPDATA%\VPN Tunnel
/// Enforcer\WebView2`); inside the data dir's cache when that dir is overridden (tests, CI), so
/// such a run leaves nothing in the user's profile; a folder of its own when elevated (WebView2
/// refuses to share a browser process across elevation levels).
fn webview_dir(dirs: &DataDirs, overridden: bool, elevated: bool, default: PathBuf) -> PathBuf {
    let dir = if overridden {
        dirs.cache.join("WebView2")
    } else {
        default
    };
    if elevated {
        dir.with_file_name("WebView2.elevated")
    } else {
        dir
    }
}

/// The root component: the tray around the shell, the pages wired in this build (every other
/// page stays unregistered and shows the shell's neutral placeholder), the wizard overlay and the
/// toast host.
#[component]
pub fn App() -> Element {
    let wiring = use_context::<Rc<Wiring>>();
    let toasts = Toasts::use_provider();
    let advanced = use_advanced(&wiring.backend);
    let registry = use_hook(registry);
    use_notices(&wiring, toasts);
    use_instance_commands(&wiring);
    use_toast_clicks(&wiring);
    rsx! {
        TrayHost {
            Shell {
                version: env!("CARGO_PKG_VERSION"),
                advanced,
                registry,
                overlays: rsx! {
                    vpnte_ui::wizard::Wizard {}
                },
                toasts: rsx! {
                    ToastHost { close_label: t!("common.close") }
                },
            }
        }
    }
}

/// The pages wired to the backend.
fn registry() -> PageRegistry {
    let mut registry = PageRegistry::new();
    registry
        .register(Page::Dashboard, vpnte_ui::dashboard::Dashboard)
        .register(Page::Servers, vpnte_ui::servers::ServersPage)
        .register(Page::Settings, vpnte_ui::settings::SettingsPage)
        .register(Page::Logs, vpnte_ui::logs::LogsPage);
    registry
        .register(Page::SpeedTest, vpnte_ui::speedtest::SpeedTestPage)
        .register(Page::Availability, vpnte_ui::availability::AvailabilityPage);
    registry
        .register(Page::Apps, vpnte_ui::split_tunnel::SplitTunnelPage)
        .register(
            Page::TrafficHistory,
            vpnte_ui::traffic_history::TrafficHistoryPage,
        )
        .register(Page::Schedule, vpnte_ui::schedule::SchedulePage);
    // Advanced mode only: the shell offers the page while `advanced` is on.
    registry.register(Page::Maintenance, vpnte_ui::maintenance::MaintenancePage);
    registry
}

/// The saved advanced mode, followed live (the shell shows the Repair entry only with it on).
fn use_advanced(backend: &Arc<Backend>) -> Signal<bool> {
    let settings = backend.settings.clone();
    let mut advanced = use_signal(|| settings.read(|s| s.advanced_mode));
    use_future(move || {
        let settings = settings.clone();
        async move {
            let mut changes = settings.subscribe();
            while changes.changed().await.is_ok() {
                let on = settings.read(|s| s.advanced_mode);
                if *advanced.peek() != on {
                    advanced.set(on);
                }
            }
        }
    });
    advanced
}

/// Backend notices marked `popup` become in-app toasts (the notifier already logged them and
/// chose between a Windows toast and the window, owner decision D-12).
fn use_notices(wiring: &Rc<Wiring>, toasts: Toasts) {
    let wiring = wiring.clone();
    use_future(move || {
        let list = wiring.notices.borrow_mut().take();
        async move {
            let Some(mut list) = list else { return };
            loop {
                match list.recv().await {
                    Ok(item) if item.popup => show_notice(toasts, &item.notice),
                    Ok(_) => {}
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "in-app notices dropped (window busy)");
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        }
    });
}

fn show_notice(toasts: Toasts, notice: &Notice) {
    let kind = match notice.level {
        Level::Info => ToastKind::Info,
        Level::Success => ToastKind::Success,
        Level::Warn => ToastKind::Warning,
        Level::Error => ToastKind::Error,
    };
    toasts.push(
        kind,
        tr_now(&notice.title),
        notice.body.as_ref().map(tr_now),
    );
}

/// Commands of later launches: `activate` shows the window; the installer's
/// `shutdown-for-update` runs the quit cleanup without a question and exits with 73.
fn use_instance_commands(wiring: &Rc<Wiring>) {
    let wiring = wiring.clone();
    let tray = use_context::<Rc<dyn TrayApi>>();
    let desktop = use_window();
    use_future(move || {
        let commands = wiring.commands.borrow_mut().take();
        let (tray, desktop) = (tray.clone(), desktop.clone());
        async move {
            let Some(mut commands) = commands else { return };
            let mut updating = false;
            while let Some(command) = commands.recv().await {
                match command {
                    Command::Activate => show_window(&desktop),
                    Command::ShutdownForUpdate if !updating => {
                        updating = true;
                        // Outlives any component: the exit must happen whatever the UI does.
                        dioxus::core::spawn_forever(shutdown_for_update(
                            tray.clone(),
                            desktop.clone(),
                        ));
                    }
                    Command::ShutdownForUpdate => {}
                }
            }
        }
    });
}

/// The installer's request (lifecycle-app §3.13): nothing is asked, the bounded cleanup runs
/// (a failed Soft rollback does not stop it; the journal finishes it at the next start), and the
/// process acknowledges with 73. A user's quit already under way may end first with 0, which
/// the installer reads as "not acknowledged" (as the old app did).
async fn shutdown_for_update(tray: Rc<dyn TrayApi>, desktop: DesktopContext) {
    tracing::info!("installer asked for shutdown");
    hide_to_tray(&desktop);
    if let Err(err) = tray.quit(QuitMode::SkipRestore).await {
        tracing::warn!(error = %err, "update shutdown: cleanup incomplete");
    }
    boot::exit(boot::EXIT_UPDATE_ACK);
}

/// A click on a Windows toast shows the window.
fn use_toast_clicks(wiring: &Rc<Wiring>) {
    let wiring = wiring.clone();
    let desktop = use_window();
    use_future(move || {
        let clicks = wiring.activations.borrow_mut().take();
        let desktop = desktop.clone();
        async move {
            let Some(mut clicks) = clicks else { return };
            while clicks.recv().await.is_some() {
                show_window(&desktop);
            }
        }
    });
}

#[cfg(test)]
mod tests;
