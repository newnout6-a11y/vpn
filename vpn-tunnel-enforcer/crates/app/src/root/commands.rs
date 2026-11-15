//! Commands of later launches (p-exit-gate), served on the backend's runtime: none of them waits
//! for the window, its page or its VirtualDom. `activate` and a link show the window through the
//! [`WindowBell`] (a link also goes to the Servers page's add dialog, where the user confirms
//! it); the installer's `shutdown-for-update` hides the window as a courtesy, runs the bounded
//! exit cleanup and exits with 73. Carried by the VirtualDom, the installer's request waited 83 s
//! on a hidden window (owner, 15.11) while setup said nothing.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;
use vpnte_ui::tray::WindowBell;
use vpnte_winnet::single_instance::Command;

use crate::api_servers::LinkInbox;
use crate::args::AWAIT_SHUTDOWN_TIMEOUT_S;
use crate::boot;
use crate::services::Backend;

/// The tunnel's share of the cleanup, as the tray's quit gives it (app-dashboard `Hub::quit`).
const TUNNEL_BUDGET: Duration = Duration::from_secs(12);
/// Feature operations still running at exit, as the tray's quit waits for them.
const OPS_BUDGET: Duration = Duration::from_secs(3);
/// The whole cleanup for the installer: past it the process acknowledges anyway (setup's helper
/// waits [`AWAIT_SHUTDOWN_TIMEOUT_S`] for the acknowledgement, review exitgate-a2; the tweak
/// journal finishes an interrupted rollback at the next start).
const UPDATE_BUDGET: Duration = Duration::from_secs(20);
const _: () = assert!(
    UPDATE_BUDGET.as_secs() < AWAIT_SHUTDOWN_TIMEOUT_S as u64,
    "within the helper's wait"
);

/// A boxed `Send` future (the cleanup).
pub(crate) type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What the commands do; the tests run them against fakes.
pub(crate) trait Effects: Send + Sync + 'static {
    /// Shows, restores and focuses the window, whatever state it is in.
    fn show(&self);
    /// Hides the window to the tray.
    fn hide(&self);
    /// Hands a link to the Servers page's add dialog.
    fn offer(&self, link: String);
    /// The bounded exit cleanup.
    fn cleanup(&self) -> Work;
    /// Ends the process with `code` (the tests record it and return).
    fn exit(&self, code: u8);
}

/// Hands the start's link to the add dialog and serves later launches' commands until the
/// process ends. Call it inside the tokio runtime.
pub(crate) fn spawn(
    commands: Option<mpsc::UnboundedReceiver<Command>>,
    first_link: Option<String>,
    effects: Arc<dyn Effects>,
) {
    if let Some(link) = first_link {
        effects.offer(link);
    }
    if let Some(commands) = commands {
        tokio::spawn(serve(commands, effects));
    }
}

/// Serves `commands` in order until the channel closes or the installer's request ends the
/// process. A user's quit already under way may end the process first with 0, which the
/// installer reads as "not acknowledged" (as the old app did).
pub(crate) async fn serve(
    mut commands: mpsc::UnboundedReceiver<Command>,
    effects: Arc<dyn Effects>,
) {
    while let Some(command) = commands.recv().await {
        match command {
            Command::Activate => effects.show(),
            Command::OpenLink(link) => {
                effects.offer(link);
                effects.show();
            }
            Command::ShutdownForUpdate => {
                tracing::info!("installer asked for shutdown");
                effects.hide();
                if timeout(UPDATE_BUDGET, effects.cleanup()).await.is_err() {
                    tracing::warn!("update shutdown: cleanup unfinished; acknowledging anyway");
                }
                effects.exit(boot::EXIT_UPDATE_ACK);
                return;
            }
        }
    }
}

/// The effects over the running app.
pub(crate) struct Live {
    pub(crate) bell: WindowBell,
    /// The Servers page's link inbox (`None`: a wiring bug, logged when a link arrives).
    pub(crate) links: Option<LinkInbox>,
    pub(crate) backend: Arc<Backend>,
}

impl Effects for Live {
    fn show(&self) {
        self.bell.show();
    }

    fn hide(&self) {
        self.bell.hide();
    }

    fn offer(&self, link: String) {
        match &self.links {
            Some(links) => links.offer(link),
            None => tracing::error!("a link arrived but no link inbox is wired"),
        }
    }

    fn cleanup(&self) -> Work {
        Box::pin(exit_cleanup(self.backend.clone()))
    }

    fn exit(&self, code: u8) {
        // Last: drains the app log (the process exits without running destructors).
        drop(self.backend.log.lock().take());
        boot::exit(code)
    }
}

/// The tray's quit cleanup (app-dashboard `Hub::quit`) as `QuitMode::SkipRestore` runs it, here
/// on the backend's runtime: `Hub::quit` is reached only through the UI thread's `TrayApi`. A
/// failed Proxy-mode rollback does not stop it; the tweak journal finishes it at the next start.
async fn exit_cleanup(backend: Arc<Backend>) {
    backend.shutdown.cancel();
    if let Ok(tunnel) = backend.tunnel() {
        let report = tunnel.shutdown(TUNNEL_BUDGET).await;
        tracing::info!(?report, "update shutdown: cleanup of the tunnel");
    }
    if timeout(OPS_BUDGET, backend.ops.close()).await.is_err() {
        tracing::warn!("feature operations still draining at exit");
    }
    if let Some(clipboard) = backend.clipboard.get() {
        clipboard.shutdown();
    }
    tracing::info!("exit cleanup done");
}

#[cfg(test)]
mod tests;
