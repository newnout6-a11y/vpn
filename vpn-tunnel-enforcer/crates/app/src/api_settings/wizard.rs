//! First-run wizard ([`WizardApi`]): what each step persists. Nothing is applied before
//! «Завершить»; then the kill switch, autostart and the key import run in that order (the
//! first two are undone when a later step fails) and one settings write with
//! `first_run_complete` closes the wizard. «Пропустить» saves the language and the flag only.
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::types::Notice;
use vpnte_base::types::{ClientDevice, KillSwitchLevel, Level};
use vpnte_base::{AppResult, ErrorKind, Msg};
use vpnte_core::settings::{ConnectionMode, RoutingMode};
use vpnte_probes::local_proxy::{self, ScanOptions};
use vpnte_servers::subscription::canonical_source;
use vpnte_ui::wizard::{
    Connection, KeyCheck, LocalProxy, Routing, WizardApi, WizardChoices, WizardDefaults,
    WizardState,
};

use super::pump::publish;
use super::{Shared, actions};
use crate::support::{blocking, detached};

/// [`WizardApi`] over the backend.
pub struct WizardService(pub(crate) Arc<Shared>);

/// The paste limit of `parse_text` (bytes), for its error message.
const PASTE_LIMIT: usize = 1 << 20;

/// Opens a fresh wizard with the settings as they are now (Settings «Пройти мастер заново»
/// and the first start).
pub async fn open(shared: &Arc<Shared>) {
    let current = defaults(shared).await;
    publish(
        &shared.wizard,
        WizardState {
            open: true,
            current,
        },
    );
}

/// The choices the wizard starts from. Hard is offered as the starting point only when this
/// process can capture with the TUN (NOADMIN §0: elevated, in this phase).
async fn defaults(shared: &Arc<Shared>) -> WizardDefaults {
    let backend = &shared.backend;
    let tun = backend.tunnel().is_ok_and(|t| t.tun_available());
    let (connection, routing) = backend
        .settings
        .read(|s| (s.connection_mode, s.routing_mode));
    WizardDefaults {
        connection: match connection {
            ConnectionMode::DirectVpn => Connection::Key,
            ConnectionMode::LocalProxy => Connection::LocalProxy,
        },
        routing: match routing {
            RoutingMode::Hard if tun => Routing::Hard,
            _ => Routing::Soft,
        },
        kill_switch: backend.protection.read(|d| d.settings.level),
        autostart: actions::read_autostart(shared).await.unwrap_or(false),
        servers: backend
            .servers
            .read(|d| d.profiles.iter().filter(|r| r.archived.is_none()).count()),
    }
}

#[async_trait(?Send)]
impl WizardApi for WizardService {
    fn state(&self) -> watch::Receiver<WizardState> {
        self.0.wizard.subscribe()
    }

    async fn detect_proxy(&self) -> AppResult<Option<LocalProxy>> {
        // Our own engine (a Soft session points the system proxy at it) is not "another client".
        let skip_pids = self
            .0
            .backend
            .tunnel()
            .ok()
            .and_then(|t| t.snapshot().borrow().pid)
            .into_iter()
            .collect();
        let options = ScanOptions {
            skip_ports: Vec::new(),
            skip_pids,
        };
        detached(async move {
            let found = local_proxy::scan(options).await;
            Ok(found.map(|p| LocalProxy {
                host: p.addr.ip().to_string(),
                port: p.addr.port(),
                kind: p.kind,
            }))
        })
        .await
    }

    async fn check_key(&self, text: String, cancel: CancellationToken) -> AppResult<KeyCheck> {
        let fetcher = self.0.backend.refresh.fetcher.clone();
        let text = text.trim().to_owned();
        // Dropping this future (the text was edited) cancels a subscription fetch.
        let _cancel_on_drop = cancel.clone().drop_guard();
        detached(async move {
            if let Some(url) = canonical_source(&text) {
                let report = fetcher.fetch(&url, ClientDevice::Pc, &cancel).await?;
                return Ok(KeyCheck {
                    servers: report.profiles.len(),
                    subscription: true,
                });
            }
            let report = blocking(move || {
                vpnte_servers::parse::parse_text(&text)
                    .map_err(|_| vpnte_servers::parse::too_large(PASTE_LIMIT))
            })
            .await?;
            if report.profiles.is_empty() {
                return Err(vpnte_servers::parse::no_profiles(&report));
            }
            Ok(KeyCheck {
                servers: report.profiles.len(),
                subscription: false,
            })
        })
        .await
    }

    async fn finish(&self, choices: WizardChoices) -> AppResult<()> {
        let shared = self.0.clone();
        detached(finish(shared, choices)).await
    }

    async fn skip(&self, lang: Lang) -> AppResult<()> {
        let shared = self.0.clone();
        detached(async move {
            let _writes = shared.writes.lock().await;
            shared.backend.settings.update(|s| {
                s.locale = Some(lang);
                s.first_run_complete = true;
            })?;
            shared.wizard.send_modify(|w| w.open = false);
            Ok(())
        })
        .await
    }
}

/// What `finish` changed before a later step failed (undone in reverse order).
#[derive(Default)]
struct Applied {
    /// The level that was in force before.
    level: Option<KillSwitchLevel>,
    /// The stored autostart value before.
    autostart: Option<bool>,
}

/// «Завершить»: see the module doc. On failure the wizard stays open with the error and the
/// kill switch / autostart changes are undone; servers a key import already added are kept
/// (they are the user's data and harmless).
async fn finish(shared: Arc<Shared>, choices: WizardChoices) -> AppResult<()> {
    let _writes = shared.writes.lock().await;
    let backend = shared.backend.clone();
    let tunnel = backend.tunnel()?.clone();
    let (routing, adjusted) = routing_for(&choices, tunnel.tun_available())?;
    let mut applied = Applied::default();
    let result = apply(&shared, &choices, routing, &mut applied).await;
    if let Err(err) = result {
        undo(&shared, applied).await;
        return Err(err);
    }
    shared.wizard.send_modify(|w| w.open = false);
    if adjusted {
        backend.notifier.notify(
            Notice::new(Level::Info, "app.settings.wizard.softChosen")
                .body(Msg::new("app.settings.wizard.softChosenBody")),
            None,
        );
    }
    tracing::info!(?routing, adjusted, "first-run wizard finished");
    Ok(())
}

/// The steps of `finish` up to and including the settings write.
async fn apply(
    shared: &Arc<Shared>,
    choices: &WizardChoices,
    routing: RoutingMode,
    applied: &mut Applied,
) -> AppResult<()> {
    let backend = &shared.backend;
    let tunnel = backend.tunnel()?.clone();
    let level = backend.protection.read(|d| d.settings.level);
    if choices.kill_switch != level {
        tunnel.set_kill_switch_level(choices.kill_switch).await?;
        applied.level = Some(level);
    }
    if actions::read_autostart(shared).await != Some(choices.autostart) {
        let before = backend.settings.read(|s| s.autostart);
        actions::apply_autostart(shared, choices.autostart).await?;
        applied.autostart = Some(before);
    }
    if let (Connection::Key, Some(key)) = (choices.connection, &choices.key) {
        let cancel = backend.shutdown.child_token();
        backend
            .servers
            .add_from_input(&backend.refresh, &key.0, None, ClientDevice::Pc, cancel)
            .await?;
    }
    let old = backend.settings.snapshot();
    backend.settings.update(|s| {
        s.locale = Some(choices.lang);
        s.connection_mode = match choices.connection {
            Connection::Key => ConnectionMode::DirectVpn,
            Connection::LocalProxy => ConnectionMode::LocalProxy,
        };
        s.routing_mode = routing;
        s.first_run_complete = true;
    })?;
    let new = backend.settings.snapshot();
    // A wizard re-run while connected: the tunnel takes the change (idle: nothing to do).
    match tunnel.apply_settings_change(old, new).await {
        Ok(done) => {
            for warning in done.warnings {
                backend
                    .notifier
                    .notify(Notice::new(Level::Warn, warning), None);
            }
        }
        Err(err) if err.kind() == ErrorKind::Cancelled => {}
        Err(err) => tracing::warn!(error = %err, "wizard settings not applied to the tunnel"),
    }
    Ok(())
}

/// Undoes the autostart and kill-switch changes of a failed `finish`; a failed undo is logged
/// and shown (the user must know the state changed).
async fn undo(shared: &Arc<Shared>, applied: Applied) {
    let mut failed = false;
    if let Some(before) = applied.autostart
        && let Err(err) = actions::apply_autostart(shared, before).await
    {
        tracing::warn!(error = %err, "wizard: autostart not restored");
        failed = true;
    }
    if let Some(level) = applied.level
        && let Ok(tunnel) = shared.backend.tunnel()
        && let Err(err) = tunnel.set_kill_switch_level(level).await
    {
        tracing::warn!(error = %err, "wizard: kill switch level not restored");
        failed = true;
    }
    if failed {
        shared.backend.notifier.notify(
            Notice::new(Level::Warn, "app.settings.wizard.restoreFailed"),
            None,
        );
    }
}

/// The routing mode to store. The wizard page offers no Soft with a key (old Soft needed a
/// local proxy); the new Soft works with both upstreams (NOADMIN §2), so a key without TUN
/// capture is stored as Soft and the user is told so. Hard chosen over Soft with a local proxy
/// is refused: the user can pick Soft on the page.
pub fn routing_for(choices: &WizardChoices, tun_available: bool) -> AppResult<(RoutingMode, bool)> {
    match (choices.routing, choices.connection) {
        (Routing::Soft, _) => Ok((RoutingMode::Soft, false)),
        (Routing::Hard, _) if tun_available => Ok((RoutingMode::Hard, false)),
        (Routing::Hard, Connection::Key) => Ok((RoutingMode::Soft, true)),
        (Routing::Hard, Connection::LocalProxy) => Err(super::save::hard_needs_admin()),
    }
}
