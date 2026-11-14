//! Backend bootstrap (work package `app-base`): data dirs, lock, logging, legacy import, stores,
//! server list, operation registry, engine paths and the notifier, plus the locale layers. No
//! network activity and no system change happens here, and no tokio runtime is needed.
pub mod docs;
pub mod notify;

use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_base::i18n::Lang;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_cleanup::legacy::CleanupMarker;
use vpnte_core::logging;
use vpnte_core::ops::OperationRegistry;
use vpnte_core::paths::DataDirs;
use vpnte_core::redact;
use vpnte_core::settings::{RoutingMode, Settings};
use vpnte_core::store::{Document, Store};
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::rulesets::{RuleSetService, RuleSetsDoc};
use vpnte_probes::geo::Geo;
use vpnte_servers::refresh::RefreshCtx;
use vpnte_servers::store::Servers;
use vpnte_servers::subscription::{Hwids, SubscriptionFetcher};
use vpnte_tunnel::history::History;
use vpnte_update::policy;
use vpnte_update::store::EngineStore;
use vpnte_winnet::clipboard::SecretClipboard;

use crate::args::Args;
use crate::services::{Backend, Engines, TunnelOps};
use docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use notify::Notifier;

/// Builds the backend. Order (storage §3.12): data dir and its lock, logging, the one-time legacy
/// import (before any store is opened), then every store. A second instance holding the data
/// lock gets `Conflict` (`core.store.dataDirLocked`). Blocking (file reads, DPAPI): call it
/// before the UI starts, or from `spawn_blocking`.
pub fn build(args: &Args) -> AppResult<Arc<Backend>> {
    build_in(args, DataDirs::resolve()?)
}

/// [`build`] in the given directories: production resolves them ([`DataDirs::resolve`], which
/// ignores the overrides in an elevated process); the bootstrap test passes throw-away ones, so it
/// runs on an elevated CI runner too without touching the real data folder.
pub(crate) fn build_in(args: &Args, dirs: DataDirs) -> AppResult<Arc<Backend>> {
    vpnte_base::http::init_tls();
    dirs.ensure()?;
    let lock = dirs.lock()?;
    // Debug logging is a setting, but settings may only be opened after the import.
    let log = logging::init(&dirs.logs, false)?;
    let elevated = vpnte_winnet::elevation::is_elevated();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        elevated,
        autostart = args.autostart,
        "starting"
    );

    let import = crate::import::import_if_needed(&dirs);
    let fresh = !dirs.root.join(Settings::FILE).exists();
    let settings = Arc::new(Store::<Settings>::open(&dirs.root));
    // Tunnel mode can run from the first start: the helper service is installed (NOADMIN §0, the
    // installer adds it) or this process is elevated.
    first_start(
        &settings,
        fresh,
        elevated || crate::boot::service::installed(),
    );
    logging::set_debug(settings.read(|s| s.ui.debug_log));

    let ops = OperationRegistry::new();
    let fetcher = Arc::new(SubscriptionFetcher::new(Hwids::current(), settings.clone()));
    let rule_sets_doc = Arc::new(Store::<RuleSetsDoc>::open(&dirs.root));
    let backend = Backend {
        lock,
        log: Mutex::new(Some(log)),
        elevated,
        engines: resolve_engines(&crate::svc_update::engine_store(
            &dirs.root,
            dirs.resources.clone(),
        )),
        protection: Arc::new(Store::<ProtectionDoc>::open(&dirs.root)),
        themes: Arc::new(Store::<ThemesDoc>::open(&dirs.root)),
        soft: Arc::new(Store::<SoftDoc>::open(&dirs.root)),
        cleanup: Arc::new(Store::<CleanupMarker>::open(&dirs.root)),
        rules: Arc::new(Store::<RulesDoc>::open(&dirs.root)),
        rule_sets: Arc::new(RuleSetService::new(rule_sets_doc, &dirs)),
        history: History::open(&dirs.root),
        servers: Arc::new(Servers::open(&dirs.root)),
        refresh: RefreshCtx::new(fetcher, ops.clone()),
        ops,
        geo: Geo::new(!settings.read(|s| s.disable_geo_lookup)),
        notifier: Arc::new(Notifier::new(settings.clone())?),
        settings,
        import,
        shutdown: CancellationToken::new(),
        clipboard: OnceLock::new(),
        tunnel: OnceLock::new(),
        dirs,
    };
    tracing::info!(imported = backend.import.is_some(), "backend ready");
    Ok(Arc::new(backend))
}

impl Backend {
    /// The tunnel; `Internal` (`app.base.tunnelMissing`) when `svc_tunnel::build` has not been
    /// stored yet (a start-order bug, never a user condition).
    pub fn tunnel(&self) -> AppResult<&Arc<dyn TunnelOps>> {
        self.tunnel
            .get()
            .ok_or_else(|| AppError::msg(ErrorKind::Internal, Msg::new("app.base.tunnelMissing")))
    }

    /// The secret clipboard, started on first use. Call it inside the tokio runtime (a backend
    /// task): starting it outside one panics.
    pub fn clipboard(&self) -> &SecretClipboard {
        self.clipboard.get_or_init(SecretClipboard::start)
    }

    /// The user's language for texts the backend renders (dialogs, exports): the stored choice,
    /// else Windows'.
    pub fn lang(&self) -> Lang {
        self.settings
            .read(|s| s.locale)
            .unwrap_or_else(vpnte_ui::lang::os_lang)
    }
}

/// The one error for a privileged operation this unelevated process cannot run (NOADMIN §0):
/// `Permission` with «Доступно, только если приложение запущено от имени администратора».
pub fn needs_admin() -> AppError {
    AppError::msg(ErrorKind::Permission, Msg::new("app.base.needsAdmin"))
}

/// The `(ru, en)` locale layers of every backend crate and of the app, for
/// `vpnte_ui::lang::init_locales` (which puts the UI's own catalog first). `vpnte-base` comes
/// first so its canonical `errors.*` texts win over the old app's strings.
pub fn locale_layers() -> Vec<(&'static str, &'static str)> {
    let mut layers = vec![(
        include_str!("../../../base/locales/base.ru.json"),
        include_str!("../../../base/locales/base.en.json"),
    )];
    for crate_layers in [
        vpnte_core::LOCALES,
        vpnte_winnet::LOCALES,
        vpnte_profiles::LOCALES,
        vpnte_view::LOCALES,
        vpnte_servers::LOCALES,
        vpnte_engine::LOCALES,
        vpnte_forensics::LOCALES,
        vpnte_automation::LOCALES,
        vpnte_probes::LOCALES,
        vpnte_tunnel::LOCALES,
        vpnte_proxies::LOCALES,
        vpnte_cleanup::LOCALES,
        vpnte_service::LOCALES,
        APP,
    ] {
        layers.extend_from_slice(crate_layers);
    }
    layers
}

/// The app's own fragments: one pair per work package (every app package ships
/// `crates/app/locales/<package>.{ru,en}.json`).
const APP: &[(&str, &str)] = &[
    (
        include_str!("../../locales/app-base.ru.json"),
        include_str!("../../locales/app-base.en.json"),
    ),
    (
        include_str!("../../locales/app-dashboard.ru.json"),
        include_str!("../../locales/app-dashboard.en.json"),
    ),
    (
        include_str!("../../locales/app-servers.ru.json"),
        include_str!("../../locales/app-servers.en.json"),
    ),
    (
        include_str!("../../locales/app-settings.ru.json"),
        include_str!("../../locales/app-settings.en.json"),
    ),
    (
        include_str!("../../locales/app-tunnel.ru.json"),
        include_str!("../../locales/app-tunnel.en.json"),
    ),
    (
        include_str!("../../locales/app-main.ru.json"),
        include_str!("../../locales/app-main.en.json"),
    ),
    (
        include_str!("../../locales/app-import.ru.json"),
        include_str!("../../locales/app-import.en.json"),
    ),
    (
        include_str!("../../locales/app-setup.ru.json"),
        include_str!("../../locales/app-setup.en.json"),
    ),
    (
        include_str!("../../locales/app-clickjack.ru.json"),
        include_str!("../../locales/app-clickjack.en.json"),
    ),
    (
        include_str!("../../locales/app-maintenance.ru.json"),
        include_str!("../../locales/app-maintenance.en.json"),
    ),
    (
        include_str!("../../locales/app-tools.ru.json"),
        include_str!("../../locales/app-tools.en.json"),
    ),
    (
        include_str!("../../locales/app-lists.ru.json"),
        include_str!("../../locales/app-lists.en.json"),
    ),
    (
        include_str!("../../locales/wire-proxies-live.ru.json"),
        include_str!("../../locales/wire-proxies-live.en.json"),
    ),
    (
        include_str!("../../locales/w7-phones.ru.json"),
        include_str!("../../locales/w7-phones.en.json"),
    ),
    (
        include_str!("../../locales/svc-wire.ru.json"),
        include_str!("../../locales/svc-wire.en.json"),
    ),
    (
        include_str!("../../locales/p-updates.ru.json"),
        include_str!("../../locales/p-updates.en.json"),
    ),
    (
        include_str!("../../locales/p-tails-a.ru.json"),
        include_str!("../../locales/p-tails-a.en.json"),
    ),
];

/// First-start settings and the log pseudonym key. A read-only `settings.json` (newer version,
/// unreadable) must not stop the start: the key then lives in memory only (B28).
fn first_start(settings: &Store<Settings>, fresh: bool, elevated: bool) {
    let key = settings
        .update(|s| {
            // NOADMIN §2: without the service (or elevation) the TUN cannot exist, so a new
            // install starts in Soft.
            if fresh && !elevated {
                s.routing_mode = RoutingMode::Soft;
            }
            s.ensure_log_key()
        })
        .unwrap_or_else(|err| {
            tracing::warn!(%err, "settings not writable; log key kept in memory");
            settings.snapshot().ensure_log_key()
        });
    if let Some(key) = key {
        redact::set_ip_key(&key);
    }
}

/// The active engines (at the start, and again after every switch of the update channel): the
/// version the update channel downloaded while it is still usable (`vpnte_update::store`: newer
/// than the bundled one, inside this build's range, its signed feed verifies), else the bundled
/// one in `resources`. Canonical when the file exists (the spelling WFP app ids and
/// `RealEngines` expect); a missing engine keeps its expected path and fails at its first start.
/// Versions this build no longer allows are dropped first. Blocking (file reads).
pub(crate) fn resolve_engines(store: &EngineStore) -> Engines {
    let path = |id: &str| {
        store.tidy(id);
        let expected = store.resolve(id).exe;
        // `canonical_exe` refuses `..` and `\?\` spellings, which a relative VPNTE_RESOURCES_DIR
        // made absolute can carry: resolve them first.
        std::fs::canonicalize(&expected)
            .ok()
            .and_then(|real| {
                let real = real.to_str()?;
                vpnte_winnet::wfp::canonical_exe(real.strip_prefix(r"\\?\").unwrap_or(real)).ok()
            })
            .unwrap_or(expected)
    };
    Engines {
        singbox: path(policy::SINGBOX),
        xray: path(policy::XRAY),
    }
}

#[cfg(test)]
mod tests;
