//! Smart RU rule-set sources: the files shipped in `resources/`, or a managed copy refreshed
//! from the SagerNet repositories.
//!
//! A refresh downloads both files over HTTPS, has the bundled sing-box parse each one
//! (`sing-box rule-set match`) and checks canaries, then promotes BOTH together as one new
//! immutable generation directory `gen-<unix ms>`. Anything wrong keeps the active files and
//! tells the user. Generations are never modified in place: sing-box watches `local` rule-set
//! files and reloads them when they change, so a running engine keeps its own generation and
//! old ones are pruned only before an engine start.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, ProxyKind, UnixMs, now_ms};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::paths::DataDirs;
use vpnte_core::settings::{BootstrapRouteMode, RuleSetMode, Settings};
use vpnte_core::store::{Document, Store};

use super::smart_ru::{GEOIP_RU, RULE_SETS};
use fetch::download;
use validate::validate;

mod fetch;
mod validate;

#[cfg(test)]
mod tests;

/// Largest rule-set file accepted (the bundled ones are 50 KB and 1 KB).
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const GEN_PREFIX: &str = "gen-";
const STAGING: &str = "staging";

/// `cache/rulesets.json`: which managed generation is active and how the last refresh went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RuleSetsDoc {
    /// Directory name of the active managed generation (`gen-<unix ms>`).
    pub current: Option<String>,
    pub last_check: Option<UnixMs>,
    pub last_ok: Option<UnixMs>,
    pub last_error: Option<RefreshFault>,
    /// The files of the current generation, by file name.
    pub files: BTreeMap<String, FileInfo>,
}

impl Document for RuleSetsDoc {
    const FILE: &'static str = "cache/rulesets.json";
    const VERSION: u32 = 1;
}

/// One downloaded file (informational: upstream files are unsigned and change daily, so no
/// hash can be pinned; trust comes from HTTPS + the engine parse + canaries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    pub size: u64,
    pub sha256: String,
    pub route: RouteKind,
}

/// How a file was fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteKind {
    Direct,
    /// The proxy from settings (`proxyOverride`).
    UserProxy,
    /// Happ's default SOCKS listener `127.0.0.1:10808`.
    HappSocks,
    /// Happ's default HTTP listener `127.0.0.1:10809`.
    HappHttp,
}

impl RouteKind {
    /// User-facing label («напрямую», «через Happ SOCKS 127.0.0.1:10808», …).
    pub fn label(self) -> Msg {
        Msg::new(match self {
            RouteKind::Direct => "engine.routing.ruleSets.route.direct",
            RouteKind::UserProxy => "engine.routing.ruleSets.route.userProxy",
            RouteKind::HappSocks => "engine.routing.ruleSets.route.happSocks",
            RouteKind::HappHttp => "engine.routing.ruleSets.route.happHttp",
        })
    }
}

/// Why the last refresh did not produce a new generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RefreshFault {
    /// Every allowed route failed for this file.
    Download { file: String },
    /// The engine could not read this file, or a canary did not match.
    Invalid { file: String },
    /// `sing-box.exe` is missing or could not run.
    EngineUnavailable,
    /// The generation could not be written.
    Storage,
}

impl RefreshFault {
    /// User-facing detail.
    pub fn msg(&self) -> Msg {
        match self {
            RefreshFault::Download { file } => {
                Msg::new("engine.routing.ruleSets.fault.download").arg("file", file)
            }
            RefreshFault::Invalid { file } => {
                Msg::new("engine.routing.ruleSets.fault.invalid").arg("file", file)
            }
            RefreshFault::EngineUnavailable => Msg::new("engine.routing.ruleSets.fault.engine"),
            RefreshFault::Storage => Msg::new("engine.routing.ruleSets.fault.storage"),
        }
    }
}

/// The rule-set related settings (read from [`Settings`]).
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshSettings {
    /// Use the managed copy when it is complete (mode `managed`).
    pub managed: bool,
    pub auto_update: bool,
    /// `false` = download directly only.
    pub use_proxy: bool,
    pub interval_h: u32,
    pub bootstrap: BootstrapRouteMode,
    /// The user's proxy (`proxyOverride` with `proxyType`), if set.
    pub user_proxy: Option<Route>,
}

impl RefreshSettings {
    /// Reads the rule-set keys of the settings document.
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            managed: s.smart_ru_rule_set_mode == RuleSetMode::Managed,
            auto_update: s.smart_ru_rule_set_auto_update,
            use_proxy: s.smart_ru_rule_set_use_proxy,
            interval_h: s.smart_ru_rule_set_update_hours,
            bootstrap: s.bootstrap_route_mode,
            user_proxy: s.proxy_override.as_ref().map(|p| p.route(s.proxy_type)),
        }
    }

    /// Whether the automatic triggers (app start, settings change, the hourly tick) should
    /// call `refresh(false)`.
    pub fn auto_refresh(&self, smart_ru_enabled: bool) -> bool {
        smart_ru_enabled && self.managed && self.auto_update
    }

    /// Download routes in trial order: `auto` = direct, then the proxies; `direct` = direct
    /// only; `localProxy` = the proxies only (a user whose direct GitHub is blackholed must
    /// not wait 45 s per file); `use_proxy = false` = direct only.
    pub fn routes(&self) -> Vec<(RouteKind, Route)> {
        let mode = if self.use_proxy {
            self.bootstrap
        } else {
            BootstrapRouteMode::Direct
        };
        let mut out: Vec<(RouteKind, Route)> = Vec::new();
        if mode != BootstrapRouteMode::LocalProxy {
            out.push((RouteKind::Direct, Route::Direct));
        }
        if mode != BootstrapRouteMode::Direct {
            let happ = |kind, port| {
                HostPort::new("127.0.0.1", port)
                    .ok()
                    .map(|a| Route::proxy(kind, &a, None))
            };
            let candidates = [
                (RouteKind::UserProxy, self.user_proxy.clone()),
                (RouteKind::HappSocks, happ(ProxyKind::Socks5, 10808)),
                (RouteKind::HappHttp, happ(ProxyKind::Http, 10809)),
            ];
            for (kind, route) in candidates {
                if let Some(route) = route
                    && !out.iter().any(|(_, r)| r.label() == route.label())
                {
                    out.push((kind, route));
                }
            }
        }
        out
    }
}

/// Which files the engine reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveSource {
    Bundled,
    /// A managed generation and when it was downloaded.
    Managed {
        generation: String,
        since: UnixMs,
    },
}

/// Result of [`RuleSetService::refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The current generation is younger than the interval; nothing downloaded.
    Fresh,
    Updated {
        generation: String,
    },
    /// Nothing changed; the active files stay in use.
    Failed(RefreshFault),
    Cancelled,
}

impl RefreshOutcome {
    /// The toast for a failed refresh: «Правила Smart RU не обновлены, используется локальная
    /// версия» (owner 10.4: never silent).
    pub fn notice(&self) -> Option<Notice> {
        match self {
            RefreshOutcome::Failed(fault) => Some(
                Notice::new(Level::Warn, "engine.routing.ruleSets.notUpdated").body(fault.msg()),
            ),
            _ => None,
        }
    }
}

/// Rule-set source selection, managed refresh and generation housekeeping.
pub struct RuleSetService {
    store: Arc<Store<RuleSetsDoc>>,
    /// `<data>\cache\rulesets`: generation directories and the staging directory.
    root: PathBuf,
    /// The shipped files (`resources\`).
    bundled: PathBuf,
    /// `resources\sing-box.exe`, used to validate downloads.
    engine: PathBuf,
    /// One refresh at a time; a forced refresh arriving mid-run runs after it.
    running: tokio::sync::Mutex<()>,
}

impl RuleSetService {
    /// Generations under `<data>\cache\rulesets`, engine and bundled files from `resources\`.
    pub fn new(store: Arc<Store<RuleSetsDoc>>, dirs: &DataDirs) -> Self {
        Self::with_paths(store, dirs.cache.join("rulesets"), dirs.resources.clone())
    }

    fn with_paths(store: Arc<Store<RuleSetsDoc>>, root: PathBuf, resources: PathBuf) -> Self {
        Self {
            store,
            root,
            engine: resources.join("sing-box.exe"),
            bundled: resources,
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// The directory to pass as `RoutingInputs::rule_set_dir`: the current managed generation
    /// when `managed` is set and both its files are present, else the bundled files. `None`
    /// when neither has both files: pass `rule_set_dir: None` (Smart RU off for the run, with
    /// a warning) instead of a missing local rule set, which sing-box refuses to start with.
    pub fn active(&self, managed: bool) -> Option<(ActiveSource, PathBuf)> {
        self.select(managed, vpnte_winnet::elevation::is_elevated())
    }

    /// Elevated, sing-box parses the files with administrator rights from user-writable folders:
    /// only the bundled files are used, and only while they match their release pins (the helper
    /// service does the same with its own copies). A managed generation has no pin to check.
    fn select(&self, managed: bool, elevated: bool) -> Option<(ActiveSource, PathBuf)> {
        let current = self.store.read(|d| d.current.clone());
        if managed
            && !elevated
            && let Some(generation) = current
            && complete(&self.root.join(&generation))
        {
            let dir = self.root.join(&generation);
            let since = gen_ms(&generation);
            return Some((ActiveSource::Managed { generation, since }, dir));
        }
        (complete(&self.bundled) && (!elevated || crate::pin::rule_sets_pinned(&self.bundled)))
            .then(|| (ActiveSource::Bundled, self.bundled.clone()))
    }

    /// Deletes generations other than the current one and the newest older one, plus a
    /// leftover staging directory. Call right before an engine start (never while a running
    /// engine may use an older generation); skipped while a refresh runs. Blocking.
    pub fn prune(&self) -> usize {
        let Ok(_guard) = self.running.try_lock() else {
            return 0;
        };
        let current = self.store.read(|d| d.current.clone());
        let mut gens: Vec<String> = std::fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(GEN_PREFIX))
            .collect();
        gens.sort_by_key(|n| std::cmp::Reverse(gen_ms(n)));
        let previous = gens.iter().find(|g| Some(*g) != current.as_ref()).cloned();
        let mut removed = 0;
        for g in gens
            .iter()
            .filter(|g| Some(*g) != current.as_ref() && Some(*g) != previous.as_ref())
        {
            match std::fs::remove_dir_all(self.root.join(g)) {
                Ok(()) => removed += 1,
                Err(err) => {
                    tracing::warn!(%err, generation = %g, "old rule-set generation not removed")
                }
            }
        }
        let _ = std::fs::remove_dir_all(self.root.join(STAGING));
        removed
    }
}

/// Refresh: download → validate → promote.
impl RuleSetService {
    /// Downloads, validates and promotes both files (see the module docs). Without `force`
    /// nothing happens while the current generation is younger than the interval and
    /// complete. On any failure the active files stay and the fault is recorded.
    pub async fn refresh(
        &self,
        cfg: &RefreshSettings,
        force: bool,
        cancel: &CancellationToken,
    ) -> RefreshOutcome {
        let routes = cfg.routes();
        let fetch = async |url: &'static str| download(url, &routes, cancel).await;
        self.refresh_with(force, cfg.interval_h, cancel, fetch)
            .await
    }

    async fn refresh_with<F>(
        &self,
        force: bool,
        interval_h: u32,
        cancel: &CancellationToken,
        fetch: F,
    ) -> RefreshOutcome
    where
        F: AsyncFn(&'static str) -> Option<(Vec<u8>, RouteKind)>,
    {
        let _guard = tokio::select! {
            guard = self.running.lock() => guard,
            () = cancel.cancelled() => return RefreshOutcome::Cancelled,
        };
        let doc = self.store.snapshot();
        let interval_ms = i64::from(interval_h) * 3_600_000;
        let fresh = doc.last_ok.is_some_and(|t| now_ms() - t < interval_ms)
            && doc
                .current
                .as_ref()
                .is_some_and(|g| complete(&self.root.join(g)));
        if fresh && !force {
            return RefreshOutcome::Fresh;
        }
        let started = now_ms();
        let staging = self.root.join(STAGING);
        let staged = self.stage(&staging, cancel, &fetch).await;
        let fault = match staged {
            Ok(files) => match self.promote(&staging, started, files).await {
                Ok(generation) => {
                    tracing::info!(%generation, "smart-RU rule sets updated");
                    return RefreshOutcome::Updated { generation };
                }
                Err(fault) => fault,
            },
            Err(None) => {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return RefreshOutcome::Cancelled;
            }
            Err(Some(fault)) => fault,
        };
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tracing::warn!(
            ?fault,
            "smart-RU rule sets not updated; the active files stay in use"
        );
        let record = self.store.update(|d| {
            d.last_check = Some(started);
            d.last_error = Some(fault.clone());
        });
        if let Err(err) = record {
            tracing::warn!(%err, "rule-set refresh state not saved");
        }
        RefreshOutcome::Failed(fault)
    }

    /// Fetches and validates both files into a fresh staging directory. `Err(None)` =
    /// cancelled.
    async fn stage<F>(
        &self,
        staging: &Path,
        cancel: &CancellationToken,
        fetch: &F,
    ) -> Result<BTreeMap<String, FileInfo>, Option<RefreshFault>>
    where
        F: AsyncFn(&'static str) -> Option<(Vec<u8>, RouteKind)>,
    {
        let storage = |err: std::io::Error| {
            tracing::warn!(%err, "rule-set staging failed");
            Some(RefreshFault::Storage)
        };
        let _ = tokio::fs::remove_dir_all(staging).await;
        tokio::fs::create_dir_all(staging).await.map_err(storage)?;
        let mut files = BTreeMap::new();
        for (tag, file, url) in RULE_SETS {
            let fetched = fetch(url).await;
            if cancel.is_cancelled() {
                return Err(None);
            }
            let Some((bytes, route)) = fetched else {
                return Err(Some(RefreshFault::Download {
                    file: file.to_owned(),
                }));
            };
            let path = staging.join(file);
            tokio::fs::write(&path, &bytes).await.map_err(storage)?;
            match validate(&self.engine, &path, tag).await {
                Some(true) => {}
                Some(false) => {
                    return Err(Some(RefreshFault::Invalid {
                        file: file.to_owned(),
                    }));
                }
                None => return Err(Some(RefreshFault::EngineUnavailable)),
            }
            let info = FileInfo {
                size: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
                route,
            };
            files.insert(file.to_owned(), info);
        }
        Ok(files)
    }

    /// Renames the staging directory into a new generation and records it.
    async fn promote(
        &self,
        staging: &Path,
        started: UnixMs,
        files: BTreeMap<String, FileInfo>,
    ) -> Result<String, RefreshFault> {
        let generation = format!("{GEN_PREFIX}{started}");
        tokio::fs::rename(staging, self.root.join(&generation))
            .await
            .map_err(|err| {
                tracing::warn!(%err, "rule-set generation not created");
                RefreshFault::Storage
            })?;
        self.store
            .update(|d| {
                d.current = Some(generation.clone());
                d.last_check = Some(started);
                d.last_ok = Some(started);
                d.last_error = None;
                d.files = files;
            })
            .map_err(|err| {
                tracing::warn!(%err, "rule-set state not saved");
                RefreshFault::Storage
            })?;
        Ok(generation)
    }
}

fn gen_ms(name: &str) -> UnixMs {
    name.strip_prefix(GEN_PREFIX)
        .and_then(|ms| ms.parse().ok())
        .unwrap_or(0)
}

/// Both files present and non-empty.
fn complete(dir: &Path) -> bool {
    RULE_SETS.iter().all(|(_, file, _)| {
        std::fs::metadata(dir.join(file)).is_ok_and(|m| m.is_file() && m.len() > 0)
    })
}
