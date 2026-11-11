//! Traffic history page: the domains the domain-history service recorded, read from the file it
//! persists (`history/traffic-domains.json`, written at most 10 s after a change and when a
//! session stops). The service itself is opened inside `svc_tunnel` and not reachable from here,
//! so this page never opens a second `Store` of it: it only reads the file, and only while the
//! page is on screen. Clearing goes through `TunnelOps::clear_traffic_history`, the service's
//! owner. Site names (opt-in enrichment) are not wired in this build: every row has none.
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Map, Value};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::{Document, SCHEMA_KEY};
use vpnte_forensics::domains::DomainsDoc;
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::traffic_history::{
    DomainRow, SiteInfo, TrafficHistoryApi, TrafficSnapshot, site_url,
};
use vpnte_ui::widgets::{Load, UiError};

use crate::api_settings::{blocking, detached};
use crate::services::Backend;

/// How often the file is looked at while the page is on screen. The service writes it at most
/// every 10 s, so a new domain shows within about 12 s.
const LOOK: Duration = Duration::from_secs(2);

/// The file's modification time and length at a read; `None` = no file yet.
pub(super) type Stamp = Option<(SystemTime, u64)>;

/// [`TrafficHistoryApi`] over the persisted domain history.
pub struct TrafficService(Arc<Shared>);

/// State shared by the actions and the watch task.
struct Shared {
    backend: Arc<Backend>,
    /// `state()` runs on the UI thread: the first read of a visit is spawned on this runtime.
    runtime: Handle,
    state: watch::Sender<TrafficSnapshot>,
    /// The file as of the last successful read (`None`: not read yet).
    seen: Mutex<Option<Stamp>>,
    /// One read at a time.
    reading: tokio::sync::Mutex<()>,
}

impl TrafficService {
    /// Starts the watch task (it reads only while the page is on screen). Call it inside the
    /// tokio runtime.
    pub fn start(backend: Arc<Backend>) -> Self {
        let shared = Arc::new(Shared {
            backend,
            runtime: Handle::current(),
            state: watch::Sender::new(TrafficSnapshot::default()),
            seen: Mutex::new(None),
            reading: tokio::sync::Mutex::new(()),
        });
        tokio::spawn(follow(shared.clone()));
        Self(shared)
    }
}

impl Shared {
    /// Reads the file when it changed since the last read (`force`: in any case) and publishes
    /// the rows with the tunnel state. A failed read keeps a published list; only a first read
    /// that fails is published as `Failed`.
    async fn refresh(&self, force: bool) -> AppResult<()> {
        let _one = self.reading.lock().await;
        let path = history_path(&self.backend.dirs.root);
        let known = if force { None } else { *self.seen.lock() };
        let read = blocking(move || read_if_changed(&path, known)).await;
        let tunnel_up = self.tunnel_up();
        match read {
            Ok(Some((stamp, rows))) => {
                *self.seen.lock() = Some(stamp);
                self.send(Some(Load::Ready(rows.into())), tunnel_up);
                Ok(())
            }
            Ok(None) => {
                self.send(None, tunnel_up);
                Ok(())
            }
            Err(err) => {
                let first = !matches!(self.state.borrow().domains, Load::Ready(_));
                let failed = first.then(|| Load::Failed(UiError::from(&err)));
                self.send(failed, tunnel_up);
                Err(err)
            }
        }
    }

    /// Sends a snapshot with `domains` (`None`: unchanged) only when something differs.
    fn send(&self, domains: Option<Load<Arc<[DomainRow]>>>, tunnel_up: bool) {
        self.state.send_if_modified(|current| {
            let mut changed = current.tunnel_up != tunnel_up;
            current.tunnel_up = tunnel_up;
            if let Some(domains) = domains
                && current.domains != domains
            {
                current.domains = domains;
                changed = true;
            }
            changed
        });
    }

    fn tunnel_up(&self) -> bool {
        self.backend
            .tunnel()
            .is_ok_and(|t| t.snapshot().borrow().state == TunnelState::Connected)
    }
}

#[async_trait(?Send)]
impl TrafficHistoryApi for TrafficService {
    fn state(&self) -> watch::Receiver<TrafficSnapshot> {
        let rx = self.0.state.subscribe();
        // The page mounts on every visit: read now instead of at the next look.
        let shared = self.0.clone();
        self.0.runtime.spawn(async move {
            if let Err(err) = shared.refresh(false).await {
                tracing::debug!(error = %err, "traffic history not read");
            }
        });
        rx
    }

    async fn reload(&self) -> AppResult<()> {
        let shared = self.0.clone();
        detached(async move { shared.refresh(true).await }).await
    }

    async fn clear(&self) -> AppResult<()> {
        let shared = self.0.clone();
        detached(async move {
            let tunnel = shared.backend.tunnel()?.clone();
            tunnel.clear_traffic_history().await?;
            // The service saved the empty history at once: show it.
            shared.refresh(true).await
        })
        .await
    }

    async fn open_site(&self, url: String) -> AppResult<()> {
        // Only `https://<plain host>`, the one link the page builds; never a path or a scheme
        // that a crafted domain could smuggle in.
        let plain = url
            .strip_prefix("https://")
            .and_then(site_url)
            .is_some_and(|built| built == url);
        if !plain {
            return Err(AppError::validation(Msg::new("app.lists.traffic.badLink")));
        }
        vpnte_winnet::shell::open_url(&url).await
    }
}

/// Looks at the file every [`LOOK`] and on every tunnel change, while the page is on screen
/// (it holds the only receivers: the page is mounted only while it is current), until
/// `backend.shutdown`.
async fn follow(shared: Arc<Shared>) {
    let mut snapshot = shared.backend.tunnel().ok().map(|t| t.snapshot());
    let mut look = tokio::time::interval(LOOK);
    look.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let shutdown = shared.backend.shutdown.clone();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = look.tick() => {}
            () = tunnel_changed(&mut snapshot) => {}
        }
        if shared.state.receiver_count() == 0 {
            continue;
        }
        if let Err(err) = shared.refresh(false).await {
            tracing::debug!(error = %err, "traffic history not read");
        }
    }
}

/// Waits for a change of the tunnel state; never returns once the tunnel is gone.
async fn tunnel_changed(rx: &mut Option<watch::Receiver<TunnelSnapshot>>) {
    let Some(current) = rx.as_mut() else {
        return std::future::pending().await;
    };
    if current.changed().await.is_err() {
        *rx = None;
    }
}

/// `history/traffic-domains.json` under the data root.
pub(super) fn history_path(root: &Path) -> PathBuf {
    DomainsDoc::FILE
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// The rows when the file differs from `known` (or always without `known`), with the stamp
/// they were read at; `None` = unchanged. Blocking.
pub(super) fn read_if_changed(
    path: &Path,
    known: Option<Stamp>,
) -> AppResult<Option<(Stamp, Vec<DomainRow>)>> {
    let stamp = match std::fs::metadata(path) {
        Ok(meta) => Some((meta.modified().map_err(read_failed)?, meta.len())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(read_failed(err)),
    };
    if known == Some(stamp) {
        return Ok(None);
    }
    let rows = match stamp {
        None => Vec::new(),
        Some(_) => match std::fs::read(path) {
            Ok(bytes) => rows(decode(&bytes).map_err(read_failed)?),
            // Removed between the two calls: the history is empty.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(read_failed(err)),
        },
    };
    Ok(Some((stamp, rows)))
}

/// The document as `Store` reads it: a UTF-8 BOM tolerated, `schemaVersion` set aside, unknown
/// keys ignored.
pub(super) fn decode(bytes: &[u8]) -> serde_json::Result<DomainsDoc> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut map: Map<String, Value> = serde_json::from_slice(bytes)?;
    map.remove(SCHEMA_KEY);
    serde_json::from_value(Value::Object(map))
}

/// Rows newest first (`last_seen`), as the service lists them; `count` = connections, or DNS
/// lookups for a domain only seen in the engine log (the forensics `visits` rule). No IP.
pub(super) fn rows(doc: DomainsDoc) -> Vec<DomainRow> {
    let mut rows: Vec<DomainRow> = doc
        .domains
        .into_values()
        .map(|record| DomainRow {
            count: u64::from(record.visits()),
            domain: record.domain,
            first_seen: record.first_seen,
            last_seen: record.last_seen,
            bytes_up: record.bytes_up,
            bytes_down: record.bytes_down,
            site: SiteInfo::None,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.domain.cmp(&b.domain))
    });
    rows
}

fn read_failed(source: impl Into<anyhow::Error>) -> AppError {
    AppError::msg(
        vpnte_base::ErrorKind::Internal,
        Msg::new("app.lists.traffic.readFailed"),
    )
    .with_source(source)
}
