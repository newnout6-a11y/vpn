//! Traffic history page over the process's one domain history (`svc_tunnel::DomainHistory`):
//! the rows the forensics `HistoryService` lists, with the site names of the opt-in lookups
//! attached while they may run, re-projected whenever the history, a site name or the tunnel
//! changes (only while the page is on screen). Clearing empties the history and the site-name
//! cache.
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_forensics::enrichment::{EnrichInputs, EnrichStatus, HistoryEntry};
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_ui::traffic_history::{
    DomainRow, SiteInfo, TrafficHistoryApi, TrafficSnapshot, site_url,
};
use vpnte_ui::widgets::Load;

use crate::api_dashboard::pace::Pace;
use crate::services::Backend;
use crate::support::{changed, changed_opt, detached};
use crate::svc_tunnel::DomainHistory;

/// [`TrafficHistoryApi`] over the domain history service.
pub struct TrafficService(Arc<Shared>);

/// State shared by the actions and the follow task.
struct Shared {
    backend: Arc<Backend>,
    domains: Arc<DomainHistory>,
    state: watch::Sender<TrafficSnapshot>,
}

impl TrafficService {
    /// Publishes the first snapshot and starts the follow task (until `backend.shutdown`). Call
    /// it inside the tokio runtime.
    pub fn start(backend: Arc<Backend>, domains: Arc<DomainHistory>) -> Self {
        let shared = Arc::new(Shared {
            backend,
            domains,
            state: watch::Sender::new(TrafficSnapshot::default()),
        });
        // Subscribe before the first projection: a change between it and the follow task's first
        // poll would otherwise be marked seen and never projected.
        let sources = Sources::subscribe(&shared);
        shared.publish();
        tokio::spawn(follow(shared.clone(), sources));
        Self(shared)
    }
}

impl Shared {
    /// Publishes the history with the tunnel state when something differs.
    fn publish(&self) {
        let inputs = self.domains.inputs.borrow().clone();
        let entries = self
            .domains
            .enricher
            .entries(self.domains.history.list(), &inputs);
        let domains = Load::Ready(rows(entries).into());
        let tunnel_up = self.tunnel_up();
        self.state.send_if_modified(|current| {
            let changed = current.tunnel_up != tunnel_up || current.domains != domains;
            current.tunnel_up = tunnel_up;
            current.domains = domains;
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
        // The follow task skips changes while nobody looks: a visit starts from now.
        self.0.publish();
        self.0.state.subscribe()
    }

    async fn reload(&self) -> AppResult<()> {
        self.0.publish();
        Ok(())
    }

    async fn clear(&self) -> AppResult<()> {
        let shared = self.0.clone();
        detached(async move {
            let cleared = shared.domains.clear().await;
            shared.publish();
            cleared
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

/// The change sources the page follows: history, site names, the lookup route, the tunnel.
struct Sources {
    history: watch::Receiver<u64>,
    names: watch::Receiver<u64>,
    inputs: watch::Receiver<EnrichInputs>,
    snapshot: Option<watch::Receiver<TunnelSnapshot>>,
}

impl Sources {
    fn subscribe(shared: &Shared) -> Self {
        Self {
            history: shared.domains.history.changes(),
            names: shared.domains.enricher.changes(),
            inputs: shared.domains.inputs.clone(),
            snapshot: shared.backend.tunnel().ok().map(|t| t.snapshot()),
        }
    }
}

/// Re-projects on every history, site-name, lookup-route and tunnel change while the page is
/// on screen (it holds the only receivers: the page is mounted only while it is current). Every
/// DNS answer line and every site-name lookup is a change (dozens a second while a browser
/// loads pages), so the list goes out paced: at most twice a second, the last push complete.
async fn follow(shared: Arc<Shared>, sources: Sources) {
    let Sources {
        mut history,
        mut names,
        mut inputs,
        mut snapshot,
    } = sources;
    let shutdown = shared.backend.shutdown.clone();
    let mut pace = Pace::live();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = changed(&mut history) => {}
            () = changed(&mut names) => {}
            () = changed(&mut inputs) => {}
            () = changed_opt(&mut snapshot) => {}
        }
        if shared.state.receiver_count() == 0 {
            continue;
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = pace.ready() => {}
        }
        // The projection below covers what changed during the wait.
        history.mark_unchanged();
        names.mark_unchanged();
        inputs.mark_unchanged();
        if let Some(snapshot) = snapshot.as_mut() {
            snapshot.mark_unchanged();
        }
        shared.publish();
    }
}

/// Rows newest first (`last_seen`, the service's order kept for ties by name); `count` =
/// connections, or DNS lookups for a domain only seen in the engine log (the forensics `visits`
/// rule). No IP.
pub(super) fn rows(entries: Vec<HistoryEntry>) -> Vec<DomainRow> {
    let mut rows: Vec<DomainRow> = entries
        .into_iter()
        .map(|entry| {
            let record = entry.record;
            DomainRow {
                count: u64::from(record.visits()),
                domain: record.domain,
                first_seen: record.first_seen,
                last_seen: record.last_seen,
                bytes_up: record.bytes_up,
                bytes_down: record.bytes_down,
                site: entry.enrichment.map_or(SiteInfo::None, |e| match e.status {
                    EnrichStatus::Pending => SiteInfo::Pending,
                    EnrichStatus::Ready => SiteInfo::Ready {
                        name: e.site_name,
                        title: e.title,
                    },
                    EnrichStatus::Unavailable => SiteInfo::Unavailable,
                }),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.domain.cmp(&b.domain))
    });
    rows
}
