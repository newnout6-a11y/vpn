//! The traffic (domain) history of this process and its opt-in site names: one
//! [`HistoryService`] fed by the Clash poller (`traffic.rs`) and by every line of the running
//! engine (its DNS answers name sites the connection list shows only as addresses), and one
//! [`Enricher`] whose lookups run only while «domain_enrichment» is on.
use std::sync::Arc;

use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_forensics::domains::{DomainsDoc, HistoryService};
use vpnte_forensics::enrichment::{EnrichInputs, Enricher, EnrichmentDoc};
use vpnte_tunnel::api::{CaptureKind, TunStatus};

use crate::services::Backend;

/// The domain history and its site names, shared by the tunnel side and the Traffic page.
pub struct DomainHistory {
    pub history: Arc<HistoryService>,
    pub enricher: Enricher,
    /// What the site-name lookups may do right now; the page attaches site info by it.
    pub inputs: watch::Receiver<EnrichInputs>,
}

impl DomainHistory {
    /// Opens both documents and starts the line feed and the setting follower under
    /// `backend.shutdown`. Runs inside the tokio runtime.
    pub(crate) fn open(
        b: &Backend,
        status: watch::Receiver<TunStatus>,
        lines: broadcast::Receiver<Arc<str>>,
    ) -> Arc<Self> {
        let history = Arc::new(HistoryService::open(
            Arc::new(Store::<DomainsDoc>::open(&b.dirs.root)),
            None,
        ));
        let enricher = Enricher::open(Arc::new(Store::<EnrichmentDoc>::open(&b.dirs.root)));
        let (tx, inputs) = watch::channel(EnrichInputs::default());
        tokio::spawn(observe(lines, history.clone(), b.shutdown.child_token()));
        tokio::spawn(follow(
            b.settings.clone(),
            status,
            history.clone(),
            enricher.clone(),
            tx,
            b.shutdown.child_token(),
        ));
        Arc::new(Self {
            history,
            enricher,
            inputs,
        })
    }

    /// Empties the history and the site-name cache, both saved at once. Both run even when the
    /// first fails: a failed half must not keep the other half.
    pub async fn clear(&self) -> AppResult<()> {
        let history = self.history.clear().await;
        let names = self.enricher.clear().await;
        history.and(names)
    }
}

/// Where site-name lookups may leave: with the TUN up a plain request already rides it; a proxy
/// capture's requests take its mixed inbound (the app never uses the system proxy implicitly);
/// without a session nowhere, so a lookup can never show the user's own address to a site.
pub(crate) fn enrich_inputs(enabled: bool, status: &TunStatus) -> EnrichInputs {
    let route = match (status.capture, status.session.as_ref()) {
        (Some(CaptureKind::Tun), Some(_)) => Some(Route::Direct),
        (Some(CaptureKind::Proxy), Some(s)) => s
            .proxy_port
            .and_then(|port| HostPort::new("127.0.0.1", port).ok())
            .map(|addr| Route::proxy(ProxyKind::Socks5, &addr, None)),
        _ => None,
    };
    EnrichInputs { enabled, route }
}

/// Every engine line into the history (it keeps only DNS answers).
async fn observe(
    mut lines: broadcast::Receiver<Arc<str>>,
    history: Arc<HistoryService>,
    cancel: CancellationToken,
) {
    loop {
        let line = tokio::select! {
            () = cancel.cancelled() => return,
            line = lines.recv() => line,
        };
        match line {
            Ok(line) => history.observe_log_line(&line),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::debug!(skipped = n, "traffic history: engine lines dropped");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Runs the enricher's tick only while the setting is on (switching it off aborts queued and
/// running lookups, the cache stays) and keeps its route in step with the session.
async fn follow(
    settings: Arc<Store<Settings>>,
    mut status: watch::Receiver<TunStatus>,
    history: Arc<HistoryService>,
    enricher: Enricher,
    tx: watch::Sender<EnrichInputs>,
    cancel: CancellationToken,
) {
    let mut changes = settings.subscribe();
    let mut tick: Option<CancellationToken> = None;
    loop {
        let enabled = settings.read(|s| s.domain_enrichment);
        let inputs = enrich_inputs(enabled, &status.borrow_and_update());
        tx.send_if_modified(|current| {
            let changed = *current != inputs;
            *current = inputs;
            changed
        });
        match (enabled, tick.take()) {
            (true, None) => {
                let token = cancel.child_token();
                enricher.spawn_tick(history.clone(), tx.subscribe(), token.clone());
                tick = Some(token);
                tracing::info!("site names: lookups on");
            }
            (false, Some(token)) => {
                token.cancel();
                tracing::info!("site names: lookups off");
            }
            (_, kept) => tick = kept,
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = changes.changed() => if changed.is_err() { return },
            changed = status.changed() => if changed.is_err() { return },
        }
    }
}
