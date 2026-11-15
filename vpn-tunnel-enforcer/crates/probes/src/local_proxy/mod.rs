//! Detection of a third-party local proxy (Happ, v2rayN, Clash, NekoRay, …) that Hard mode puts
//! under the TUN. Candidates come from client configs, system proxy settings, loopback listeners
//! and typical ports (that priority order, as in the old scan); they are classified by a protocol
//! handshake, and the winner is verified once through an IP echo. Detection is behaviour-based:
//! a process name only orders candidates.
mod candidates;
mod handshake;
mod system;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde::Serialize;
use tokio::time::{Instant, timeout_at};
use vpnte_base::types::ProxyKind;

pub use candidates::{
    CONFIG_DIRS, Candidate, ListenerRow, Source, TYPICAL_PORTS, config_candidates,
    listener_candidates, merge, proxy_server_candidates, strip_comment, text_candidates,
    typical_candidates,
};
pub use handshake::{
    Attempt, CHECK_HOST, ECHO_URL, PROBE_TIMEOUT, attempt, classify, is_http_200, pick, verify,
};
pub use system::{
    PROXY_ENV, SystemProxy, WinInet, config_roots, listener_rows, read_winhttp, scan_configs,
};

/// Whole scan budget, verification included.
pub const SCAN_BUDGET: Duration = Duration::from_secs(6);
/// Longest wait for the verification request.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// A verified result is reused this long (measured from scan completion).
pub const POSITIVE_TTL: Duration = Duration::from_secs(8);
/// "Nothing found" / "found but not verified" is reused only this long, so a proxy that was just
/// started is found by the next poll.
pub const NEGATIVE_TTL: Duration = Duration::from_millis(500);

/// A local proxy found on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProxy {
    pub addr: SocketAddr,
    pub kind: ProxyKind,
    pub source: Source,
    /// A request through it reached the Internet (the IP echo answered).
    pub verified: bool,
    /// Public IP seen through it, from the verification request.
    pub public_ip: Option<IpAddr>,
}

impl LocalProxy {
    /// `127.0.0.1:10808 (socks5)`: log-safe label, also used in user-facing arguments.
    pub fn label(&self) -> String {
        let kind = match self.kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        };
        format!("{} ({kind})", self.addr)
    }
}

/// What the real scan must leave out: the app's own loopback listeners.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOptions {
    /// Ports of the app's own listeners (engine inbounds, external proxy slots).
    pub skip_ports: Vec<u16>,
    /// Extra process ids to ignore; this process is always ignored.
    pub skip_pids: Vec<u32>,
}

/// One full scan of the system, budget [`SCAN_BUDGET`].
pub async fn scan(options: ScanOptions) -> Option<LocalProxy> {
    let deadline = Instant::now() + SCAN_BUDGET;
    let gather = async move {
        let roots = config_roots();
        let configs = tokio::task::spawn_blocking(move || scan_configs(&roots));
        let system = tokio::task::spawn_blocking(|| SystemProxy::read().candidates());
        let listeners = tokio::task::spawn_blocking(move || {
            let mut pids = options.skip_pids.clone();
            pids.push(std::process::id());
            listener_rows()
                .map(|rows| listener_candidates(&rows, &pids, &options.skip_ports))
                .unwrap_or_default()
        });
        let (configs, system, listeners) = tokio::join!(configs, system, listeners);
        merge([
            configs.unwrap_or_default(),
            system.unwrap_or_default(),
            listeners.unwrap_or_default(),
            typical_candidates(),
        ])
    };
    let candidates = timeout_at(deadline, gather).await.ok()?;
    let (winner, kind) = timeout_at(deadline, pick(candidates)).await.ok()??;
    let left = deadline
        .saturating_duration_since(Instant::now())
        .min(VERIFY_TIMEOUT);
    let public_ip = verify(winner.addr, kind, left.max(Duration::from_millis(1))).await;
    let found = LocalProxy {
        addr: winner.addr,
        kind,
        source: winner.source,
        verified: public_ip.is_some(),
        public_ip,
    };
    tracing::info!(proxy = %found.label(), verified = found.verified, "local proxy detected");
    Some(found)
}

/// A scan run by the detector (the real one is [`scan`]).
pub type ScanFn = Arc<dyn Fn() -> BoxFuture<'static, Option<LocalProxy>> + Send + Sync>;
/// Monotonic clock of the detector's cache.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Single-flight detector with a short cache: concurrent callers share one scan; a result is
/// reused [`POSITIVE_TTL`] when verified, else [`NEGATIVE_TTL`], counted from scan completion.
/// A scan that is cancelled (caller dropped) leaves no cache, so the next caller rescans.
pub struct LocalProxyDetector {
    scan: ScanFn,
    now: Clock,
    cache: tokio::sync::Mutex<Option<(Instant, Option<LocalProxy>)>>,
}

impl LocalProxyDetector {
    /// Detector over the real system.
    pub fn new(options: ScanOptions) -> Self {
        let scan: ScanFn = Arc::new(move || Box::pin(scan(options.clone())));
        Self::with_scanner(scan, Arc::new(Instant::now))
    }

    /// Detector over a custom scan and clock (tests, alternative sources).
    pub fn with_scanner(scan: ScanFn, now: Clock) -> Self {
        Self {
            scan,
            now,
            cache: tokio::sync::Mutex::new(None),
        }
    }

    /// The local proxy, from the cache or a fresh scan.
    pub async fn detect(&self) -> Option<LocalProxy> {
        let mut cache = self.cache.lock().await;
        if let Some((at, result)) = cache.as_ref() {
            let ttl = if result.as_ref().is_some_and(|p| p.verified) {
                POSITIVE_TTL
            } else {
                NEGATIVE_TTL
            };
            if (self.now)().saturating_duration_since(*at) < ttl {
                return result.clone();
            }
        }
        let result = (self.scan)().await;
        *cache = Some(((self.now)(), result.clone()));
        result
    }

    /// Cheap local re-handshake of a known proxy (the idle poll); a full scan only when it fails.
    pub async fn recheck(&self, known: &LocalProxy) -> bool {
        attempt(known.addr, known.kind, PROBE_TIMEOUT).await == Attempt::Speaks
    }
}

#[cfg(test)]
mod tests;
