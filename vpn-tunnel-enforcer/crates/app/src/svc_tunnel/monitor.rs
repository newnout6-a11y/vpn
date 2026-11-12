//! [`Monitor`] and [`Confirmations`] over the public-IP monitor (monitoring §3.4, §6.2): one
//! monitored connection per tunnel session, the home IP read through the engine's direct-out,
//! the exit adopted through the session's own path (TUN-bound sockets or the mixed inbound).
//! Between sessions the home IP comes from [`home`] (owner decision 13).
mod home;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, Loopback};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::geo::Geo;
use vpnte_probes::ip_monitor::{AdoptError, ConnId, IpMonitor};
use vpnte_probes::public_ip::{Family, IpReader, IpRoute, WAVE_BUDGET};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_tunnel::lifecycle::Monitor;
use vpnte_tunnel::runtime::Confirmations;
use vpnte_winnet::adapters::{self, TUN_V4};

use super::decide::check_interval;
use super::leaks::Leaks;

/// Exit adoption after a connect: up to 4 reads, 2 s apart (monitoring §3.4).
const ADOPT_ATTEMPTS: u32 = 4;
const ADOPT_PAUSE: Duration = Duration::from_secs(2);
/// Debounce of the network-change watch behind the home-address reads.
const NET_SETTLE: Duration = Duration::from_millis(1500);

/// The public-IP side of a session.
pub(super) struct IpWatch {
    pub ip: IpMonitor,
    reader: Arc<IpReader>,
    settings: Arc<Store<Settings>>,
    status: watch::Receiver<TunStatus>,
    conn: AtomicU64,
    adopting: Mutex<Option<CancellationToken>>,
    /// Background leak self-tests (elevated process only).
    pub leaks: Option<Leaks>,
    shutdown: CancellationToken,
}

impl IpWatch {
    /// `ip` reads through `reader`; `status` is the runtime's status watch.
    pub fn new(
        ip: IpMonitor,
        reader: Arc<IpReader>,
        settings: Arc<Store<Settings>>,
        status: watch::Receiver<TunStatus>,
        leaks: Option<Leaks>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            ip,
            reader,
            settings,
            status,
            conn: AtomicU64::new(0),
            adopting: Mutex::new(None),
            leaks,
            shutdown,
        }
    }

    /// The reader the leak check shares (one 429 backoff for the process).
    pub fn reader(&self) -> &IpReader {
        &self.reader
    }

    /// Starts the home-address reads between sessions under `cancel`; `geo` is the switch of the
    /// "no online lookups" setting, kept in step by whoever saves it.
    pub fn spawn_home_reads(&self, geo: Geo, cancel: CancellationToken) {
        let changes = adapters::watch_network(NET_SETTLE, cancel.clone())
            .inspect_err(
                |err| tracing::warn!(%err, "no network-change watch: home IP read at start only"),
            )
            .ok();
        let reads = home::HomeReads {
            sampler: self.reader.clone(),
            ip: self.ip.clone(),
            geo,
            status: self.status.clone(),
        };
        tokio::spawn(reads.run(changes, cancel));
    }

    fn cancel_adoption(&self) {
        if let Some(token) = self.adopting.lock().take() {
            token.cancel();
        }
    }

    /// The machine woke from sleep or the session was unlocked: the protection and the DNS
    /// capture are re-checked at once (elevated process only: that is where they exist).
    pub fn resumed(&self) {
        if let Some(leaks) = &self.leaks {
            leaks.resumed();
        }
    }
}

/// Where the running session's traffic leaves: the TUN, or the mixed inbound of a proxy
/// capture (the adaptive bypass probes through it); `None` without a running session.
pub(crate) fn exit_route(status: &TunStatus) -> Option<IpRoute> {
    routes(status).map(|(exit, _)| exit)
}

/// Where this session's traffic leaves (the monitored route) and where the user's own traffic
/// leaves (the engine's authenticated direct-out); `None` without a running session.
fn routes(status: &TunStatus) -> Option<(IpRoute, IpRoute)> {
    let session = status.session.as_ref()?;
    let exit = match status.capture? {
        // A socket bound to the TUN address can only leave through the TUN (strong-host model).
        // The exit is adopted as IPv4, so the periodic reads stay on IPv4 too.
        CaptureKind::Tun => IpRoute::Tun {
            v4: TUN_V4.addr(),
            v6: None,
        },
        // The mixed inbound of a proxy capture takes SOCKS5 without authentication.
        CaptureKind::Proxy => IpRoute::Loopback(Loopback {
            port: session.proxy_port?,
            creds: None,
        }),
    };
    let home = IpRoute::Loopback(Loopback {
        port: session.direct.port,
        creds: Some(Creds {
            user: session.direct.user.clone(),
            pass: session.direct.pass.clone(),
        }),
    });
    Some((exit, home))
}

impl Monitor for IpWatch {
    fn suppress_leak_tests(&self, span: Duration) {
        if let Some(leaks) = &self.leaks {
            leaks.watch.suppress(span);
        }
    }

    fn start(&self, _generation: Option<u64>) {
        let Some((exit, home)) = routes(&self.status.borrow()) else {
            tracing::warn!("ip monitor: the session has no endpoints; not started");
            return;
        };
        let conn = self.conn.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(leaks) = &self.leaks {
            // The leak check card shows this session's self-test only.
            leaks.latest.lock().take();
        }
        self.ip
            .start(conn, exit, check_interval(&self.settings.snapshot()));
        let token = self.shutdown.child_token();
        if let Some(old) = self.adopting.lock().replace(token.clone()) {
            old.cancel();
        }
        tokio::spawn(adopt(
            self.ip.clone(),
            self.reader.clone(),
            conn,
            home,
            token,
        ));
    }

    fn stop(&self) {
        self.cancel_adoption();
        self.ip.stop();
    }

    fn egress_ip(&self) -> Option<String> {
        let e = self.ip.evidence();
        e.baseline.or(e.last.map(|s| s.ip)).map(|ip| ip.to_string())
    }
}

/// The runtime's outside evidence that the tunnel carries traffic: a TUN-bound read showed the
/// adopted exit recently (B-IP-4). Built before the runtime, so it holds the monitor alone.
pub(super) struct Alive(pub IpMonitor);

impl Confirmations for Alive {
    fn confirmed_within(&self, age: Duration) -> bool {
        self.0.last_alive().is_some_and(|at| at.elapsed() <= age)
    }
}

/// Reads the home IP (what a leak would show), then adopts the session's exit.
async fn adopt(
    ip: IpMonitor,
    reader: Arc<IpReader>,
    conn: ConnId,
    home: IpRoute,
    cancel: CancellationToken,
) {
    // A failed read keeps the previous home IP: only an exit equal to it could be misjudged.
    if let Some(sample) = reader.wave(&home, Family::V4, WAVE_BUDGET, &cancel).await {
        ip.set_real_ip(Some(sample.ip));
    }
    for attempt in 1..=ADOPT_ATTEMPTS {
        match ip.adopt_baseline(conn, None, &cancel).await {
            Ok(_) => return,
            // Stale: another session took over; RealIp: the verdict is `Failed` and stays so.
            Err(AdoptError::Cancelled | AdoptError::Stale | AdoptError::RealIp) => return,
            Err(e) => tracing::debug!(attempt, error = %e, "exit IP not adopted yet"),
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(ADOPT_PAUSE) => {}
        }
    }
    tracing::info!("exit IP not adopted after the post-connect reads: not checked");
}
