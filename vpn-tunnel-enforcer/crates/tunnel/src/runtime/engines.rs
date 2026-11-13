//! The engines as the actor drives them: sing-box ([`CoreProc`]), the two Xray slots
//! ([`Slots`]) and the few network reads around them ([`Engines`]). [`RealEngines`] runs the
//! bundled binaries through `vpnte_engine` (its slot egress probes wait for the app's
//! [`HandshakeGate`]); the actor tests use fakes.
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{io, iter};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, OutboundFault, ProxyKind};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::{HostPort, Route, client_for};
use vpnte_engine::clash_api::{ClashApi, ClashEndpoint};
use vpnte_engine::singbox_process::{ExitInfo, SingBoxProcess, StartError, StopError};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::tags::{PROXY_OUT, SLOT_TAGS};
use vpnte_engine::xray_config::{ResolveFault, ResolvePath, Resolved, resolve_hosts};
use vpnte_engine::xray_process::{SlotLaunch, XrayError, XrayEvent, XraySupervisor};
use vpnte_profiles::model::Profile;

/// One running sing-box (the real one: `SingBoxProcess`). Dropping the last handle kills it.
#[async_trait]
pub trait CoreProc: Send + Sync {
    /// Process id of the engine.
    fn pid(&self) -> u32;
    /// `sing-box started (` seen and the process alive.
    async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError>;
    /// Terminates and waits for the exit; `Ok` is the exit proof (idempotent).
    async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError>;
    /// `Some` once the process exited.
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>>;
    /// Upstream fault classified from the engine's recent output (crash table), if any.
    fn recent_fault(&self) -> Option<OutboundFault>;
}

/// The two Xray upstream slots of one session (the real one: `XraySupervisor`).
#[async_trait]
pub trait Slots: Send + Sync {
    /// Starts `slot` and waits for its authenticated SOCKS readiness; a failed start leaves
    /// nothing running.
    async fn start(
        &mut self,
        slot: Slot,
        ep: SlotEndpoint,
        launch: SlotLaunch,
        cancel: &CancellationToken,
    ) -> Result<(), XrayError>;
    /// Restarts a crashed slot with its previous launch (same port and credentials).
    async fn restart(&mut self, slot: Slot, cancel: &CancellationToken) -> Result<(), XrayError>;
    /// Stops `slot` (idempotent); `running` tells whether the exit was proven.
    async fn stop(&mut self, slot: Slot) -> Result<(), XrayError>;
    /// Stops both slots; `Err` when an exit was not proven.
    async fn stop_all(&mut self) -> Result<(), XrayError>;
    /// Marks `slot` active after the selector confirmed it.
    fn activate(&mut self, slot: Slot) -> Result<(), XrayError>;
    /// `slot` has a live process.
    fn running(&self, slot: Slot) -> bool;
    /// Upstream fault in the slot's output of the last two minutes: in a slot session sing-box
    /// only dials loopback, so the server's refusals show in Xray's log alone.
    fn recent_fault(&self, slot: Slot) -> Option<OutboundFault>;
}

/// Engine binaries and the network reads the actor needs around them.
#[async_trait]
pub trait Engines: Send + Sync {
    /// Spawns sing-box with `config` on stdin.
    fn spawn_core(&self, config: &[u8]) -> io::Result<Arc<dyn CoreProc>>;
    /// A fresh slot pair for one session; exits of running slots arrive on `events`.
    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots>;
    /// The sing-box binary (other processes of it: external proxy slots, probe engines).
    fn singbox_exe(&self) -> PathBuf;
    /// The Xray binary (its own traffic leaves the machine directly).
    fn xray_exe(&self) -> PathBuf;
    /// Engine log files of a session (with or without the Xray slots).
    fn log_files(&self, slots: bool) -> Vec<PathBuf>;
    /// Points the selector `proxy-out` at `slot` and reads it back.
    async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()>;
    /// `(connection id, downloaded bytes)` of the open connections leaving through the upstream.
    async fn upstream_downloads(&self, clash: &ClashEndpoint) -> AppResult<Vec<(String, u64)>>;
    /// Resolves server names before an engine dials them: Xray's (Xray itself must never
    /// resolve: it would loop) and a native profile's (pinned, see `pin`).
    async fn resolve(
        &self,
        hosts: &[String],
        path: ResolvePath,
        cancel: &CancellationToken,
    ) -> Result<Resolved, ResolveFault>;
    /// Public IPv4 seen through an authenticated loopback SOCKS listener (a staged slot): each
    /// echo request is a new handshake to `server`, the slot's upstream.
    async fn egress_via(
        &self,
        server: &Profile,
        port: u16,
        creds: &Creds,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr>;
    /// Public IPv4 seen through the running tunnel: the default route under the TUN, the
    /// session's loopback `mixed` inbound (`via`) under the proxy capture (the app's own
    /// requests never use the system proxy, so the default route would show the real address).
    async fn egress(
        &self,
        via: Option<u16>,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr>;
    /// The local proxy answers on TCP within `limit`; returns its listener's image path.
    async fn local_proxy(&self, addr: &HostPort, limit: Duration) -> AppResult<Option<PathBuf>>;
    /// IPv4 resolvers of the physical adapters (empty when unreadable).
    async fn physical_dns(&self) -> Vec<Ipv4Addr>;
    /// WP-12 lab: starts mihomo with `config` (translated for `socks` / `controller`) and waits
    /// for its readiness; a failed start leaves nothing running.
    #[cfg(feature = "lab")]
    async fn start_mihomo(
        &self,
        config: &vpnte_engine::mihomo_config::Compiled,
        socks: SlotEndpoint,
        controller: ClashEndpoint,
        cancel: &CancellationToken,
    ) -> AppResult<Arc<dyn CoreProc>>;
}

/// Admits the probe handshakes the runtime makes to a server. RU networks freeze a server name
/// for ~120 s after ~3 new TLS handshakes within a minute (Nov 2026), so the slot's egress probe
/// shares the app's handshake budget with every other check; this crate cannot depend on the
/// probes, the app hands the budget in.
#[async_trait]
pub trait HandshakeGate: Send + Sync {
    /// Waits for a handshake slot to `server`; `Err` = not now (the budget's "retry in N s") or
    /// cancelled.
    async fn admit(&self, server: &Profile, cancel: &CancellationToken) -> AppResult<()>;
}

#[async_trait]
impl CoreProc for SingBoxProcess {
    fn pid(&self) -> u32 {
        SingBoxProcess::pid(self)
    }
    async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError> {
        SingBoxProcess::wait_ready(self, timeout, cancel).await
    }
    async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError> {
        SingBoxProcess::terminate(self, within).await
    }
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        SingBoxProcess::exit_watch(self)
    }
    fn recent_fault(&self) -> Option<OutboundFault> {
        SingBoxProcess::recent_fault(self)
    }
}

#[async_trait]
impl Slots for XraySupervisor {
    async fn start(
        &mut self,
        slot: Slot,
        ep: SlotEndpoint,
        launch: SlotLaunch,
        cancel: &CancellationToken,
    ) -> Result<(), XrayError> {
        XraySupervisor::start(self, slot, ep, launch, cancel)
            .await
            .map(drop)
    }
    async fn restart(&mut self, slot: Slot, cancel: &CancellationToken) -> Result<(), XrayError> {
        XraySupervisor::restart(self, slot, cancel).await.map(drop)
    }
    async fn stop(&mut self, slot: Slot) -> Result<(), XrayError> {
        XraySupervisor::stop(self, slot).await
    }
    async fn stop_all(&mut self) -> Result<(), XrayError> {
        XraySupervisor::stop_all(self).await
    }
    fn activate(&mut self, slot: Slot) -> Result<(), XrayError> {
        XraySupervisor::activate(self, slot)
    }
    fn running(&self, slot: Slot) -> bool {
        self.status(slot).running
    }
    fn recent_fault(&self, slot: Slot) -> Option<OutboundFault> {
        XraySupervisor::recent_fault(self, slot)
    }
}

/// Public-IP echo services, tried in order (plain-text IPv4 answers).
const ECHO_URLS: [&str; 2] = ["https://api.ipify.org", "https://ifconfig.me/ip"];
/// Cold SOCKS egress probe budget (xray-engine §3.8).
const EGRESS_VIA_BUDGET: Duration = Duration::from_secs(4);

/// The engine executables a runtime starts. Canonical install paths: the WFP permits match the
/// image path the processes run from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineExes {
    pub singbox: PathBuf,
    pub xray: PathBuf,
}

/// The engine files a runtime started, per engine. The update channel's trial charges a start
/// to an engine version only when that version's file ran for it: an in-place server switch
/// keeps the running processes, and Tunnel mode through the helper service runs none here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineStarts {
    /// sing-box cores (attempts: a file that does not even spawn counts as well).
    pub singbox: Started,
    /// Xray slot sets, one per session start that needs Xray.
    pub xray: Started,
}

/// The starts of one engine: how many so far, and the file of the last one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Started {
    pub count: u64,
    pub exe: Option<PathBuf>,
}

impl Started {
    fn bump(&mut self, exe: &Path) {
        self.count += 1;
        self.exe = Some(exe.to_path_buf());
    }
}

/// The real engines over `vpnte_engine`.
pub struct RealEngines {
    /// Read at every engine start: the update channel may switch an engine while the app runs
    /// (a running sing-box or Xray slot set keeps the file it started from).
    exes: watch::Receiver<EngineExes>,
    /// Every file started, as it starts.
    starts: watch::Sender<EngineStarts>,
    logs: Option<PathBuf>,
    gate: Option<Arc<dyn HandshakeGate>>,
    feed: EngineFeed,
    /// WP-12 lab: the mihomo exe and the dir of its per-run home dirs.
    #[cfg(feature = "lab")]
    mihomo: Option<(PathBuf, PathBuf)>,
}

impl RealEngines {
    /// Fixed engines (the helper service runs only its own pinned files). `logs` = the engine
    /// logs dir (`sing-box.log`, `xray-a.log`, `xray-b.log`).
    pub fn new(singbox: PathBuf, xray: PathBuf, logs: Option<PathBuf>) -> Self {
        Self::following(watch::channel(EngineExes { singbox, xray }).1, logs)
    }

    /// Engines that follow `exes`: every start reads the paths current then, so an engine the
    /// update channel installed or rolled back runs from the next start on, without an app
    /// restart.
    pub fn following(exes: watch::Receiver<EngineExes>, logs: Option<PathBuf>) -> Self {
        Self {
            exes,
            starts: watch::channel(EngineStarts::default()).0,
            logs,
            gate: None,
            feed: EngineFeed::default(),
            #[cfg(feature = "lab")]
            mihomo: None,
        }
    }

    /// WP-12 lab: the mihomo exe (canonical install path) and a private dir for its run homes
    /// (swept here: nothing runs yet).
    #[cfg(feature = "lab")]
    #[must_use]
    pub fn with_mihomo(mut self, exe: PathBuf, runs: PathBuf) -> Self {
        vpnte_engine::mihomo_process::sweep_homes(&runs);
        self.mihomo = Some((exe, runs));
        self
    }

    /// The engine files this runtime started so far ([`EngineStarts`]).
    pub fn starts(&self) -> watch::Receiver<EngineStarts> {
        self.starts.subscribe()
    }

    /// Every egress probe through a slot first waits for `gate` (the app's handshake budget).
    #[must_use]
    pub fn with_gate(mut self, gate: Arc<dyn HandshakeGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// What the cores this runtime starts hand to in-process consumers (take it before the
    /// engines move into the runtime).
    pub fn feed(&self) -> EngineFeed {
        self.feed.clone()
    }
}

/// Lines a subscriber may fall behind before it loses the oldest ones.
const FEED_BACKLOG: usize = 1024;

/// The sing-box cores of one runtime as in-process consumers see them: their raw output lines
/// in one stream that outlives crash restarts (the traffic history parses DNS answers from it),
/// and the config of the last core started (the diagnostics export redacts it). Both hold
/// secrets: never log them; the config stays in memory only.
#[derive(Clone)]
pub struct EngineFeed {
    lines: broadcast::Sender<Arc<str>>,
    config: Arc<Mutex<Option<Arc<[u8]>>>>,
}

impl Default for EngineFeed {
    fn default() -> Self {
        Self {
            lines: broadcast::channel(FEED_BACKLOG).0,
            config: Arc::default(),
        }
    }
}

impl EngineFeed {
    /// Raw lines of every core started from now on (a slow reader loses the oldest lines).
    pub fn subscribe_lines(&self) -> broadcast::Receiver<Arc<str>> {
        self.lines.subscribe()
    }

    /// The config the last core was started with (JSON bytes); `None` before the first start.
    pub fn last_config(&self) -> Option<Arc<[u8]>> {
        self.config.lock().clone()
    }

    /// Keeps `config` and forwards `lines` until the core's output ends. Without a runtime (no
    /// subscriber could exist) nothing is forwarded.
    fn attach(&self, config: &[u8], mut lines: broadcast::Receiver<Arc<str>>) {
        *self.config.lock() = Some(Arc::from(config));
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let out = self.lines.clone();
        runtime.spawn(async move {
            loop {
                match lines.recv().await {
                    // No subscriber right now: the line is simply not wanted.
                    Ok(line) => drop(out.send(line)),
                    // Lost lines are lost for every consumer alike; the engine never waits.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }
}

/// Why no address came back from the echo services: the source of their `egressUnknown` error,
/// so a caller can tell a silent route from one that answered (audit mihomo-b3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum EchoFailure {
    /// No service sent an HTTP answer: nothing came back through the route.
    #[error("no echo service answered through the route")]
    NoReply,
    /// Answers came back (an error status, a page that is not an address): the route carries
    /// traffic, only the address is unknown.
    #[error("the echo services answered without an address")]
    NoAddress,
}

/// The `egressUnknown` error of an echo that found no address, with its cause.
pub(super) fn echo_failed(why: EchoFailure) -> AppError {
    AppError::msg(ErrorKind::Network, Msg::new("tunnel.runtime.egressUnknown")).with_source(why)
}

/// What `err` says about the route, when it is an echo's own failure.
#[cfg(feature = "lab")]
pub(super) fn echo_failure(err: &AppError) -> Option<EchoFailure> {
    err.source.as_ref()?.downcast_ref::<EchoFailure>().copied()
}

/// The first public IP an echo service reports through `route`. With `admit`, every request
/// first takes a handshake slot of the server behind the route: the fallback service is a new
/// connection, and an unbudgeted retry against a freezing server extends the freeze.
async fn echo(
    route: &Route,
    timeout: Duration,
    admit: Option<(&dyn HandshakeGate, &Profile)>,
    cancel: &CancellationToken,
) -> AppResult<IpAddr> {
    let client = client_for(route, timeout)?;
    let ask = async {
        let mut why = EchoFailure::NoReply;
        for url in ECHO_URLS {
            if let Some((gate, server)) = admit {
                gate.admit(server, cancel).await?;
            }
            let Ok(resp) = client.get(url).send().await else {
                continue;
            };
            why = EchoFailure::NoAddress;
            let answer = if resp.status().is_success() {
                resp.text().await.ok()
            } else {
                None
            };
            if let Some(ip) = answer.and_then(|t| t.trim().parse::<IpAddr>().ok()) {
                return Ok(ip);
            }
        }
        Err(echo_failed(why))
    };
    tokio::select! {
        () = cancel.cancelled() => Err(AppError::cancelled()),
        ip = ask => ip,
    }
}

#[async_trait]
impl Engines for RealEngines {
    fn spawn_core(&self, config: &[u8]) -> io::Result<Arc<dyn CoreProc>> {
        let exe = self.singbox_exe();
        self.starts.send_modify(|s| s.singbox.bump(&exe));
        let core = SingBoxProcess::spawn(&exe, config, self.logs.as_deref())?;
        self.feed.attach(config, core.subscribe_lines());
        Ok(Arc::new(core))
    }

    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots> {
        let exe = self.xray_exe();
        self.starts.send_modify(|s| s.xray.bump(&exe));
        Box::new(XraySupervisor::new(exe, self.logs.clone(), events))
    }

    fn singbox_exe(&self) -> PathBuf {
        self.exes.borrow().singbox.clone()
    }

    fn xray_exe(&self) -> PathBuf {
        self.exes.borrow().xray.clone()
    }

    fn log_files(&self, slots: bool) -> Vec<PathBuf> {
        let Some(dir) = &self.logs else {
            return Vec::new();
        };
        let xray = Slot::BOTH.iter().filter(|_| slots).map(|s| s.log_stem());
        iter::once(vpnte_engine::singbox_process::LOG_STEM)
            .chain(xray)
            .map(|stem| dir.join(format!("{stem}.log")))
            .collect()
    }

    async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()> {
        let api = ClashApi::new(clash)?;
        api.select(PROXY_OUT, slot.tag(), &SLOT_TAGS).await?;
        Ok(())
    }

    async fn upstream_downloads(&self, clash: &ClashEndpoint) -> AppResult<Vec<(String, u64)>> {
        let api = ClashApi::new(clash)?;
        let snapshot = api.connections().await?;
        let upstream = |tag: &String| tag == PROXY_OUT || SLOT_TAGS.contains(&tag.as_str());
        Ok(snapshot
            .connections
            .into_iter()
            .filter(|c| c.chains.iter().any(upstream))
            .map(|c| (c.id, c.download))
            .collect())
    }

    async fn resolve(
        &self,
        hosts: &[String],
        path: ResolvePath,
        cancel: &CancellationToken,
    ) -> Result<Resolved, ResolveFault> {
        resolve_hosts(hosts, path, cancel).await
    }

    async fn egress_via(
        &self,
        server: &Profile,
        port: u16,
        creds: &Creds,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        let addr = HostPort::new("127.0.0.1", port)?;
        let route = Route::proxy(ProxyKind::Socks5, &addr, Some(creds));
        let admit = self.gate.as_deref().map(|gate| (gate, server));
        echo(&route, EGRESS_VIA_BUDGET, admit, cancel).await
    }

    async fn egress(
        &self,
        via: Option<u16>,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        let route = match via {
            Some(port) => {
                let addr = HostPort::new("127.0.0.1", port)?;
                Route::proxy(ProxyKind::Socks5, &addr, None)
            }
            None => Route::Direct,
        };
        echo(&route, timeout, None, cancel).await
    }

    async fn local_proxy(&self, addr: &HostPort, limit: Duration) -> AppResult<Option<PathBuf>> {
        let unreachable = || {
            AppError::msg(
                ErrorKind::Network,
                Msg::new("tunnel.runtime.proxyNotListening").arg("addr", addr),
            )
        };
        // If the client is closed or in its own TUN mode the port does not listen: starting the
        // TUN anyway would blackhole all traffic.
        let stream = tokio::time::timeout(limit, tokio::net::TcpStream::connect(addr.to_string()))
            .await
            .map_err(|_| unreachable())?
            .map_err(|e| unreachable().with_source(e))?;
        let peer = stream.peer_addr().map_err(AppError::from)?;
        drop(stream);
        let hosts = [
            peer.ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        ];
        let port = addr.port();
        let owner = tokio::task::spawn_blocking(move || {
            vpnte_winnet::process::listener_owner(
                vpnte_winnet::process::Transport::Tcp,
                port,
                &hosts,
            )
        })
        .await
        .map_err(AppError::internal)?;
        match owner {
            Ok(owner) => Ok(owner.and_then(|o| o.image)),
            Err(e) => {
                tracing::warn!(error = %e, "local proxy owner unreadable");
                Ok(None)
            }
        }
    }

    async fn physical_dns(&self) -> Vec<Ipv4Addr> {
        let read = tokio::task::spawn_blocking(vpnte_winnet::adapters::physical_dns_v4).await;
        match read {
            Ok(Ok(dns)) => dns,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "physical DNS unreadable: engine defaults apply");
                Vec::new()
            }
            Err(e) => {
                tracing::warn!(error = %e, "physical DNS read panicked");
                Vec::new()
            }
        }
    }

    #[cfg(feature = "lab")]
    async fn start_mihomo(
        &self,
        config: &vpnte_engine::mihomo_config::Compiled,
        socks: SlotEndpoint,
        controller: ClashEndpoint,
        cancel: &CancellationToken,
    ) -> AppResult<Arc<dyn CoreProc>> {
        let Some((exe, runs)) = &self.mihomo else {
            let msg = Msg::new("tunnel.runtime.mihomo.unavailable");
            return Err(AppError::msg(ErrorKind::Internal, msg));
        };
        let logs = self.logs.as_deref();
        super::mihomo::start_run(exe, runs, logs, config, socks, controller, cancel).await
    }
}

#[cfg(test)]
mod feed_tests {
    use super::*;

    /// The feed keeps the last config and forwards a core's lines until its output ends; a
    /// subscriber taken before the core started sees every line of every core.
    #[tokio::test]
    async fn the_feed_forwards_lines_of_every_core_and_keeps_the_last_config() {
        let feed = EngineFeed::default();
        assert!(feed.last_config().is_none());
        let mut rx = feed.subscribe_lines();
        for (config, line) in [(&b"{\"a\":1}"[..], "first"), (&b"{\"b\":2}"[..], "second")] {
            let (core, core_rx) = broadcast::channel::<Arc<str>>(8);
            feed.attach(config, core_rx);
            core.send(Arc::from(line)).unwrap();
            let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("forwarded")
                .unwrap();
            assert_eq!(&*got, line);
            assert_eq!(feed.last_config().as_deref(), Some(config));
            // The core's output ended: its forwarder ends, the feed stays open.
            drop(core);
        }
        assert!(rx.try_recv().is_err());
    }
}

#[cfg(test)]
mod exes_tests {
    use super::*;

    fn exes(dir: &str) -> EngineExes {
        EngineExes {
            singbox: PathBuf::from(dir).join("sing-box.exe"),
            xray: PathBuf::from(dir).join("xray.exe"),
        }
    }

    /// p-follow (p-updates follow-up): engines that follow the update channel start from the
    /// paths current at each start, so a newly installed engine needs no app restart; fixed ones
    /// (the helper service) keep theirs.
    #[test]
    fn every_start_reads_the_current_engine_paths() {
        let (tx, rx) = watch::channel(exes("bundled"));
        let following = RealEngines::following(rx, None);
        assert_eq!(following.singbox_exe(), exes("bundled").singbox);
        tx.send_replace(exes("1.14.5"));
        assert_eq!(following.singbox_exe(), exes("1.14.5").singbox);
        assert_eq!(following.xray_exe(), exes("1.14.5").xray);
        let fixed = RealEngines::new(exes("pinned").singbox, exes("pinned").xray, None);
        assert_eq!(fixed.singbox_exe(), exes("pinned").singbox);
        assert_eq!(fixed.xray_exe(), exes("pinned").xray);
    }

    /// fix-follow (pfollow-b1): each engine file a start runs is counted with its path, even a
    /// file that does not spawn; nothing else bumps the counts (no file here exists, so nothing
    /// runs).
    #[tokio::test]
    async fn every_engine_start_is_counted_with_its_file() {
        let (tx, rx) = watch::channel(exes("no-such-dir-a"));
        let engines = RealEngines::following(rx, None);
        let starts = engines.starts();
        assert_eq!(*starts.borrow(), EngineStarts::default());
        assert!(engines.spawn_core(b"{}").is_err(), "no such file");
        tx.send_replace(exes("no-such-dir-b"));
        drop(engines.slots(mpsc::channel(1).0));
        let seen = starts.borrow().clone();
        assert_eq!(seen.singbox.count, 1);
        assert_eq!(seen.singbox.exe, Some(exes("no-such-dir-a").singbox));
        assert_eq!(seen.xray.count, 1);
        assert_eq!(seen.xray.exe, Some(exes("no-such-dir-b").xray));
    }
}
