//! The engines as the actor drives them: sing-box ([`CoreProc`]), the two Xray slots
//! ([`Slots`]) and the few network reads around them ([`Engines`]). [`RealEngines`] runs the
//! bundled binaries through `vpnte_engine`; the actor tests use fakes.
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{io, iter};

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
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
}

/// Engine binaries and the network reads the actor needs around them.
#[async_trait]
pub trait Engines: Send + Sync {
    /// Spawns sing-box with `config` on stdin.
    fn spawn_core(&self, config: &[u8]) -> io::Result<Arc<dyn CoreProc>>;
    /// A fresh slot pair for one session; exits of running slots arrive on `events`.
    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots>;
    /// The Xray binary (its own traffic leaves the machine directly).
    fn xray_exe(&self) -> PathBuf;
    /// Engine log files of a session (with or without the Xray slots).
    fn log_files(&self, slots: bool) -> Vec<PathBuf>;
    /// Points the selector `proxy-out` at `slot` and reads it back.
    async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()>;
    /// `(connection id, downloaded bytes)` of the open connections leaving through the upstream.
    async fn upstream_downloads(&self, clash: &ClashEndpoint) -> AppResult<Vec<(String, u64)>>;
    /// Resolves Xray's server names (Xray itself must never resolve: it would loop).
    async fn resolve(
        &self,
        hosts: &[String],
        path: ResolvePath,
        cancel: &CancellationToken,
    ) -> Result<Resolved, ResolveFault>;
    /// Public IPv4 seen through an authenticated loopback SOCKS listener (a staged slot).
    async fn egress_via(
        &self,
        port: u16,
        creds: &Creds,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr>;
    /// Public IPv4 seen through the default route (the tunnel once it is up).
    async fn egress(&self, timeout: Duration, cancel: &CancellationToken) -> AppResult<IpAddr>;
    /// The local proxy answers on TCP within `limit`; returns its listener's image path.
    async fn local_proxy(&self, addr: &HostPort, limit: Duration) -> AppResult<Option<PathBuf>>;
    /// IPv4 resolvers of the physical adapters (empty when unreadable).
    async fn physical_dns(&self) -> Vec<Ipv4Addr>;
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
}

/// Public-IP echo services, tried in order (plain-text IPv4 answers).
const ECHO_URLS: [&str; 2] = ["https://api.ipify.org", "https://ifconfig.me/ip"];
/// Cold SOCKS egress probe budget (xray-engine §3.8).
const EGRESS_VIA_BUDGET: Duration = Duration::from_secs(4);

/// The bundled engines. Paths must be the canonical install paths: the WFP permits match the
/// image path the processes run from.
pub struct RealEngines {
    singbox: PathBuf,
    xray: PathBuf,
    logs: Option<PathBuf>,
}

impl RealEngines {
    /// `logs` = the engine logs dir (`sing-box.log`, `xray-a.log`, `xray-b.log`).
    pub fn new(singbox: PathBuf, xray: PathBuf, logs: Option<PathBuf>) -> Self {
        Self {
            singbox,
            xray,
            logs,
        }
    }
}

/// The first public IP an echo service reports through `route`.
async fn echo(route: &Route, timeout: Duration, cancel: &CancellationToken) -> AppResult<IpAddr> {
    let client = client_for(route, timeout)?;
    let ask = async {
        for url in ECHO_URLS {
            let answer = match client.get(url).send().await {
                Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
                _ => None,
            };
            if let Some(ip) = answer.and_then(|t| t.trim().parse::<IpAddr>().ok()) {
                return Ok(ip);
            }
        }
        Err(AppError::msg(
            ErrorKind::Network,
            Msg::new("tunnel.runtime.egressUnknown"),
        ))
    };
    tokio::select! {
        () = cancel.cancelled() => Err(AppError::cancelled()),
        ip = ask => ip,
    }
}

#[async_trait]
impl Engines for RealEngines {
    fn spawn_core(&self, config: &[u8]) -> io::Result<Arc<dyn CoreProc>> {
        let core = SingBoxProcess::spawn(&self.singbox, config, self.logs.as_deref())?;
        Ok(Arc::new(core))
    }

    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots> {
        Box::new(XraySupervisor::new(
            self.xray.clone(),
            self.logs.clone(),
            events,
        ))
    }

    fn xray_exe(&self) -> PathBuf {
        self.xray.clone()
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
        port: u16,
        creds: &Creds,
        cancel: &CancellationToken,
    ) -> AppResult<IpAddr> {
        let addr = HostPort::new("127.0.0.1", port)?;
        let route = Route::proxy(ProxyKind::Socks5, &addr, Some(creds));
        echo(&route, EGRESS_VIA_BUDGET, cancel).await
    }

    async fn egress(&self, timeout: Duration, cancel: &CancellationToken) -> AppResult<IpAddr> {
        echo(&Route::Direct, timeout, cancel).await
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
}
