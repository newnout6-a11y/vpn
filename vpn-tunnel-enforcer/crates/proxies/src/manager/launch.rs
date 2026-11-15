//! Starting a slot's engine (spec 6.4, 6.6, 6.7; B-11, B-21, B-27, B-28, B-29): the engine the
//! main tunnel would pick for the profile, endpoint names resolved by the app and pinned into
//! the config (the slot config has no DNS of its own, so no plaintext bootstrap query leaves
//! outside the tunnel), then `sing-box run -c stdin`, ready once the slot listener accepts.
//! Xray profiles run as a chain: the slot's sing-box forwards over SOCKS5 to a per-slot Xray
//! child on an ephemeral loopback port; either child exiting fails the slot.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::Engine as EngineKind;
use vpnte_core::net;
use vpnte_core::resolve::{ResolveError, ServerAddrs, resolve_server};
use vpnte_core::socks5::{self, SocksError};
use vpnte_engine::singbox_process::{ExitInfo, SingBoxProcess};
use vpnte_engine::slot::{Slot as XraySlot, SlotEndpoint};
use vpnte_engine::xray_config::{build_config, proxy_graph, select_engine};
use vpnte_engine::xray_process::{SlotLaunch, XrayEvent, XraySupervisor};
use vpnte_profiles::emit_singbox::{EmitPolicy, SingBoxFragment, emit_singbox};
use vpnte_profiles::model::Profile;
use vpnte_winnet::elevation::is_elevated;

use super::EngineChoice;
use crate::config::{self, PROXY_OUT_TAG};
use crate::model::ProxyError;

/// The slot listener must accept this soon after the spawn (B-11: replaces `sing-box check`).
pub(super) const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// Exit wait after a terminate (B-18).
pub(super) const STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a resolved endpoint stays pinned (old `ENDPOINT_RESOLUTION_TTL_MS`).
const RESOLVE_TTL: Duration = Duration::from_secs(300);

/// Everything a start needs, prepared before the slot's old engine is stopped. No `Debug`: the
/// configs carry server credentials.
pub(crate) struct Plan {
    pub port: u16,
    /// sing-box config (JSON) for stdin.
    pub singbox: Vec<u8>,
    pub xray: Option<XrayPlan>,
    /// What the slot runs without, for its row (`proxies.slot.spoofDropped`).
    pub notice: Option<Msg>,
}

/// The per-slot Xray child of an Xray profile.
pub(crate) struct XrayPlan {
    pub endpoint: SlotEndpoint,
    pub launch: SlotLaunch,
}

/// Builds the start plan of `profile` on `port`: engine selection as for the main tunnel,
/// every server name resolved and pinned, the slot config generated.
pub(super) async fn prepare(
    profile: &Profile,
    port: u16,
    choice: EngineChoice,
    names: &Names,
) -> Result<Plan, ProxyError> {
    let engine = select_engine(profile, choice.pref)
        .engine()
        .map_err(|reject| ProxyError::Refused(reject.msg()))?;
    if engine == EngineKind::SingBox {
        let policy = EmitPolicy {
            device: Some(choice.device),
            ..EmitPolicy::default()
        };
        let mut upstream = emit_singbox(profile, PROXY_OUT_TAG, &policy)
            .map_err(|e| ProxyError::Engine(format!("cannot build the proxy outbound: {e}")))?;
        let notice = gate_spoof(&mut upstream, &profile.name, is_elevated());
        for host in config::hostnames(&upstream) {
            let ip = names.resolve(&host).await?;
            config::pin(&mut upstream, &host, ip);
        }
        let singbox = config::build(&upstream, port)?.to_string().into_bytes();
        return Ok(Plan {
            port,
            singbox,
            xray: None,
            notice,
        });
    }
    let mut graph = proxy_graph(profile, choice.device)
        .map_err(|e| ProxyError::Engine(format!("cannot build the Xray config: {e}")))?;
    let mut resolved = HashMap::new();
    for host in graph.hosts() {
        let ip = names.resolve(&host).await?;
        resolved.insert(host, ip);
    }
    graph.substitute(&resolved);
    let endpoint = SlotEndpoint::allocate(&[port])
        .map_err(|e| ProxyError::Engine(format!("no port for the Xray child: {e}")))?;
    let bridge = config::xray_bridge(endpoint.port(), endpoint.creds())?;
    let singbox = config::build(&bridge, port)?.to_string().into_bytes();
    let launch = SlotLaunch {
        config: build_config(&graph, &endpoint).to_string().into_bytes(),
        // Only the supervisor's own status would report it, and nothing here reads that.
        dial_target: None,
    };
    Ok(Plan {
        port,
        singbox,
        xray: Some(XrayPlan { endpoint, launch }),
        notice: None,
    })
}

/// Audit item 18 on the slot path: a provider's `tls.spoof` needs an elevated sing-box, so an
/// unelevated slot runs without it and its row says so (the same note as the main tunnel's).
fn gate_spoof(upstream: &mut SingBoxFragment, name: &str, elevated: bool) -> Option<Msg> {
    vpnte_engine::singbox_config::gate_spoof(upstream, elevated)
        .then(|| Msg::new("proxies.slot.spoofDropped").arg("name", name))
}

/// Endpoint names resolved by the app, cached for five minutes, in the order of
/// `vpnte_core::resolve::resolve_server`: the direct DoH / TCP chain that sees through the
/// Russian DNS blocking (through the main tunnel when that is up), the OS resolver, then the
/// address the name had last time. A censored network's poisoned plaintext answer is never
/// asked from the engine.
#[derive(Default)]
pub(super) struct Names {
    cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl Names {
    /// The address to dial for `host`.
    pub(super) async fn resolve(&self, host: &str) -> Result<IpAddr, ProxyError> {
        let key = host.trim().to_ascii_lowercase();
        let cached = self.cache.lock().get(&key).copied();
        if let Some((ip, at)) = cached
            && at.elapsed() < RESOLVE_TTL
        {
            return Ok(ip);
        }
        let found = resolve_server(&key, dialable).await;
        // A bridged answer is not cached: the next start asks the live resolvers again.
        let live = found.as_ref().is_ok_and(|f| !f.last_known);
        let ip = pick(&key, found)?;
        if live {
            self.cache.lock().insert(key, (ip, Instant::now()));
        }
        Ok(ip)
    }
}

/// Block-page answers (loopback, `0.0.0.0/8`, link-local, multicast, broadcast) are not
/// servers; private and CGNAT servers are accepted.
fn dialable(ip: IpAddr) -> bool {
    let ip = net::unmap(ip);
    let special = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 0 || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    };
    !(special || ip.is_multicast() || net::is_loopback(ip) || net::is_link_local(ip))
}

/// The address to dial from a `resolve_server` answer (IPv4 preferred). The slot API has no
/// channel for a non-fatal warning, so a last known address is logged, never silent.
pub(super) fn pick(
    host: &str,
    found: Result<ServerAddrs, ResolveError>,
) -> Result<IpAddr, ProxyError> {
    match found {
        Ok(found) => {
            if found.last_known {
                tracing::warn!("proxy endpoint unresolvable; dialing its last known address");
            }
            config::preferred_address(&found.addrs)
                .ok_or_else(|| ProxyError::Engine(format!("cannot resolve {host}")))
        }
        Err(err) => Err(ProxyError::Engine(format!("cannot resolve {host}: {err}"))),
    }
}

/// How a slot engine ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Exit {
    pub code: Option<i32>,
    /// Last engine lines, redacted (for the log).
    pub tail: String,
}

impl From<ExitInfo> for Exit {
    fn from(info: ExitInfo) -> Self {
        Exit {
            code: info.code,
            tail: info.stderr_tail,
        }
    }
}

/// A running slot engine: sing-box, plus the Xray child of an Xray profile. Dropping it kills
/// every child (each runs in its own kill-on-close Job).
#[async_trait::async_trait]
pub(crate) trait Engine: Send + Sync {
    /// Process id of the sing-box child.
    fn pid(&self) -> u32;
    /// Resolves once any child of the slot has exited.
    async fn exited(&self) -> Exit;
    /// Raw sing-box output lines. They may hold secrets: never log one unredacted.
    fn lines(&self) -> broadcast::Receiver<Arc<str>>;
    /// Terminates every child; `false` when an exit was not confirmed within `within`.
    async fn terminate(&self, within: Duration) -> bool;
}

/// What touches the machine when a slot starts; tests replace it with a scripted one.
#[async_trait::async_trait]
pub(crate) trait Launch: Send + Sync {
    /// `Ok` when 127.0.0.1:`port` can be bound now, else the OS reason.
    fn check_port(&self, port: u16) -> Result<(), String>;
    /// Starts the plan's children and waits until the slot listener accepts.
    async fn start(
        &self,
        plan: Plan,
        cancel: &CancellationToken,
    ) -> Result<Arc<dyn Engine>, ProxyError>;
}

/// The bundled engines in the resources directory.
pub(super) struct Engines {
    singbox: PathBuf,
    xray: PathBuf,
}

impl Engines {
    pub(super) fn new(resources: &Path) -> Self {
        Self {
            singbox: resources.join("sing-box.exe"),
            xray: resources.join("xray.exe"),
        }
    }

    async fn start_xray(
        &self,
        plan: XrayPlan,
        cancel: &CancellationToken,
    ) -> Result<XrayChild, ProxyError> {
        let (events_tx, events) = mpsc::channel(4);
        // No log file: the per-slot child must not rotate the main tunnel's `xray-a.log`.
        let mut sup = XraySupervisor::new(self.xray.clone(), None, events_tx);
        sup.start(XraySlot::A, plan.endpoint, plan.launch, cancel)
            .await
            .map_err(|e| ProxyError::Engine(format!("xray did not start: {e}")))?;
        Ok(XrayChild {
            sup: tokio::sync::Mutex::new(sup),
            events: tokio::sync::Mutex::new(events),
        })
    }
}

#[async_trait::async_trait]
impl Launch for Engines {
    fn check_port(&self, port: u16) -> Result<(), String> {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .map(drop)
            .map_err(|e| e.to_string())
    }

    async fn start(
        &self,
        plan: Plan,
        cancel: &CancellationToken,
    ) -> Result<Arc<dyn Engine>, ProxyError> {
        let xray = match plan.xray {
            Some(xray) => Some(self.start_xray(xray, cancel).await?),
            None => None,
        };
        // No log file either (it would rotate the main tunnel's `sing-box.log`); the manager
        // logs the slot's lines itself, rate-limited and redacted.
        let singbox = SingBoxProcess::spawn(&self.singbox, &plan.singbox, None)
            .map_err(|e| ProxyError::Engine(format!("sing-box could not be started: {e}")))?;
        let running = Running { singbox, xray };
        match running.ready(plan.port, cancel).await {
            Ok(()) => Ok(Arc::new(running)),
            Err(err) => {
                running.terminate(STOP_TIMEOUT).await;
                Err(err)
            }
        }
    }
}

/// The per-slot Xray child and its exit events.
struct XrayChild {
    sup: tokio::sync::Mutex<XraySupervisor>,
    events: tokio::sync::Mutex<mpsc::Receiver<XrayEvent>>,
}

/// The children of one running slot.
struct Running {
    singbox: SingBoxProcess,
    xray: Option<XrayChild>,
}

impl Running {
    /// Ready = the listener accepts a TCP connection while sing-box runs. sing-box logs its own
    /// "started" line at INFO, and the slot config logs at WARN, so the port is the signal.
    async fn ready(&self, port: u16, cancel: &CancellationToken) -> Result<(), ProxyError> {
        let mut exit = self.singbox.exit_watch();
        tokio::select! {
            biased;
            info = exit_of(&mut exit) => Err(start_failure(port, info)),
            ready = socks5::wait_ready(port, None, READY_TIMEOUT, cancel) => match ready {
                // The port may have been answered by someone else while sing-box died on it.
                Ok(()) => match self.singbox.exit_info() {
                    Some(info) => Err(start_failure(port, Some(info))),
                    None => Ok(()),
                },
                Err(SocksError::Cancelled) => Err(ProxyError::Engine("start cancelled".into())),
                Err(_) => Err(ProxyError::Engine(format!(
                    "sing-box did not open port {port} in time"
                ))),
            },
        }
    }
}

async fn exit_of(rx: &mut watch::Receiver<Option<ExitInfo>>) -> Option<ExitInfo> {
    rx.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|info| info.clone())
}

/// The error of a sing-box that exited during its start: a lost port race (B-23) is reported
/// like the pre-check would have, anything else with the engine's last line.
fn start_failure(port: u16, info: Option<ExitInfo>) -> ProxyError {
    let Some(info) = info else {
        return ProxyError::Engine("sing-box exited during start".into());
    };
    let last = info
        .stderr_tail
        .lines()
        .last()
        .unwrap_or_default()
        .trim()
        .to_owned();
    if info.binds_any(&[port]) {
        return ProxyError::Conflict(format!("Port {port} is unavailable: {last}"));
    }
    let code = code_text(info.code);
    ProxyError::Engine(format!("sing-box exited during start ({code}): {last}"))
}

/// An engine exit code for texts and logs (`unknown` when none was reported).
pub(super) fn code_text(code: Option<i32>) -> String {
    code.map_or_else(|| "unknown".into(), |c| c.to_string())
}

#[async_trait::async_trait]
impl Engine for Running {
    fn pid(&self) -> u32 {
        self.singbox.pid()
    }

    async fn exited(&self) -> Exit {
        let mut singbox = self.singbox.exit_watch();
        let Some(xray) = &self.xray else {
            return exit_of(&mut singbox).await.map_or(UNKNOWN_EXIT, Exit::from);
        };
        let mut events = xray.events.lock().await;
        tokio::select! {
            info = exit_of(&mut singbox) => info.map_or(UNKNOWN_EXIT, Exit::from),
            event = events.recv() => match event {
                Some(XrayEvent::Exited { code, tail, .. }) => Exit { code, tail },
                None => UNKNOWN_EXIT,
            },
        }
    }

    fn lines(&self) -> broadcast::Receiver<Arc<str>> {
        self.singbox.subscribe_lines()
    }

    async fn terminate(&self, within: Duration) -> bool {
        // Both children at once: each stop may take the engine's graceful wait plus a kill.
        let xray = async {
            match &self.xray {
                Some(xray) => xray.sup.lock().await.stop(XraySlot::A).await.is_ok(),
                None => true,
            }
        };
        let (singbox, xray) = tokio::join!(self.singbox.terminate(within), xray);
        singbox.is_ok() && xray
    }
}

const UNKNOWN_EXIT: Exit = Exit {
    code: None,
    tail: String::new(),
};

#[cfg(test)]
mod tests;
