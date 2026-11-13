//! Actor tests: fake engines, slots, capture and inputs over one shared [`World`] that records
//! every effect in order. Nothing here touches the machine.
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, KillSwitchLevel, OutboundFault};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::{ConfigError, TunStack};
use vpnte_engine::singbox_process::{ExitInfo, StartError, StopError};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_config::{ResolveFault, ResolvePath, Resolved};
use vpnte_engine::xray_process::{SlotLaunch, XrayError, XrayEvent};
use vpnte_profiles::model::Profile;

use super::capture::{
    Capture, CaptureCheck, CapturePlan, CaptureProof, EngineParts, ProxyCapture, tun_config,
    tun_form,
};
use super::engines::{CoreProc, Engines, Slots};
use super::{InputsSource, RuntimeDeps, Timings, UserInputs};
use crate::api::{CaptureKind, StartRequest, TunnelEvent};

mod gate;
mod kill_switch;
mod lane;
mod live;
#[cfg(feature = "lab")]
mod mihomo;
mod proxy;
mod recovery;
mod spoof;
mod supervision;

/// What a spawned core does when asked for readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ready {
    Ok,
    /// Exits before readiness; the ports are reported as bind failures.
    Exit(Vec<u16>),
    /// Exits on its own Clash API port (WSAEACCES on an excluded port range).
    BindFail,
    /// Never ready until cancelled.
    Hold,
}

/// What the fake egress probe through a loopback listener gets (the real echo's outcomes).
#[cfg(feature = "lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressVia {
    /// The slot's address came back.
    Ip,
    /// Nothing came back (a silent server).
    NoReply,
    /// Answers came back, none an address (an echo service's 429 page).
    NoAddress,
    /// The handshake budget deferred the probe: nothing was dialled.
    Deferred,
}

/// Knobs and the effect log shared by all fakes.
pub struct World {
    pub log: Mutex<Vec<String>>,
    pub ready: Mutex<VecDeque<Ready>>,
    pub cores: Mutex<Vec<Arc<FakeCore>>>,
    pub configs: Mutex<Vec<Value>>,
    pub kill_ok: AtomicBool,
    pub ready_fail: AtomicBool,
    pub release_fail: AtomicBool,
    pub gone: AtomicBool,
    /// `wait_gone` takes 200 ms (to overlap a second command with a running stop).
    pub slow_gone: AtomicBool,
    pub auto_restart: AtomicBool,
    /// The core records no outbound fault: its crashes say nothing about the server.
    pub no_fault: AtomicBool,
    pub xray_stop_fail: AtomicBool,
    /// The level the TUN protection enforces (the app's guard keeps it equal to the stored one).
    pub guard: Mutex<KillSwitchLevel>,
    pub avoid: Mutex<Vec<Vec<String>>>,
    pub aliases: AtomicU32,
    pub slot_ip: [IpAddr; 2],
    /// What the tunnel egresses as (the selected slot's IP).
    pub tunnel_ip: Mutex<IpAddr>,
    pub running: Mutex<[bool; 2]>,
    pub stage_fail: AtomicBool,
    /// Staging waits until cancelled.
    pub stage_hold: AtomicBool,
    /// The selector write "succeeds" but the tunnel keeps egressing through the old slot.
    pub select_ignored: AtomicBool,
    pub xray_events: Mutex<Option<mpsc::Sender<XrayEvent>>>,
    /// What every server-name lookup answers: the warning of a success, or the fault.
    pub resolve_answer: Mutex<Result<Option<Msg>, ResolveFault>>,
    /// The paths server names were resolved on, in order.
    pub resolve_paths: Mutex<Vec<ResolvePath>>,
    /// The egress probe through a staged upstream gets no answer (a silent server).
    #[cfg(feature = "lab")]
    pub egress_via: Mutex<EgressVia>,
    /// The mihomo run dies while its egress is probed (lab).
    #[cfg(feature = "lab")]
    pub crash_mihomo_on_probe: AtomicBool,
    /// The SOCKS port of the last mihomo run started (lab).
    #[cfg(feature = "lab")]
    pub mihomo_port: Mutex<Option<u16>>,
    /// The hop port of the last mihomo run (what sing-box must dial).
    #[cfg(feature = "lab")]
    pub mihomo_hop: Mutex<Option<u16>>,
}

impl World {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::new(Vec::new()),
            ready: Mutex::new(VecDeque::new()),
            cores: Mutex::new(Vec::new()),
            configs: Mutex::new(Vec::new()),
            kill_ok: AtomicBool::new(true),
            ready_fail: AtomicBool::new(false),
            release_fail: AtomicBool::new(false),
            gone: AtomicBool::new(true),
            slow_gone: AtomicBool::new(false),
            auto_restart: AtomicBool::new(true),
            no_fault: AtomicBool::new(false),
            xray_stop_fail: AtomicBool::new(false),
            guard: Mutex::new(KillSwitchLevel::Standard),
            avoid: Mutex::new(Vec::new()),
            aliases: AtomicU32::new(0),
            slot_ip: [
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43)),
            ],
            tunnel_ip: Mutex::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
            running: Mutex::new([false; 2]),
            stage_fail: AtomicBool::new(false),
            stage_hold: AtomicBool::new(false),
            select_ignored: AtomicBool::new(false),
            xray_events: Mutex::new(None),
            resolve_answer: Mutex::new(Ok(None)),
            resolve_paths: Mutex::new(Vec::new()),
            #[cfg(feature = "lab")]
            egress_via: Mutex::new(EgressVia::Ip),
            #[cfg(feature = "lab")]
            crash_mihomo_on_probe: AtomicBool::new(false),
            #[cfg(feature = "lab")]
            mihomo_port: Mutex::new(None),
            #[cfg(feature = "lab")]
            mihomo_hop: Mutex::new(None),
        })
    }

    pub fn note(&self, what: impl Into<String>) {
        self.log.lock().push(what.into());
    }

    pub fn log(&self) -> Vec<String> {
        self.log.lock().clone()
    }

    pub fn count(&self, what: &str) -> usize {
        self.log().iter().filter(|l| *l == what).count()
    }

    /// Position of the first `what` in the log.
    pub fn at(&self, what: &str) -> usize {
        self.log()
            .iter()
            .position(|l| l == what)
            .unwrap_or_else(|| panic!("{what} not in {:?}", self.log()))
    }

    pub fn core(&self, n: usize) -> Arc<FakeCore> {
        self.cores.lock()[n].clone()
    }
}

pub struct FakeCore {
    pub pid: u32,
    ready: Ready,
    world: Arc<World>,
    exit: watch::Sender<Option<ExitInfo>>,
    /// The `proxy-in` listener of a proxy-capture config (connects succeed into its backlog).
    listener: Mutex<Option<std::net::TcpListener>>,
}

fn exit_info(code: i32, user_initiated: bool, bind: Vec<u16>) -> ExitInfo {
    ExitInfo {
        at: SystemTime::now(),
        code: Some(code),
        stderr_tail: "FATAL fake".into(),
        user_initiated,
        graceful: false,
        bind_failures: bind,
        access_denied: false,
    }
}

impl FakeCore {
    /// The engine dies on its own.
    pub fn crash(&self) {
        self.listener.lock().take();
        self.exit
            .send_replace(Some(exit_info(2, false, Vec::new())));
    }

    /// The engine stays alive but its mixed inbound stops accepting.
    pub fn deafen(&self) {
        self.listener.lock().take();
    }

    /// Port of the `proxy-in` listener, while it listens.
    pub fn proxy_port(&self) -> Option<u16> {
        let listener = self.listener.lock();
        listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
    }
}

#[async_trait]
impl CoreProc for FakeCore {
    fn pid(&self) -> u32 {
        self.pid
    }
    async fn wait_ready(
        &self,
        _timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError> {
        match &self.ready {
            Ready::Ok => Ok(()),
            Ready::Exit(ports) => {
                self.listener.lock().take();
                let info = exit_info(1, false, ports.clone());
                self.exit.send_replace(Some(info.clone()));
                Err(StartError::Exited(info))
            }
            Ready::BindFail | Ready::Hold => {
                cancel.cancelled().await;
                Err(StartError::Cancelled)
            }
        }
    }
    async fn terminate(&self, _within: Duration) -> Result<ExitInfo, StopError> {
        self.world.note(format!("terminate:{}", self.pid));
        if let Some(info) = self.exit.borrow().clone() {
            return Ok(info);
        }
        if !self.world.kill_ok.load(Ordering::SeqCst) {
            return Err(StopError::ExitNotConfirmed);
        }
        self.listener.lock().take();
        let info = exit_info(1, true, Vec::new());
        self.exit.send_replace(Some(info.clone()));
        Ok(info)
    }
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.exit.subscribe()
    }
    fn recent_fault(&self) -> Option<OutboundFault> {
        let none = self.world.no_fault.load(Ordering::SeqCst);
        (!none).then_some(OutboundFault::UpstreamUnreachable)
    }
}

pub struct FakeSlots(Arc<World>);

fn slot_name(slot: Slot) -> &'static str {
    match slot {
        Slot::A => "a",
        Slot::B => "b",
    }
}

#[async_trait]
impl Slots for FakeSlots {
    async fn start(
        &mut self,
        slot: Slot,
        _ep: SlotEndpoint,
        _launch: SlotLaunch,
        cancel: &CancellationToken,
    ) -> Result<(), XrayError> {
        self.0.note(format!("xray-start:{}", slot_name(slot)));
        if self.0.stage_hold.load(Ordering::SeqCst) {
            cancel.cancelled().await;
            return Err(XrayError::Cancelled);
        }
        if self.0.stage_fail.load(Ordering::SeqCst) {
            return Err(XrayError::NotStarted);
        }
        self.0.running.lock()[slot.index()] = true;
        Ok(())
    }
    async fn restart(&mut self, slot: Slot, _cancel: &CancellationToken) -> Result<(), XrayError> {
        self.0.note(format!("xray-restart:{}", slot_name(slot)));
        self.0.running.lock()[slot.index()] = true;
        Ok(())
    }
    async fn stop(&mut self, slot: Slot) -> Result<(), XrayError> {
        self.0.note(format!("xray-stop:{}", slot_name(slot)));
        self.0.running.lock()[slot.index()] = false;
        Ok(())
    }
    async fn stop_all(&mut self) -> Result<(), XrayError> {
        self.0.note("xray-stop-all");
        if self.0.xray_stop_fail.load(Ordering::SeqCst) {
            return Err(XrayError::ExitNotConfirmed);
        }
        *self.0.running.lock() = [false; 2];
        Ok(())
    }
    fn activate(&mut self, slot: Slot) -> Result<(), XrayError> {
        self.0.note(format!("activate:{}", slot_name(slot)));
        Ok(())
    }
    fn running(&self, slot: Slot) -> bool {
        self.0.running.lock()[slot.index()]
    }
    /// Clean, unlike `FakeCore`: a slot session's crash is judged by Xray's log, not the core's.
    fn recent_fault(&self, _slot: Slot) -> Option<OutboundFault> {
        None
    }
}

pub struct FakeEngines(pub Arc<World>);

#[async_trait]
impl Engines for FakeEngines {
    fn spawn_core(&self, config: &[u8]) -> std::io::Result<Arc<dyn CoreProc>> {
        let w = &self.0;
        let json: Value = serde_json::from_slice(config).map_err(std::io::Error::other)?;
        let port = clash_port(&json);
        w.configs.lock().push(json.clone());
        let pid = 4100 + u32::try_from(w.cores.lock().len()).unwrap_or(0);
        w.note(format!("spawn:{pid}"));
        let ready = match w.ready.lock().pop_front().unwrap_or(Ready::Ok) {
            Ready::BindFail => Ready::Exit(vec![port]),
            other => other,
        };
        let core = Arc::new(FakeCore {
            pid,
            ready,
            world: w.clone(),
            exit: watch::channel(None).0,
            listener: Mutex::new(proxy_listener(&json)),
        });
        w.cores.lock().push(core.clone());
        Ok(core)
    }
    fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots> {
        *self.0.xray_events.lock() = Some(events);
        Box::new(FakeSlots(self.0.clone()))
    }
    fn singbox_exe(&self) -> PathBuf {
        PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer\resources\sing-box.exe")
    }
    fn xray_exe(&self) -> PathBuf {
        PathBuf::from(r"C:\Program Files\VPN Tunnel Enforcer\resources\xray.exe")
    }
    fn log_files(&self, slots: bool) -> Vec<PathBuf> {
        let mut v = vec![PathBuf::from("sing-box.log")];
        if slots {
            v.extend(["xray-a.log", "xray-b.log"].map(PathBuf::from));
        }
        v
    }
    async fn select(&self, _clash: &ClashEndpoint, slot: Slot) -> AppResult<()> {
        self.0.note(format!("select:{}", slot_name(slot)));
        if !self.0.select_ignored.load(Ordering::SeqCst) {
            *self.0.tunnel_ip.lock() = self.0.slot_ip[slot.index()];
        }
        Ok(())
    }
    async fn upstream_downloads(&self, _c: &ClashEndpoint) -> AppResult<Vec<(String, u64)>> {
        Ok(Vec::new())
    }
    async fn resolve(
        &self,
        hosts: &[String],
        path: ResolvePath,
        _cancel: &CancellationToken,
    ) -> Result<Resolved, ResolveFault> {
        self.0.resolve_paths.lock().push(path);
        let warning = self.0.resolve_answer.lock().clone()?;
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let addrs = hosts.iter().map(|h| (h.clone(), ip)).collect();
        Ok(Resolved { addrs, warning })
    }
    async fn egress_via(
        &self,
        server: &Profile,
        port: u16,
        _c: &Creds,
        _x: &CancellationToken,
    ) -> AppResult<IpAddr> {
        let _ = port;
        self.0.note(format!("egress-via:{}", server.server));
        #[cfg(feature = "lab")]
        if self.0.crash_mihomo_on_probe.load(Ordering::SeqCst) {
            let cores = self.0.cores.lock().clone();
            cores
                .iter()
                .filter(|c| c.pid >= 5100)
                .for_each(|c| c.crash());
        }
        #[cfg(feature = "lab")]
        {
            use super::engines::{EchoFailure, echo_failed};
            match *self.0.egress_via.lock() {
                EgressVia::Ip => {}
                EgressVia::NoReply => return Err(echo_failed(EchoFailure::NoReply)),
                EgressVia::NoAddress => return Err(echo_failed(EchoFailure::NoAddress)),
                EgressVia::Deferred => {
                    let msg = Msg::new("probes.discipline.deferred");
                    return Err(AppError::conflict(msg));
                }
            }
        }
        let staged = usize::from(self.0.running.lock()[1]);
        Ok(self.0.slot_ip[staged])
    }
    async fn egress(
        &self,
        via: Option<u16>,
        _t: Duration,
        _c: &CancellationToken,
    ) -> AppResult<IpAddr> {
        self.0.note(match via {
            Some(port) => format!("egress:{port}"),
            None => "egress".to_owned(),
        });
        Ok(*self.0.tunnel_ip.lock())
    }
    async fn local_proxy(&self, addr: &HostPort, _limit: Duration) -> AppResult<Option<PathBuf>> {
        self.0.note(format!("probe:{addr}"));
        Ok(Some(PathBuf::from(r"C:\Program Files\Happ\core\xray.exe")))
    }
    async fn physical_dns(&self) -> Vec<Ipv4Addr> {
        vec![Ipv4Addr::new(192, 168, 1, 1)]
    }
    /// A mihomo run that is ready at once (the AmneziaWG hop's answer is `egress_via`).
    #[cfg(feature = "lab")]
    async fn start_mihomo(
        &self,
        config: &vpnte_engine::mihomo_config::Compiled,
        socks: SlotEndpoint,
        _controller: ClashEndpoint,
        _cancel: &CancellationToken,
    ) -> AppResult<Arc<dyn CoreProc>> {
        let w = &self.0;
        let pid = 5100 + u32::try_from(w.cores.lock().len()).unwrap_or(0);
        w.note(format!("mihomo-start:{pid}"));
        *w.mihomo_port.lock() = Some(socks.port());
        *w.mihomo_hop.lock() = Some(config.hop_port());
        let core = Arc::new(FakeCore {
            pid,
            ready: Ready::Ok,
            world: w.clone(),
            exit: watch::channel(None).0,
            listener: Mutex::new(None),
        });
        w.cores.lock().push(core.clone());
        Ok(core)
    }
}

pub struct FakeCapture(pub Arc<World>);

#[async_trait]
impl Capture for FakeCapture {
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan> {
        let w = &self.0;
        w.avoid.lock().push(avoid.to_vec());
        let n = w.aliases.fetch_add(1, Ordering::SeqCst);
        let alias = if avoid.is_empty() {
            "Ethernet 5".to_owned()
        } else {
            format!("Ethernet {}", 6 + n)
        };
        w.note(format!("prepare:{alias}"));
        let guard = *w.guard.lock();
        Ok(CapturePlan {
            alias: Some(alias),
            form: tun_form(guard, false),
            stack: TunStack::Mixed,
            mtu: vpnte_engine::singbox_config::select_mtu(
                req.stealth,
                req.adaptive,
                req.public_wifi,
            ),
            guard,
            warnings: Vec::new(),
        })
    }
    fn config(
        &self,
        plan: &CapturePlan,
        parts: &EngineParts,
    ) -> Result<(Value, [u8; 32]), ConfigError> {
        tun_config(plan, parts)
    }
    async fn begin(&self, _plan: &CapturePlan, programs: &[PathBuf]) -> AppResult<()> {
        self.0.note(format!("begin:{}", programs.len()));
        Ok(())
    }
    async fn ready(
        &self,
        plan: &CapturePlan,
        _timeout: Duration,
        _cancel: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        self.0.note("ready");
        if self.0.ready_fail.load(Ordering::SeqCst) {
            let msg = Msg::new("tunnel.runtime.tunSetup.adapter");
            return Err(AppError::msg(ErrorKind::Timeout, msg));
        }
        Ok(CaptureProof {
            luid: Some(42),
            alias: plan.alias.clone(),
            port: None,
        })
    }
    async fn routes_ok(&self, _proof: &CaptureProof) -> bool {
        true
    }
    async fn lost(&self) -> AppResult<()> {
        self.0.note("lost");
        Ok(())
    }
    async fn release(&self) -> AppResult<()> {
        self.0.note("release");
        if self.0.release_fail.load(Ordering::SeqCst) {
            return Err(AppError::new(ErrorKind::Internal));
        }
        Ok(())
    }
    async fn wait_gone(&self, _plan: &CapturePlan, _t: Duration, _c: &CancellationToken) -> bool {
        self.0.note("wait-gone");
        if self.0.slow_gone.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        self.0.gone.load(Ordering::SeqCst)
    }
    async fn check(&self, _proof: &CaptureProof) -> CaptureCheck {
        CaptureCheck::Clear
    }
    /// As the real TUN capture: the protection's level in force now (`World::guard`).
    fn guard(&self, _plan: &CapturePlan) -> KillSwitchLevel {
        *self.0.guard.lock()
    }
}

pub struct FakeInputs(pub Arc<World>);

#[async_trait]
impl InputsSource for FakeInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Ok(UserInputs {
            auto_restart_on_crash: self.0.auto_restart.load(Ordering::SeqCst),
            kill_switch: KillSwitchLevel::Standard,
            ..UserInputs::default()
        })
    }
}

/// Short timings: backoff in milliseconds, watchdogs effectively off.
pub fn timings() -> Timings {
    Timings {
        backoff: [20, 40, 60].map(Duration::from_millis),
        stable: Duration::from_secs(60),
        proxy_watch: Duration::from_secs(600),
        egress_watch: Duration::from_secs(600),
        capture_watch: Duration::from_secs(600),
        ..Timings::default()
    }
}

pub fn deps(world: &Arc<World>) -> RuntimeDeps {
    RuntimeDeps {
        engines: Arc::new(FakeEngines(world.clone())),
        tun: Some(Arc::new(FakeCapture(world.clone()))),
        proxy: Arc::new(ProxyCapture::new()),
        inputs: Arc::new(FakeInputs(world.clone())),
        failover: None,
        confirmations: None,
        timings: timings(),
    }
}

/// Every event received so far, without waiting.
pub fn drain(rx: &mut broadcast::Receiver<TunnelEvent>) -> Vec<TunnelEvent> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        out.push(e);
    }
    out
}

/// Waits (bounded) until `pred` holds for a received event; returns all events seen.
pub async fn until(
    rx: &mut broadcast::Receiver<TunnelEvent>,
    pred: impl Fn(&TunnelEvent) -> bool,
) -> Vec<TunnelEvent> {
    let mut seen = Vec::new();
    let wait = async {
        loop {
            match rx.recv().await {
                Ok(e) => {
                    let hit = pred(&e);
                    seen.push(e);
                    if hit {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .is_err()
    {
        panic!("event not seen; got {seen:?}");
    }
    seen
}

/// Binds the `proxy-in` port of a proxy-capture config, as sing-box would.
fn proxy_listener(config: &Value) -> Option<std::net::TcpListener> {
    let inbounds = config["inbounds"].as_array()?;
    let inbound = inbounds.iter().find(|i| i["tag"] == "proxy-in")?;
    let port = u16::try_from(inbound["listen_port"].as_u64()?).ok()?;
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()
}

/// The Clash API port a generated config listens on.
pub fn clash_port(config: &Value) -> u16 {
    config["experimental"]["clash_api"]["external_controller"]
        .as_str()
        .and_then(|s| s.rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

pub fn local_req() -> StartRequest {
    StartRequest {
        mode: crate::api::Mode::LocalProxy {
            addr: "127.0.0.1:10808".into(),
            kind: vpnte_base::types::ProxyKind::Socks5,
        },
        capture: CaptureKind::Tun,
        kill_switch: KillSwitchLevel::Standard,
        public_wifi: false,
        stealth: false,
        adaptive: vpnte_base::types::AdaptiveMode::Baseline,
        engine: vpnte_base::types::EnginePref::Auto,
        origin: crate::api::Origin::User,
    }
}

/// Obvious fakes: documentation addresses and a zero UUID.
pub const XRAY_KEY: &str = "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls&sni=example.com&type=tcp#Fake%20A";
pub const XRAY_KEY_2: &str = "vless://00000000-0000-4000-8000-000000000002@203.0.113.11:443?security=tls&sni=example.com&type=tcp#Fake%20B";
pub const NATIVE_KEY: &str =
    "trojan://fake-password@203.0.113.12:443?security=tls&sni=example.com#Fake%20C";
/// A native key that dials a name (WebSocket over TLS): its address is pinned at the start.
pub const NATIVE_BY_NAME_KEY: &str = "vless://00000000-0000-4000-8000-000000000004@cdn.example:443?type=ws&path=%2Fws&security=tls#Fake%20D";

pub fn vpn_req(uri: &str, engine: vpnte_base::types::EnginePref) -> StartRequest {
    let profile = vpnte_profiles::uri::parse_uri(uri).expect("fake key parses");
    StartRequest {
        mode: crate::api::Mode::DirectVpn {
            profile: crate::api::VpnProfile {
                id: profile.name.clone(),
                profile: Arc::new(profile),
                device: None,
                engine: vpnte_base::types::EnginePref::Auto,
            },
        },
        engine,
        ..local_req()
    }
}
