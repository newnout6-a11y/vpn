//! Starting a slot's engine (spec 6.4, 6.6, 6.7; B-11, B-21, B-27, B-28, B-29): the engine the
//! main tunnel would pick for the profile, endpoint names resolved by the app and pinned into
//! the config (the slot config has no DNS of its own, so no plaintext bootstrap query leaves
//! outside the tunnel), then `sing-box run -c stdin`, ready once the slot listener accepts.
//! Xray profiles run as a chain: the slot's sing-box forwards over SOCKS5 to a per-slot Xray
//! child on an ephemeral loopback port; either child exiting fails the slot.
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine as EngineKind;
use vpnte_core::net;
use vpnte_core::resolve::{How, resolve_host};
use vpnte_core::socks5::{self, SocksError};
use vpnte_engine::singbox_process::{ExitInfo, SingBoxProcess};
use vpnte_engine::slot::{Slot as XraySlot, SlotEndpoint};
use vpnte_engine::xray_config::{build_config, proxy_graph, select_engine};
use vpnte_engine::xray_process::{SlotLaunch, XrayEvent, XraySupervisor};
use vpnte_profiles::emit_singbox::{EmitPolicy, emit_singbox};
use vpnte_profiles::model::{Host, Profile};

use super::EngineChoice;
use crate::config::{self, PROXY_OUT_TAG};
use crate::model::ProxyError;

/// The slot listener must accept this soon after the spawn (B-11: replaces `sing-box check`).
pub(super) const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// Exit wait after a terminate (B-18).
pub(super) const STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a resolved endpoint stays pinned (old `ENDPOINT_RESOLUTION_TTL_MS`).
const RESOLVE_TTL: Duration = Duration::from_secs(300);
/// OS resolver deadline (old `ENDPOINT_RESOLUTION_TIMEOUT_MS`).
const OS_TIMEOUT: Duration = Duration::from_millis(2_500);
/// DNS-over-HTTPS deadline, both servers together.
const DOH_TIMEOUT: Duration = Duration::from_secs(6);

/// Everything a start needs, prepared before the slot's old engine is stopped. No `Debug`: the
/// configs carry server credentials.
pub(crate) struct Plan {
    pub port: u16,
    /// sing-box config (JSON) for stdin.
    pub singbox: Vec<u8>,
    pub xray: Option<XrayPlan>,
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
        .map_err(|reject| {
            ProxyError::Engine(format!(
                "the profile cannot run with the current engine setting ({})",
                reject.msg().key
            ))
        })?;
    if engine == EngineKind::SingBox {
        let policy = EmitPolicy {
            device: Some(choice.device),
            ..EmitPolicy::default()
        };
        let mut upstream = emit_singbox(profile, PROXY_OUT_TAG, &policy)
            .map_err(|e| ProxyError::Engine(format!("cannot build the proxy outbound: {e}")))?;
        for host in config::hostnames(&upstream) {
            let ip = names.resolve(&host).await?;
            config::pin(&mut upstream, &host, ip);
        }
        let singbox = config::build(&upstream, port)?.to_string().into_bytes();
        return Ok(Plan {
            port,
            singbox,
            xray: None,
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
    let dial_target = match &profile.server {
        Host::Ip(ip) => Some(*ip),
        Host::Domain(_) => resolved.values().next().copied(),
    }
    .map(|ip| SocketAddr::new(ip, profile.port));
    let launch = SlotLaunch {
        config: build_config(&graph, &endpoint).to_string().into_bytes(),
        dial_target,
    };
    Ok(Plan {
        port,
        singbox,
        xray: Some(XrayPlan { endpoint, launch }),
    })
}

/// Endpoint names resolved by the app, cached for five minutes. The OS resolver goes first (it
/// follows the system DNS, through the main tunnel when that is up), then DNS-over-HTTPS; a
/// censored network's poisoned plaintext answer is never asked from the engine.
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
        let ip = resolve_with(&key, |how| lookup(&key, how)).await?;
        self.cache.lock().insert(key, (ip, Instant::now()));
        Ok(ip)
    }
}

async fn lookup(host: &str, how: How) -> Option<Vec<IpAddr>> {
    let limit = match how {
        How::System => OS_TIMEOUT,
        How::Doh => DOH_TIMEOUT,
    };
    let answer = tokio::time::timeout(limit, resolve_host(host, how, dialable)).await;
    answer.ok()?.ok()
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

/// Tries the OS resolver, then DoH; the preferred address (IPv4 first) of the first answer.
pub(super) async fn resolve_with<F, Fut>(host: &str, lookup: F) -> Result<IpAddr, ProxyError>
where
    F: Fn(How) -> Fut,
    Fut: Future<Output = Option<Vec<IpAddr>>>,
{
    if let Some(ip) = lookup(How::System)
        .await
        .and_then(|a| config::preferred_address(&a))
    {
        tracing::debug!(via = "os", "resolved proxy endpoint");
        return Ok(ip);
    }
    tracing::warn!("system DNS could not resolve a proxy endpoint; trying DNS-over-HTTPS");
    if let Some(ip) = lookup(How::Doh)
        .await
        .and_then(|a| config::preferred_address(&a))
    {
        tracing::debug!(via = "doh", "resolved proxy endpoint");
        return Ok(ip);
    }
    Err(ProxyError::Engine(format!("cannot resolve {host}")))
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
    let code = info
        .code
        .map_or_else(|| "unknown".into(), |c| c.to_string());
    ProxyError::Engine(format!("sing-box exited during start ({code}): {last}"))
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
        let singbox = self.singbox.terminate(within).await.is_ok();
        let xray = match &self.xray {
            Some(xray) => xray.sup.lock().await.stop(XraySlot::A).await.is_ok(),
            None => true,
        };
        singbox && xray
    }
}

const UNKNOWN_EXIT: Exit = Exit {
    code: None,
    tail: String::new(),
};

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use vpnte_base::types::{ClientDevice, EnginePref};
    use vpnte_profiles::model::{Kind, Reality, Tls, Transport, WgPeer, WireGuard};

    use super::*;
    use crate::manager::tests::vless;

    const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

    /// Names with `host` already resolved (no lookup happens).
    fn names(entries: &[(&str, &str)]) -> Names {
        let names = Names::default();
        for (host, ip) in entries {
            let ip = ip.parse().unwrap();
            names
                .cache
                .lock()
                .insert((*host).into(), (ip, Instant::now()));
        }
        names
    }

    async fn singbox_config(profile: &Profile, names: &Names) -> Value {
        let plan = prepare(profile, 17990, EngineChoice::default(), names)
            .await
            .unwrap();
        assert!(plan.xray.is_none());
        serde_json::from_slice(&plan.singbox).unwrap()
    }

    /// Spec external-proxy §7.3 (Rust vectors): a host name endpoint is pinned to the resolved
    /// IP with no DNS machinery in the config; the provider SNI stays; an IP endpoint needs no
    /// resolution at all.
    #[tokio::test]
    async fn hostname_endpoints_are_pinned() {
        let mut p = vless("vpn.example.test");
        p.tls = Some(Tls {
            server_name: Some("cdn.example.test".into()),
            ..Tls::default()
        });
        p.dial.dns_strategy = Some("prefer_ipv4".into());
        let original = p.clone();
        let names = names(&[("vpn.example.test", "203.0.113.5")]);
        let config = singbox_config(&p, &names).await;
        let out = &config["outbounds"][0];
        assert_eq!(out["server"], "203.0.113.5");
        assert_eq!(out["tag"], "proxy-out");
        assert_eq!(out["tls"]["server_name"], "cdn.example.test");
        for key in ["domain_strategy", "domain_resolver"] {
            assert!(out.get(key).is_none(), "{key}");
        }
        assert!(config.get("dns").is_none());
        assert!(config["route"].get("default_domain_resolver").is_none());
        assert_eq!(p, original);

        // No SNI of its own: the host name keeps the certificate check; ws gets its Host.
        p.tls = Some(Tls::default());
        p.transport = Some(Transport::Ws {
            path: "/x".into(),
            host: None,
            max_early_data: None,
            early_data_header: None,
        });
        let config = singbox_config(&p, &names).await;
        let out = &config["outbounds"][0];
        assert_eq!(out["tls"]["server_name"], "vpn.example.test");
        assert_eq!(out["transport"]["headers"]["Host"], "vpn.example.test");

        let ip = vless("203.0.113.10");
        let config = singbox_config(&ip, &Names::default()).await;
        assert_eq!(config["outbounds"][0]["server"], "203.0.113.10");
        assert!(config.get("dns").is_none());
    }

    /// Spec external-proxy §7.3: OS resolver first, DoH when it fails, IPv4 preferred, and a
    /// clear error when both fail.
    #[tokio::test]
    async fn resolution_falls_back_to_doh() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let doh_only =
            |how| async move { (how == How::Doh).then(|| vec!["203.0.113.6".parse().unwrap()]) };
        assert_eq!(
            resolve_with("vpn.example.test", doh_only).await.unwrap(),
            ip("203.0.113.6")
        );
        let none = |_| async { None };
        let err = resolve_with("vpn.example.test", none).await.unwrap_err();
        assert_eq!(
            err,
            ProxyError::Engine("cannot resolve vpn.example.test".into())
        );
        let mixed = |_| async {
            Some(vec![
                "2001:db8::1".parse().unwrap(),
                "203.0.113.7".parse().unwrap(),
            ])
        };
        assert_eq!(
            resolve_with("vpn.example.test", mixed).await.unwrap(),
            ip("203.0.113.7")
        );
        assert!(dialable(ip("198.51.100.1")) && dialable(ip("10.0.0.1")));
        for blocked in [
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "169.254.1.1",
            "255.255.255.255",
            "::",
        ] {
            assert!(!dialable(ip(blocked)), "{blocked}");
        }
    }

    fn wireguard() -> Profile {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        Profile {
            port: 51820,
            kind: Kind::Wireguard(WireGuard {
                private_key: key.clone(),
                local_address: vec!["10.66.0.2/32".parse().unwrap()],
                mtu: None,
                dns: Vec::new(),
                peers: vec![WgPeer {
                    host: Host::Ip("203.0.113.20".parse().unwrap()),
                    port: 51820,
                    public_key: key,
                    pre_shared_key: None,
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    keepalive_s: None,
                    reserved: None,
                }],
            }),
            tls: None,
            ..vless("203.0.113.20")
        }
    }

    /// REALITY over VLESS: Xray is preferred (engine selection of the main tunnel). Fake keys.
    fn reality() -> Profile {
        Profile {
            tls: Some(Tls {
                server_name: Some("www.example.com".into()),
                fingerprint: Some("chrome".into()),
                reality: Some(Reality {
                    public_key: "fakefakefakefakefakefakefakefakefakefakefak".into(),
                    short_id: "ab".into(),
                    spider_x: None,
                }),
                ..Tls::default()
            }),
            ..vless("203.0.113.30")
        }
    }

    /// B-28 / B-27: WireGuard runs as a sing-box endpoint; an Xray profile runs behind a SOCKS5
    /// bridge to its own Xray child; there is never a `block` outbound and the last rule
    /// rejects (B-2).
    #[tokio::test]
    async fn wireguard_and_xray_shapes() {
        let config = singbox_config(&wireguard(), &Names::default()).await;
        assert_eq!(config["endpoints"][0]["tag"], "proxy-out");
        let outbounds = config["outbounds"].as_array().unwrap();
        assert!(
            outbounds
                .iter()
                .all(|o| o["type"] != "wireguard" && o["type"] != "block")
        );

        let plan = prepare(
            &reality(),
            17991,
            EngineChoice::default(),
            &Names::default(),
        )
        .await
        .unwrap();
        let xray = plan.xray.as_ref().unwrap();
        let config: Value = serde_json::from_slice(&plan.singbox).unwrap();
        let bridge = &config["outbounds"][0];
        let creds = xray.endpoint.creds();
        let expected = json!({
            "type": "socks", "tag": "proxy-out", "version": "5", "server": "127.0.0.1",
            "server_port": xray.endpoint.port(), "username": creds.user, "password": creds.pass,
            "udp_fragment": true,
        });
        assert_eq!(bridge, &expected);
        assert_eq!(
            config["route"]["rules"].as_array().unwrap().last(),
            Some(&json!({ "action": "reject" }))
        );
        assert_eq!(
            xray.launch.dial_target,
            Some("203.0.113.30:443".parse().unwrap())
        );
        let forced = EngineChoice {
            pref: EnginePref::SingBox,
            device: ClientDevice::Android,
        };
        let plan = prepare(&reality(), 17991, forced, &Names::default())
            .await
            .unwrap();
        assert!(plan.xray.is_none());
    }

    /// AT-02-008: the prepared configs pass the bundled engines' own checks (skipped quietly
    /// when the binaries are not present).
    #[tokio::test]
    async fn prepared_configs_pass_the_engine_checks() {
        let resources = Path::new(RESOURCES);
        let (singbox, xray) = (resources.join("sing-box.exe"), resources.join("xray.exe"));
        if !singbox.exists() || !xray.exists() {
            return;
        }
        for profile in [vless("203.0.113.10"), wireguard(), reality()] {
            let plan = prepare(&profile, 17990, EngineChoice::default(), &Names::default())
                .await
                .unwrap();
            let checked =
                vpnte_engine::singbox_process::check_config(&singbox, &plan.singbox).await;
            assert!(checked.is_ok(), "{}: {checked:?}", profile.kind.label());
            if let Some(x) = plan.xray {
                let checked =
                    vpnte_engine::xray_process::check_config(&xray, &x.launch.config).await;
                assert!(checked.is_ok(), "xray: {checked:?}");
            }
        }
    }
}
