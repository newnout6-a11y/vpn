//! The temporary probe engine: sing-box (config on stdin, authenticated mixed inbound) or Xray
//! (the engine crate's slot launcher), readiness of the local SOCKS port raced with the
//! engine's exit, output for the classifier, and a guaranteed stop.
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppError;
use vpnte_base::types::Loopback;
use vpnte_core::socks5::{self, SocksError};
use vpnte_engine::ports;
use vpnte_engine::singbox_process::{ExitInfo, STOP_TIMEOUT, SingBoxProcess, StartError};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_config::{
    ResolveFault, ResolvePath, build_config, proxy_graph, resolve_hosts,
};
use vpnte_engine::xray_process::{SlotLaunch, XrayError, XraySupervisor};
use vpnte_profiles::model::Profile;

use super::ProbeCtx;
use super::config::{Uplink, probe_config};
use crate::ping::is_loopback_host;

/// Budget for the probe's local SOCKS port (keyHealthChecker.ts:595; Xray keeps its launcher's
/// own 3.5 s readiness budget).
pub(crate) const SOCKS_READY: Duration = Duration::from_millis(2500);
/// Output lines handed to the classifier.
const OUTPUT_LINES: usize = 500;

/// A started probe engine. Dropping it kills the process (its own kill-on-close Job).
pub(crate) enum Running {
    SingBox(SingBoxProcess),
    Xray(Box<XraySupervisor>),
}

impl Running {
    /// Recent engine output, redacted (secrets of the config and credentials masked).
    pub(crate) fn output(&self) -> String {
        match self {
            Running::SingBox(sb) => sb.tail(OUTPUT_LINES).join("\n"),
            Running::Xray(sup) => sup.log_tail(Slot::A),
        }
    }

    /// Stops the engine and waits for the exit (best effort; the Job kills it on drop anyway).
    pub(crate) async fn stop(self) {
        match self {
            Running::SingBox(sb) => {
                if sb.terminate(STOP_TIMEOUT).await.is_err() {
                    tracing::warn!(pid = sb.pid(), "probe engine exit not confirmed");
                }
            }
            Running::Xray(mut sup) => {
                if let Err(err) = sup.stop_all().await {
                    tracing::warn!(error = %err, "probe xray exit not confirmed");
                }
            }
        }
    }
}

/// How a start ended.
pub(crate) enum Start {
    /// The engine runs and its SOCKS port accepted our credentials.
    Ready(Box<Running>, Loopback),
    /// The engine exited or never served its port: a key verdict from this text.
    Failed(String),
    /// The profile cannot be configured for the engine: a configuration verdict.
    Invalid,
    /// The engine died on its inbound port, taken by another program meanwhile (setup, not
    /// a verdict: retried once with another port).
    PortLost(u16),
}

/// Starts sing-box with the probe config of `p`. Setup failures (no free port, missing or
/// blocked executable, our port taken twice) and cancellation are errors, never a verdict.
pub(crate) async fn start_singbox(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> Result<Start, AppError> {
    let route = match &ctx.net.tun_direct {
        Some(direct) => Uplink::Detour(direct.clone()),
        // A server on this PC is not reached through a NIC.
        None if is_loopback_host(&p.server.to_string()) => Uplink::Bind(None),
        None => Uplink::Bind(physical_alias().await),
    };
    let mut lost: Vec<u16> = Vec::new();
    loop {
        let listen = Loopback {
            port: ports::alloc_port(false, &lost)?,
            creds: Some(ports::creds()),
        };
        let Ok(config) = probe_config(p, &listen, ctx.device, &route) else {
            return Ok(Start::Invalid);
        };
        let bytes = serde_json::to_vec(&config).map_err(AppError::internal)?;
        let sb = SingBoxProcess::spawn(&ctx.singbox_exe, &bytes, None)
            .map_err(|err| AppError::from(StartError::Spawn(err)))?;
        match ready_singbox(sb, listen, cancel).await? {
            // Ports are bind-tested, then released: another program can take ours in between.
            Start::PortLost(port) if lost.is_empty() => lost.push(port),
            Start::PortLost(_) => return Err(ports::PortsExhausted.into()),
            start => return Ok(start),
        }
    }
}

/// Waits for the authenticated inbound, raced with the engine's exit and `cancel`.
async fn ready_singbox(
    sb: SingBoxProcess,
    listen: Loopback,
    cancel: &CancellationToken,
) -> Result<Start, AppError> {
    let mut exit = sb.exit_watch();
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(SocksError::Cancelled),
        info = exited(&mut exit) => return Ok(exit_start(&sb, info.as_ref(), listen.port)),
        ready = socks5::wait_ready(listen.port, listen.creds.as_ref(), SOCKS_READY, cancel) => ready,
    };
    match outcome {
        Ok(()) => match sb.exit_info() {
            None => Ok(Start::Ready(Box::new(Running::SingBox(sb)), listen)),
            Some(info) => Ok(exit_start(&sb, Some(&info), listen.port)),
        },
        Err(SocksError::Cancelled) => {
            Running::SingBox(sb).stop().await;
            Err(AppError::cancelled())
        }
        Err(err) => {
            // Something else may answer on our port while the engine dies on it: the exit
            // decides, so stop first and read the evidence.
            let info = sb.terminate(STOP_TIMEOUT).await.ok();
            match exit_start(&sb, info.as_ref(), listen.port) {
                Start::Failed(text) => Ok(Start::Failed(format!(
                    "{text}\nlocal socks not ready: {}",
                    readiness_text(err)
                ))),
                lost => Ok(lost),
            }
        }
    }
}

async fn exited(rx: &mut watch::Receiver<Option<ExitInfo>>) -> Option<ExitInfo> {
    rx.wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|info| info.clone())
}

/// After an exit: our port lost to another program, else a failure with everything the engine
/// printed.
fn exit_start(sb: &SingBoxProcess, info: Option<&ExitInfo>, port: u16) -> Start {
    if info.is_some_and(|i| i.binds_any(&[port])) {
        return Start::PortLost(port);
    }
    let tail = sb.tail(OUTPUT_LINES).join("\n");
    match info {
        Some(info) if !tail.contains(info.stderr_tail.as_str()) => {
            Start::Failed(format!("{tail}\n{}", info.stderr_tail))
        }
        _ => Start::Failed(tail),
    }
}

/// Classifier wording of a readiness failure: a timeout must read as one, and nothing about our
/// own listener (its authentication) may read as the key's.
fn readiness_text(err: SocksError) -> &'static str {
    match err {
        SocksError::Timeout => "timeout",
        _ => "no answer",
    }
}

/// Starts Xray (selection already chose it) for `p`: provider graph or translated profile, names
/// resolved by the app (through the running sing-box's bootstrap DNS listener while our TUN
/// runs, else directly: the DoH / TCP chain, the OS resolver, the last known address), then
/// the engine crate's slot launcher with its authenticated readiness. Xray's own dials are
/// routed `direct-out` by the tunnel's process-path rule for the Xray executable.
pub(crate) async fn start_xray(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> Result<Start, AppError> {
    let Ok(mut graph) = proxy_graph(p, ctx.device) else {
        return Ok(Start::Invalid);
    };
    let hosts = graph.hosts();
    if !hosts.is_empty() {
        let path = match ctx.dns_bootstrap_in {
            Some(addr) if ctx.net.tunnel_running() => ResolvePath::ViaSingBox(addr),
            _ => ResolvePath::Direct,
        };
        match resolve_hosts(&hosts, path, cancel).await {
            Ok(resolved) => graph.substitute(&resolved.addrs),
            Err(ResolveFault::Cancelled) => return Err(AppError::cancelled()),
            Err(_) => {
                return Ok(Start::Failed(
                    "host unreachable: server name not resolved".into(),
                ));
            }
        }
    }
    let mut lost: Vec<u16> = Vec::new();
    loop {
        let ep = SlotEndpoint::allocate(&lost)?;
        let launch = SlotLaunch {
            config: build_config(&graph, &ep).to_string().into_bytes(),
            dial_target: None,
        };
        // Exit events matter only to the tunnel's supervisor; this one owns a single probe.
        let (events, _) = mpsc::channel(1);
        let mut sup = XraySupervisor::new(ctx.xray_exe.clone(), None, events);
        return match sup.start(Slot::A, ep.clone(), launch, cancel).await {
            Ok(_) => Ok(Start::Ready(
                Box::new(Running::Xray(Box::new(sup))),
                ep.loopback(),
            )),
            Err(XrayError::Cancelled) => Err(AppError::cancelled()),
            Err(XrayError::ConfigRejected(_)) => Ok(Start::Invalid),
            // Go's locale-independent `listen tcp …: bind:`: another program took our port.
            Err(XrayError::ExitedEarly { tail, .. })
                if tail.contains(&format!("127.0.0.1:{}: bind:", ep.port())) =>
            {
                if !lost.is_empty() {
                    return Err(ports::PortsExhausted.into());
                }
                lost.push(ep.port());
                continue;
            }
            Err(XrayError::ExitedEarly { tail, .. }) => Ok(Start::Failed(tail)),
            Err(XrayError::NotReady { cause, .. }) => Ok(Start::Failed(format!(
                "local socks not ready: {}",
                readiness_text(cause)
            ))),
            Err(err) => Err(err.into()),
        };
    }
}

/// The alias of the physical adapter that carries the default IPv4 route (one with a gateway
/// first), for `bind_interface`; `None` when no physical adapter is up.
pub(crate) async fn physical_alias() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        let adapters = vpnte_winnet::adapters::physical_adapters().ok()?;
        let routed = adapters.iter().find(|a| !a.gateways_v4().is_empty());
        routed.or(adapters.first()).map(|a| a.alias.clone())
    })
    .await
    .ok()
    .flatten()
}
