//! Routing plan for Hard mode: may the app create its system TUN now, and what would change?
//! A pure decision table over the foreign tunnels, proxy listeners and the local proxy found on
//! this machine (old `connectionPlanner`), plus [`plan_now`] that reads them.
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, Verdict, now_ms};
use vpnte_winnet::adapters::foreign_tun::{Foreign, Severity};

use crate::local_proxy::{ListenerRow, LocalProxy};

/// Overall state of the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanStatus {
    Ready,
    Protected,
    Blocked,
    Broken,
}

/// What the app should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendedMode {
    /// Start our TUN.
    Hard,
    /// Keep using the VPN that is already up.
    External,
    /// Nothing can be started now.
    Off,
}

/// A tunnel adapter that is not ours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub name: String,
    pub description: String,
    pub address: IpAddr,
    /// It captures default routes (prefix ≤ /1): starting our TUN next to it is refused.
    pub conflict: bool,
}

impl From<&Foreign> for TunnelInfo {
    fn from(f: &Foreign) -> Self {
        Self {
            name: f.name.clone(),
            description: f.description.clone(),
            address: f.address,
            conflict: f.severity == Severity::Conflict,
        }
    }
}

impl TunnelInfo {
    /// `name address`, as the old plan texts printed it.
    pub fn label(&self) -> String {
        format!("{} {}", self.name, self.address)
    }
}

/// A loopback listener that looks like a VPN / proxy client (display only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerInfo {
    pub process: String,
    pub addr: SocketAddr,
    pub pid: u32,
}

/// Process names of VPN / proxy clients.
pub static CLIENT_PROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)happ|hiddify|nekoray|nekobox|v2ray|xray|sing-box|singbox|sing-tun|clash|flclash|mihomo|shadowsocks|ss-local|trojan|outline|wireguard|openvpn|karing|streisand|surfboard|vpn",
    )
    .expect("static regex")
});

/// Ports such clients use by default.
pub fn is_client_port(port: u16) -> bool {
    matches!(
        port,
        1080 | 1081
            | 1087
            | 10808
            | 10809
            | 7890
            | 7891
            | 7892
            | 7893
            | 7897
            | 8080
            | 2080
            | 2081
            | 6450
            | 6451
            | 9090
            | 20170
            | 20171
            | 8388
            | 17990..=17999
    )
}

/// Loopback / wildcard listeners of a client process or on a client port, unique by
/// (process, port); `skip_pids` = the app's own processes.
pub fn proxy_listeners(rows: &[ListenerRow], skip_pids: &[u32]) -> Vec<ListenerInfo> {
    let mut out: Vec<ListenerInfo> = Vec::new();
    for row in rows {
        let ip = row.local.ip();
        let process = row.process.clone().unwrap_or_default();
        if !(ip.is_loopback() || ip.is_unspecified())
            || skip_pids.contains(&row.pid)
            || !(CLIENT_PROCESS.is_match(&process) || is_client_port(row.local.port()))
            || out
                .iter()
                .any(|l| l.process == process && l.addr.port() == row.local.port())
        {
            continue;
        }
        out.push(ListenerInfo {
            process,
            addr: row.local,
            pid: row.pid,
        });
    }
    out
}

/// One step of the plan: what it is now, and what it will be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    pub label: Msg,
    pub before: Msg,
    pub after: Msg,
    pub verdict: Verdict,
}

/// The plan shown on the start page / diagnostics and consulted by the Hard-mode start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingPlan {
    pub ran_at: UnixMs,
    pub status: PlanStatus,
    pub recommended_mode: RecommendedMode,
    pub title: Msg,
    /// Shown before the explanation: the adapter read failed, a conflict is not excluded.
    pub note: Option<Msg>,
    pub explanation: Msg,
    pub before: Msg,
    pub after: Msg,
    pub can_start_hard: bool,
    pub proxy: Option<LocalProxy>,
    /// Foreign tunnels; empty also when the read failed (`tunnels_verified == false`).
    pub tunnels: Vec<TunnelInfo>,
    pub tunnels_verified: bool,
    pub listeners: Vec<ListenerInfo>,
    pub blockers: Vec<Msg>,
    pub steps: Vec<PlanStep>,
}

/// What the decision table looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanInputs {
    /// Our TUN is up.
    pub tun_running: bool,
    /// Alias of our TUN for the texts (`None` = the fallback alias).
    pub tun_alias: Option<String>,
    /// Foreign tunnels; `None` = the adapter read failed.
    pub tunnels: Option<Vec<TunnelInfo>>,
    pub listeners: Vec<ListenerInfo>,
    pub direct_vpn: bool,
    /// Name of the active Direct VPN profile.
    pub active_profile: Option<String>,
    /// The proxy Hard mode would use (the probed override, or the detector's result).
    pub proxy: Option<LocalProxy>,
}

type Args<'a> = &'a [(&'static str, &'a str)];

fn msg(key: String, args: Args) -> Msg {
    args.iter().fold(Msg::new(key), |m, &(k, v)| m.arg(k, v))
}

fn step(name: &str, verdict: Verdict, args: Args) -> PlanStep {
    let part = |p: &str| msg(format!("probes.plan.step.{name}.{p}"), args);
    PlanStep {
        label: part("label"),
        before: part("before"),
        after: part("after"),
        verdict,
    }
}

/// The decision table (first match wins):
/// our TUN + foreign tunnel → broken; foreign tunnel → protected (Hard start refused only when
/// one captures default routes); Direct VPN without / with a profile → blocked / ready; local
/// proxy missing / not answering / verified → blocked / blocked / ready. An unread adapter list
/// never claims "no conflicting TUN": a warning step and note are added instead.
pub fn routing_plan(inputs: &PlanInputs) -> RoutingPlan {
    let tun = inputs
        .tun_alias
        .clone()
        .unwrap_or_else(|| vpnte_winnet::adapters::alias::FALLBACK.to_owned());
    let tunnels = inputs.tunnels.clone().unwrap_or_default();
    let foreign = tunnels
        .iter()
        .map(TunnelInfo::label)
        .collect::<Vec<_>>()
        .join(", ");
    let proxy = inputs
        .proxy
        .as_ref()
        .map(LocalProxy::label)
        .unwrap_or_default();
    let profile = inputs.active_profile.clone().unwrap_or_default();
    let args: Args = &[
        ("tun", &tun),
        ("foreign", &foreign),
        ("proxy", &proxy),
        ("profile", &profile),
    ];

    let mut steps = Vec::new();
    let (kind, status, mode, can_start) = if inputs.tun_running && !tunnels.is_empty() {
        steps.push(step("removeDouble", Verdict::Fail, args));
        (
            "doubleTunnel",
            PlanStatus::Broken,
            RecommendedMode::External,
            false,
        )
    } else if !tunnels.is_empty() {
        steps.push(step("useExisting", Verdict::Ok, args));
        if let Some(p) = &inputs.proxy {
            steps.push(step(
                "viaProxy",
                if p.verified {
                    Verdict::Ok
                } else {
                    Verdict::Warn
                },
                args,
            ));
        }
        // D-7 / B-22: the start refuses a tunnel that captures default routes; agree with it.
        let can_start = !tunnels.iter().any(|t| t.conflict);
        (
            "foreignTun",
            PlanStatus::Protected,
            RecommendedMode::External,
            can_start,
        )
    } else if inputs.direct_vpn && inputs.active_profile.is_none() {
        steps.push(step("chooseProfile", Verdict::Fail, args));
        (
            "noProfile",
            PlanStatus::Blocked,
            RecommendedMode::Off,
            false,
        )
    } else if inputs.direct_vpn {
        steps.push(step("connectProfile", Verdict::Ok, args));
        steps.push(step("lanDirectVpn", Verdict::Ok, args));
        (
            "directReady",
            PlanStatus::Ready,
            RecommendedMode::Hard,
            true,
        )
    } else if inputs.proxy.is_none() {
        steps.push(step("findProxy", Verdict::Fail, args));
        ("noProxy", PlanStatus::Blocked, RecommendedMode::Off, false)
    } else if inputs.proxy.as_ref().is_some_and(|p| !p.verified) {
        steps.push(step("checkProxy", Verdict::Fail, args));
        (
            "proxyDead",
            PlanStatus::Blocked,
            RecommendedMode::Off,
            false,
        )
    } else {
        steps.push(step("createTun", Verdict::Ok, args));
        steps.push(step("lanDirectProxy", Verdict::Ok, args));
        ("hardReady", PlanStatus::Ready, RecommendedMode::Hard, true)
    };

    let part = |p: &str| msg(format!("probes.plan.{kind}.{p}"), args);
    let blockers = match kind {
        "directReady" | "hardReady" => Vec::new(),
        _ => vec![part("blocker")],
    };
    let mut plan = RoutingPlan {
        ran_at: now_ms(),
        status,
        recommended_mode: mode,
        title: part("title"),
        note: None,
        explanation: part("explanation"),
        before: part("before"),
        after: part("after"),
        can_start_hard: can_start,
        proxy: inputs.proxy.clone(),
        tunnels,
        tunnels_verified: inputs.tunnels.is_some(),
        listeners: inputs.listeners.clone(),
        blockers,
        steps,
    };
    if inputs.tunnels.is_none() {
        // Fail closed on the claim, not on availability.
        plan.steps
            .insert(0, step("checkTunnels", Verdict::Warn, args));
        plan.note = Some(Msg::new("probes.plan.tunnelsUnverified"));
        if plan.status == PlanStatus::Ready {
            plan.explanation = Msg::new("probes.plan.readyUnverified");
        }
    }
    plan
}

impl RoutingPlan {
    /// The Hard-mode start gate: `Conflict` with the plan's own refusal text when it may not start.
    pub fn gate(&self) -> vpnte_base::AppResult<()> {
        if self.can_start_hard {
            return Ok(());
        }
        let key = self.title.key.replace(".title", ".gate");
        Err(vpnte_base::AppError::conflict(Msg {
            key: key.into(),
            args: self.title.args.clone(),
        }))
    }
}

/// What [`plan_now`] needs from the running app.
pub struct PlanContext<'a> {
    pub tun_running: bool,
    /// LUID of our running TUN: never reported as foreign.
    pub tun_luid: Option<u64>,
    pub tun_alias: Option<String>,
    pub direct_vpn: bool,
    pub active_profile: Option<String>,
    /// Manual proxy from the settings (`host`, `port`, kind): probed instead of detected.
    pub proxy_override: Option<(String, u16, vpnte_base::types::ProxyKind)>,
    pub detector: &'a crate::local_proxy::LocalProxyDetector,
    /// The app's own processes (engines), left out of the listener list.
    pub skip_pids: Vec<u32>,
}

/// Reads the machine (foreign tunnels, listeners, the proxy) and applies [`routing_plan`].
/// No proxy is looked for in Direct VPN mode.
pub async fn plan_now(ctx: PlanContext<'_>) -> RoutingPlan {
    use vpnte_winnet::adapters::{alias, foreign_tun};
    let own_luid = ctx.tun_luid;
    let tunnels = tokio::task::spawn_blocking(move || {
        let aliases = alias::all_aliases();
        let own: Vec<&str> = aliases.iter().map(String::as_str).collect();
        foreign_tun::detect(own_luid, &own)
            .ok()
            .map(|found| found.iter().map(TunnelInfo::from).collect())
    });
    let mut skip = ctx.skip_pids.clone();
    skip.push(std::process::id());
    let listeners = tokio::task::spawn_blocking(move || {
        crate::local_proxy::listener_rows()
            .map(|rows| proxy_listeners(&rows, &skip))
            .unwrap_or_default()
    });
    let proxy = async {
        match (&ctx.proxy_override, ctx.direct_vpn) {
            (_, true) => None,
            (Some((host, port, kind)), false) => {
                crate::local_proxy::probe_manual(host, *port, *kind).await
            }
            (None, false) => ctx.detector.detect().await,
        }
    };
    let (tunnels, listeners, proxy) = tokio::join!(tunnels, listeners, proxy);
    routing_plan(&PlanInputs {
        tun_running: ctx.tun_running,
        tun_alias: ctx.tun_alias,
        tunnels: tunnels.ok().flatten(),
        listeners: listeners.unwrap_or_default(),
        direct_vpn: ctx.direct_vpn,
        active_profile: ctx.active_profile,
        proxy,
    })
}
