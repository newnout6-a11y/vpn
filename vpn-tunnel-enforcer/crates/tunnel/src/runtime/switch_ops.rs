//! In-place upstream switch (tunnel-core §3.8): admission (`None` = "use the protected
//! restart") and the runtime's [`SwitchOps`] over the two Xray slots. The coordinator itself
//! is `crate::switch`.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, Loopback};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::{UdpPolicy, Upstream, select_mtu};
use vpnte_engine::slot::Slot as EngineSlot;
use vpnte_engine::xray_config::{self, ResolvePath, Resolved};
use vpnte_engine::xray_process::SlotLaunch;
use vpnte_winnet::adapters::{TUN_V4, TUN_V6};

use super::actor::{Actor, Phase, SlotSession};
use super::capture::{Capture, CaptureProof, EngineParts};
use super::engines::{CoreProc, EchoFailure, Engines, core_budget, echo_failed, echo_failure};
use super::{Timings, config};
use crate::api::{
    Mode, NameHint, Origin, OwnerCheck, Slot, StartRequest, SwitchFailure, SwitchOutcome,
    SwitchPhase, SwitchReceipt, TunnelEvent, VpnProfile,
};
use crate::switch::{SwitchOps, run_protected_switch};

pub(super) fn engine_slot(slot: Slot) -> EngineSlot {
    match slot {
        Slot::A => EngineSlot::A,
        Slot::B => EngineSlot::B,
    }
}

pub(super) fn api_slot(slot: EngineSlot) -> Slot {
    match slot {
        EngineSlot::A => Slot::A,
        EngineSlot::B => Slot::B,
    }
}

fn unconfirmed(what: &'static str) -> AppError {
    AppError::msg(
        ErrorKind::Network,
        Msg::new("tunnel.runtime.switchUnconfirmed"),
    )
    .with_source(std::io::Error::other(what))
}

/// The runtime's effects for one protected switch.
struct RuntimeSwitch<'a> {
    engines: &'a dyn Engines,
    capture: &'a dyn Capture,
    slots: &'a mut SlotSession,
    clash: &'a ClashEndpoint,
    proof: &'a CaptureProof,
    core: &'a Arc<dyn CoreProc>,
    next: &'a VpnProfile,
    previous: EngineSlot,
    cancel: &'a CancellationToken,
    is_owner: &'a OwnerCheck,
    /// The handle's stop counter and its value when the switch was requested.
    stops: &'a AtomicU64,
    stops_at: u64,
    timings: &'a Timings,
    /// When the staged graph's balancer has judged its members (`None`: no balancer).
    settle: Option<Duration>,
    /// The candidate's proof waits for the traffic it carries after the select (the handshake
    /// budget of its server name is spent for now: speed audit F4).
    by_traffic: bool,
    /// speed3 S3-07 (owner default 1): a user's switch to a server with fresh evidence selects
    /// first and proves once after it ([`RuntimeSwitch::confirm_fresh`]); every other switch
    /// keeps its probe.
    fresh: bool,
    /// speed3 S3-10 (b): the app's addresses for the candidate's names (this switch only).
    hints: Vec<NameHint>,
    /// The core's probe inbound (`live-check-in`): the TUN's proofs after the select go through
    /// it (lab L11-3).
    check: Option<&'a Loopback>,
    /// When the candidate's slot accepted: its balancer's observatory runs from about then.
    staged_at: Option<tokio::time::Instant>,
    /// The candidate's names answered from this process's memory (lab L11-4).
    recalled: Vec<String>,
}

/// The switch failed where its candidate was dialled (staged, probed, confirmed): an address it
/// dialled from memory or from the app's hint may be what failed, so it goes (S3-09 (e); the app
/// drops its hints by the same rule, speed3-a1).
pub fn dial_failed(receipt: &SwitchReceipt) -> bool {
    let dialled = |f: &SwitchFailure| {
        matches!(
            f.phase,
            SwitchPhase::Stage | SwitchPhase::Probe | SwitchPhase::Confirm
        )
    };
    receipt.outcome == SwitchOutcome::Failed && receipt.failures.iter().any(dialled)
}

/// How long a candidate proven by its own traffic may take to show it.
const TRAFFIC_PROOF: Duration = Duration::from_secs(3);
const TRAFFIC_POLL: Duration = Duration::from_millis(250);
/// How often a fresh candidate's own downloads are read during its one proof (loopback reads).
const FRESH_POLL: Duration = Duration::from_millis(50);

/// The pause between two reads of a candidate's downloads, `waited` into its proof: every
/// [`FRESH_POLL`] for the first `budget`, every [`TRAFFIC_POLL`] after it.
fn poll(waited: Duration, budget: Duration) -> Duration {
    if waited < budget {
        FRESH_POLL
    } else {
        TRAFFIC_POLL
    }
}

impl RuntimeSwitch<'_> {
    /// Answers came back through `slot` (its own connections downloaded something).
    async fn carries(&self, slot: EngineSlot) -> bool {
        let carried = self.engines.slot_downloads(self.clash, slot).await;
        carried.is_ok_and(|c| c.iter().any(|(_, down)| *down > 0))
    }

    /// What is left until the candidate's balancer has judged its members (`None`: no balancer,
    /// or judged already).
    fn settle_left(&self) -> Option<Duration> {
        let left = self.settle?.saturating_sub(self.staged_at?.elapsed());
        (!left.is_zero()).then_some(left)
    }

    /// The echo through the running core to the slot its selector points at: under the proxy
    /// capture through its mixed inbound (the way the user's programs go), under the TUN through
    /// the core's probe inbound (`live-check-in`, always to the selector). Lab L11-3: through the
    /// TUN the echo first looked its service's name up on the core's DoH connection, which the
    /// select had just cut, and the service's own requests follow the user's rules there.
    async fn echo(
        &self,
        limit: Duration,
        settle: Option<Duration>,
        token: &CancellationToken,
    ) -> AppResult<IpAddr> {
        let engines = self.engines;
        match (self.proof.port, self.check) {
            (Some(port), _) => engines.egress_core(port, None, limit, settle, token).await,
            (None, Some(check)) => {
                let creds = check.creds.as_ref();
                (engines.egress_core(check.port, creds, limit, settle, token)).await
            }
            // No probe inbound (never in a slot run): through the capture itself.
            (None, None) => engines.egress(None, limit, token).await,
        }
    }

    /// Data came back through the candidate `slot` after the select, within `within`: its own
    /// downloads (the user's traffic, read on loopback) or the echo through the core, whichever
    /// first; an echo that got nothing back leaves the traffic the rest of the time. `Ok(None)`:
    /// proven by its traffic; the echo's address or failure is the caller's to judge.
    async fn data_back(
        &self,
        slot: EngineSlot,
        limit: Duration,
        settle: Option<Duration>,
        within: Duration,
    ) -> AppResult<Option<IpAddr>> {
        if let Some(at) = settle {
            // Lab L11-3: one silent member of an unjudged balancer is no dead server.
            let ms = u64::try_from(at.as_millis()).unwrap_or(u64::MAX);
            tracing::info!(ms, "switch: the candidate's balancer settles first");
        }
        let echo_token = self.cancel.child_token();
        let echo = self.echo(limit, settle, &echo_token);
        tokio::pin!(echo);
        let deadline = tokio::time::sleep(within);
        tokio::pin!(deadline);
        let mut silent: Option<AppError> = None;
        let started = tokio::time::Instant::now();
        let back = loop {
            if self.carries(slot).await {
                if self.fresh {
                    tracing::info!(?slot, "switch: the fresh candidate carries traffic");
                } else {
                    tracing::info!(?slot, "switch: the candidate carries traffic");
                }
                break Ok(None);
            }
            tokio::select! {
                // Nothing came back, whichever deadline came first: the echo's own verdict.
                () = &mut deadline => {
                    break Err(silent.unwrap_or_else(|| echo_failed(EchoFailure::NoReply)));
                }
                () = self.cancel.cancelled() => break Err(AppError::cancelled()),
                seen = &mut echo, if silent.is_none() => match seen {
                    Ok(ip) => break Ok(Some(ip)),
                    // Its own traffic may still prove it until the deadline.
                    Err(e) if echo_failure(&e) == Some(EchoFailure::NoReply) => {
                        if self.fresh {
                            tracing::info!(error = %e, "switch: the fresh candidate's echo failed");
                        } else {
                            tracing::info!(error = %e, "switch: the candidate's echo got nothing back");
                        }
                        silent = Some(e);
                    }
                    Err(e) => break Err(e),
                },
                // A balanced candidate's longer wait reads the connections less often.
                () = tokio::time::sleep(poll(started.elapsed(), self.timings.confirm_candidate)) => {}
            }
        };
        echo_token.cancel();
        back
    }

    /// speed3 S3-07, the one proof of a fresh candidate selected without a probe: the selector
    /// read `slot` back at the select; data must now come back through it within
    /// `confirm_candidate` (a balanced slot not settled yet: until one request after its settle
    /// point), with no hedge: its own downloads (the user's traffic) count first, else the one
    /// echo through the core. Any exit counts: no probe named one, and servers of one provider
    /// share exits.
    async fn confirm_fresh(&mut self, slot: EngineSlot) -> AppResult<()> {
        let budget = self.timings.confirm_candidate;
        let settle = self.settle_left();
        // The echo's own hedge would start after twice the budget: never reached.
        let limit = budget.saturating_mul(2);
        let within = match settle {
            Some(_) => core_budget(limit, settle).1.total,
            None => budget,
        };
        match self.data_back(slot, limit, settle, within).await {
            Ok(ip) => {
                self.slots.egress[slot.index()] = ip;
                Ok(())
            }
            Err(e) if echo_failure(&e) == Some(EchoFailure::NoAddress) => Ok(()),
            Err(e) if echo_failure(&e) == Some(EchoFailure::NoReply) => {
                Err(unconfirmed("no answer through the fresh candidate"))
            }
            Err(e) => Err(e),
        }
    }

    /// The candidate selected without a probe of its own: answers coming back through it within
    /// [`TRAFFIC_PROOF`] prove it; none (an idle session) and it gets the probe it skipped,
    /// behind the budget as before.
    async fn confirm_by_traffic(&mut self, slot: EngineSlot) -> AppResult<()> {
        let until = tokio::time::Instant::now() + TRAFFIC_PROOF;
        loop {
            let carried = self.engines.slot_downloads(self.clash, slot).await;
            if carried.is_ok_and(|c| c.iter().any(|(_, down)| *down > 0)) {
                tracing::info!(?slot, "switch: the new slot carries traffic");
                return Ok(());
            }
            if tokio::time::Instant::now() >= until {
                break;
            }
            tokio::select! {
                () = self.cancel.cancelled() => return Err(AppError::cancelled()),
                () = tokio::time::sleep(TRAFFIC_POLL) => {}
            }
        }
        let ep = self.slots.endpoints[slot.index()].clone();
        let creds = ep.creds();
        let profile = &self.next.profile;
        let engines = self.engines;
        let ip = engines
            .egress_via(profile, ep.port(), creds, self.settle, self.cancel)
            .await?;
        self.slots.egress[slot.index()] = Some(ip);
        Ok(())
    }
}

/// The tunnel's echo `seen` proves it leaves through the slot whose own probe saw `expected`.
/// Lab live-8 L8-1: a balancer's connections leave from its members, so its probe and the
/// tunnel's echo may name two exits; the selector was read back, so for a `balanced` slot an
/// answer through the tunnel is the proof (answers without an address too).
fn tunnel_exit_matches(
    seen: AppResult<std::net::IpAddr>,
    expected: std::net::IpAddr,
    balanced: bool,
) -> AppResult<()> {
    match seen {
        Err(e) if balanced && echo_failure(&e) == Some(EchoFailure::NoAddress) => Ok(()),
        Err(e) => Err(e),
        Ok(seen) if !balanced && seen != expected => {
            Err(unconfirmed("tunnel egress differs from the slot's"))
        }
        Ok(_) => Ok(()),
    }
}

/// How long a switch's stage waits for a lookup ahead of the click already in flight (lab L11-4:
/// 107-336 ms each) before it asks the bootstrap itself.
const JOIN_LIMIT: Duration = Duration::from_millis(1_000);

/// The address of an answer learned elsewhere that a lookup could have given (S3-09's rules:
/// `may_be_server`, never our TUN's networks), IPv4 first.
fn first_usable(addrs: &[IpAddr]) -> Option<IpAddr> {
    let usable = |ip: &&IpAddr| {
        let ours = match ip {
            IpAddr::V4(v4) => TUN_V4.contains(v4),
            IpAddr::V6(v6) => TUN_V6.contains(v6),
        };
        vpnte_core::resolve::may_be_server(**ip) && !ours
    };
    addrs
        .iter()
        .filter(usable)
        .min_by_key(|ip| ip.is_ipv6())
        .copied()
}

/// The app's hints for `hosts` (S3-09's rules, as the start takes them): per hinted name its
/// [`first_usable`] address; the other names are asked. A hint names its host: it never stands
/// in for another.
fn hinted(hosts: &[String], hints: &[NameHint]) -> (HashMap<String, IpAddr>, Vec<String>) {
    let (mut found, mut ask) = (HashMap::new(), Vec::new());
    for host in hosts {
        let hint = hints.iter().find(|h| h.name.eq_ignore_ascii_case(host));
        match hint.and_then(|h| first_usable(&h.addrs)) {
            Some(ip) => {
                found.insert(host.clone(), ip);
            }
            None => ask.push(host.clone()),
        }
    }
    (found, ask)
}

/// Lab L11-4: the names of `hosts` this process answers without asking anyone
/// ([`vpnte_core::resolve::recall`]: the user's lookups ahead of the click, a recent session's
/// names; one in flight joined for up to [`JOIN_LIMIT`]), filtered as a hint is; the rest to ask.
async fn recalled(
    hosts: Vec<String>,
    cancel: &CancellationToken,
) -> (HashMap<String, IpAddr>, Vec<String>) {
    let (mut found, mut ask) = (HashMap::new(), Vec::new());
    for host in hosts {
        let recall = tokio::time::timeout(JOIN_LIMIT, vpnte_core::resolve::recall(&host));
        let addrs = tokio::select! {
            () = cancel.cancelled() => None,
            got = recall => got.ok().flatten(),
        };
        match addrs.as_deref().and_then(first_usable) {
            Some(ip) => {
                found.insert(host, ip);
            }
            None => ask.push(host),
        }
    }
    (found, ask)
}

/// The slot runs and the routes still go through the capture.
async fn proven(running: bool, capture: &dyn Capture, proof: &CaptureProof) -> bool {
    running && capture.routes_ok(proof).await
}

impl SwitchOps for RuntimeSwitch<'_> {
    async fn stage(&mut self, slot: Slot, cancel: &CancellationToken) -> AppResult<()> {
        let slot = engine_slot(slot);
        let device = self.next.device.unwrap_or_default();
        let mut graph = xray_config::proxy_graph(&self.next.profile, device)?;
        // The TUN is up: names resolve through sing-box's bootstrap inbound, never by Xray.
        let dns = SocketAddr::from((Ipv4Addr::LOCALHOST, self.slots.dns_bootstrap));
        let step = std::time::Instant::now();
        // speed3 S3-10 (b): a name the app's hint answers skips the bootstrap's cold direct DoH,
        // and so does one this process already holds (lab L11-4).
        let (hinted, ask) = hinted(&graph.hosts(), &self.hints);
        let (recalled, ask) = recalled(ask, cancel).await;
        self.recalled = recalled.keys().cloned().collect();
        let mut resolved = Resolved::default();
        if !ask.is_empty() {
            let path = ResolvePath::ViaSingBox(dns);
            resolved = self.engines.resolve(&ask, path, cancel).await?;
        }
        resolved.addrs.extend(hinted);
        resolved.addrs.extend(recalled);
        // speed3 S3-10 step lines (lab L-3: ~240 ms before «xray-b spawned» had no line).
        let (ms, asked) = (step.elapsed().as_millis(), ask.len());
        tracing::info!(ms, asked, "candidate resolved");
        let step = std::time::Instant::now();
        graph.substitute(&resolved.addrs);
        self.settle = super::start::settle_of(&graph);
        self.slots.balanced[slot.index()] = self.settle.is_some();
        let ep = self.slots.endpoints[slot.index()].clone();
        let launch = SlotLaunch {
            config: xray_config::build_config(&graph, &ep)
                .to_string()
                .into_bytes(),
            dial_target: resolved
                .addrs
                .values()
                .next()
                .map(|ip| SocketAddr::new(*ip, self.next.profile.port)),
        };
        tracing::info!(ms = step.elapsed().as_millis(), "candidate config built");
        // A staged slot has no proven exit yet: an address of its last server must never be
        // published for this one when its traffic proves it.
        self.slots.egress[slot.index()] = None;
        self.slots.slots.start(slot, ep, launch, cancel).await?;
        self.staged_at = Some(tokio::time::Instant::now());
        Ok(())
    }

    async fn probe(&mut self, slot: Slot, cancel: &CancellationToken) -> AppResult<()> {
        let i = engine_slot(slot).index();
        let ep = self.slots.endpoints[i].clone();
        if !self.engines.handshake_ready(&self.next.profile) {
            // Lab live-7 F4: the name's budget (3 handshakes a minute, shared by servers with
            // one REALITY name) held the switch for 30 s. The proof needs no handshake of its
            // own: the select comes first and the traffic the new slot carries proves it.
            tracing::info!("switch: the handshake budget is spent for now: proof by traffic");
            self.by_traffic = true;
            return Ok(());
        }
        if self.fresh {
            tracing::info!("switch: fresh evidence: select first, one proof after");
            return Ok(());
        }
        let ip = self
            .engines
            .egress_via(
                &self.next.profile,
                ep.port(),
                ep.creds(),
                self.settle,
                cancel,
            )
            .await?;
        self.slots.egress[i] = Some(ip);
        Ok(())
    }

    async fn select(&mut self, slot: Slot) -> AppResult<()> {
        self.engines.select(self.clash, engine_slot(slot)).await
    }

    async fn confirm(&mut self, slot: Slot) -> AppResult<()> {
        let slot = engine_slot(slot);
        let running = self.slots.slots.running(slot);
        if !proven(running, self.capture, self.proof).await {
            return Err(unconfirmed("slot or routes not proven"));
        }
        if self.by_traffic && slot != self.previous {
            return self.confirm_by_traffic(slot).await;
        }
        if self.fresh && slot != self.previous {
            return self.confirm_fresh(slot).await;
        }
        // A slot proven by its traffic named no exit (a switch by traffic, a recovery proven by
        // traffic: Lane A's L10-2): the selector was read back, so any answer proves it, as for a
        // balanced slot.
        let expected = self.slots.egress[slot.index()];
        let balanced = self.slots.balanced[slot.index()] || expected.is_none();
        let expected = expected.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        if slot == self.previous {
            // The retained upstream gets its own short, fresh proof the caller cannot cancel.
            let (budget, token) = (self.timings.confirm_previous, CancellationToken::new());
            let seen = self.echo(budget, None, &token).await;
            tunnel_exit_matches(seen, expected, balanced)?;
        } else {
            // Lab L11-3: its own traffic proves it too (any exit: the selector was read back),
            // and a balanced candidate not settled yet is asked again at its settle point.
            let (limit, settle) = (self.timings.confirm_candidate, self.settle_left());
            let within = core_budget(limit, settle).1.total;
            if let Some(seen) = self
                .data_back(slot, limit, settle, within)
                .await
                .transpose()
            {
                tunnel_exit_matches(seen, expected, balanced)?;
            }
        }
        let running = self.slots.slots.running(slot);
        if !proven(running, self.capture, self.proof).await {
            return Err(unconfirmed("slot or routes lost during the proof"));
        }
        Ok(())
    }

    fn alive(&self, slot: Slot) -> bool {
        self.slots.slots.running(engine_slot(slot))
    }

    async fn stop(&mut self, slot: Slot) -> AppResult<()> {
        self.slots.slots.stop(engine_slot(slot)).await?;
        Ok(())
    }

    fn commit(&mut self, slot: Slot) -> AppResult<()> {
        if !self.is_owner() {
            return Err(unconfirmed("switch superseded"));
        }
        let slot = engine_slot(slot);
        self.slots.slots.activate(slot)?;
        self.slots.active = slot;
        Ok(())
    }

    /// Old `owner()`: the caller's check, no stop requested since, the same core still alive.
    /// A stop request ends ownership at once, so the drain neither re-selects nor re-proves
    /// the previous upstream (§7.17 "native stop mid-switch").
    fn is_owner(&self) -> bool {
        (self.is_owner)()
            && self.stops.load(Ordering::SeqCst) == self.stops_at
            && self.core.exit_watch().borrow().is_none()
    }
}

impl Actor {
    /// Swaps the upstream behind the running tunnel, or `None` when that is not possible in
    /// place (anything but a compatible Xray-slot session). `stops` = the stop counter when the
    /// switch was requested.
    pub(super) async fn cmd_switch(
        &mut self,
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
        stops: u64,
    ) -> Option<SwitchReceipt> {
        let step = std::time::Instant::now();
        let admitted = self.switch_admitted(&next).await;
        tracing::info!(admitted, ms = step.elapsed().as_millis(), "switch admitted");
        if !admitted {
            return None;
        }
        self.switches += 1;
        let generation = self.switches;
        self.emit(TunnelEvent::SwitchBegan { generation });
        let op = cancel.child_token();
        self.guard_op(&op);
        let receipt = self.run_switch(&next, &op, &is_owner, stops).await;
        self.clear_op();
        if let Some(receipt) = &receipt {
            self.emit(TunnelEvent::SwitchFinished {
                generation,
                verified: receipt.verified(),
            });
        }
        receipt
    }

    /// speed3 S3-07: the app's own evidence (in-process) that the server works now.
    fn app_evidence(&self, profile_id: &str) -> bool {
        (self.deps.failover.as_ref()).is_some_and(|f| f.fresh(profile_id))
    }

    /// The running config can serve `next` as it is: Xray slots both, same config key with
    /// the current settings (split / domain rules, DNS, MTU, UDP policy), active slot alive.
    async fn switch_admitted(&self, next: &StartRequest) -> bool {
        let Phase::Running(s) = &self.phase else {
            return false;
        };
        if next.capture != s.req.capture {
            return false;
        }
        let (Mode::DirectVpn { .. }, Mode::DirectVpn { profile }) = (&s.req.mode, &next.mode)
        else {
            return false;
        };
        let Some(slots) = &s.slots else {
            return false;
        };
        let run = super::start::choose(profile, next.engine).map(|r| r.kind);
        if slots.suspect || run.ok() != Some(Engine::Xray) || !slots.slots.running(slots.active) {
            return false;
        }
        let Ok(user) = self.deps.inputs.snapshot().await else {
            return false;
        };
        let phys_dns = self.deps.engines.physical_dns().await;
        let hostname = config::endpoint_is_hostname(&profile.profile);
        // The start's engine rules exactly, or the compat key never matches.
        let engines = super::start::direct_engines(
            &*self.deps.engines,
            next.capture,
            vec![self.deps.engines.xray_exe()],
        );
        let (routing, _) = config::routing(&user, &engines, false, &phys_dns, hostname);
        let mut plan = s.plan.clone();
        plan.mtu = select_mtu(next.stealth, next.adaptive, next.public_wifi);
        let parts = EngineParts {
            upstream: Upstream::XraySlots {
                slots: slots.endpoints.clone(),
                active: slots.active,
                udp: UdpPolicy::of(&profile.profile),
            },
            listeners: s.listeners.clone(),
            routing,
            phys_dns,
        };
        // The key alone: rendering the whole config only to compare it cost every switch.
        self.capture
            .compat(&plan, &parts)
            .is_ok_and(|key| key == s.compat)
    }

    /// Runs the coordinator, racing the core's exit (a crash cancels the switch and waits for
    /// its compensation), then publishes a commit.
    async fn run_switch(
        &mut self,
        next: &StartRequest,
        op: &CancellationToken,
        is_owner: &OwnerCheck,
        stops_at: u64,
    ) -> Option<SwitchReceipt> {
        let Mode::DirectVpn { profile } = &next.mode else {
            return None;
        };
        // Xray gets the app's default TLS tricks resolved into the profile (item 18).
        let run = VpnProfile {
            profile: Arc::new(super::start::xray_profile(&profile.profile, next)),
            ..profile.clone()
        };
        // What the client sent with this request about the server: read once (handed out once).
        let facts = self.deps.inputs.server_facts(&profile.id);
        let fresh = next.origin == Origin::User && (facts.fresh || self.app_evidence(&profile.id));
        let deps = &self.deps;
        let capture = &*self.capture;
        let stops = &self.shared.stops;
        let Phase::Running(s) = &mut self.phase else {
            return None;
        };
        let slots = s.slots.as_mut()?;
        let previous = slots.active;
        let mut exit = s.core.exit_watch();
        let mut ops = RuntimeSwitch {
            engines: &*deps.engines,
            capture,
            slots,
            clash: &s.clash,
            proof: &s.proof,
            core: &s.core,
            next: &run,
            previous,
            cancel: op,
            is_owner,
            stops,
            stops_at,
            timings: &deps.timings,
            settle: None,
            by_traffic: false,
            fresh,
            hints: facts.hints,
            check: s.listeners.probe.as_ref(),
            staged_at: None,
            recalled: Vec::new(),
        };
        let candidate = previous.other();
        let mut receipt = {
            let run = run_protected_switch(api_slot(previous), api_slot(candidate), &mut ops, op);
            tokio::pin!(run);
            tokio::select! {
                receipt = &mut run => receipt,
                () = async { let _ = exit.wait_for(Option::is_some).await; } => {
                    // A crash cancels the switch; its compensation still runs to the end.
                    op.cancel();
                    run.await
                }
            }
        };
        receipt.ownership_lost = !ops.is_owner();
        let stage_failed = receipt
            .failures
            .iter()
            .any(|f| f.phase == SwitchPhase::Stage);
        if receipt.previous_preserved && receipt.candidate_stopped && stage_failed {
            // Another listener may have claimed the standby port: reallocate next time.
            ops.slots.suspect = true;
        }
        if dial_failed(&receipt) && !ops.recalled.is_empty() {
            // S3-09 (e): an answer from memory that did not carry the candidate goes; the next
            // try asks the resolvers.
            vpnte_core::resolve::drop_names(&ops.recalled);
        }
        if receipt.committed {
            s.req = next.clone();
            // The new slot's own proof (`None`: proven by its traffic, no address read).
            s.exit = ops.slots.egress[ops.slots.active.index()];
            // Admitted only for an Xray run, so the choice is known; its reason may differ.
            if let Ok(run) = super::start::choose(profile, next.engine) {
                s.engine = run;
                receipt.engine = Some(run);
            }
            receipt.warnings = super::start::xray_warnings(&run.profile, next);
        }
        tracing::info!(outcome = ?receipt.outcome, committed = receipt.committed,
            verified = receipt.verified(), "upstream switch finished");
        debug_assert!(receipt.outcome != SwitchOutcome::Success || receipt.committed);
        if receipt.committed {
            self.last = Some(next.clone());
            let name = profile.profile.name.clone();
            let protocol = profile.profile.kind.label().to_owned();
            let engine = receipt.engine;
            let exit = match &self.phase {
                Phase::Running(s) => s.exit,
                _ => None,
            };
            self.publish(|st| {
                st.profile_name = Some(name);
                st.protocol = Some(protocol);
                st.engine = engine.or(st.engine);
                st.proven_exit = exit;
                st.proxy_reachable = true;
                st.warning = None;
            });
            // History observers close the old server's session; they cannot undo the commit.
            self.emit(TunnelEvent::ProtectedRestart {
                reason: "server switch".into(),
            });
        }
        Some(receipt)
    }
}

#[cfg(test)]
mod confirm_tests {
    use std::net::IpAddr;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Lab live-8 L8-1: a plain slot's tunnel exit must be the slot's own; a balanced slot's
    /// may be any member's (or an answer without an address), a silent tunnel never passes.
    #[test]
    fn a_balanced_slot_confirms_by_any_answer() {
        let (slot, other) = (ip("198.51.100.1"), ip("198.51.100.2"));
        assert!(tunnel_exit_matches(Ok(slot), slot, false).is_ok());
        assert!(tunnel_exit_matches(Ok(other), slot, false).is_err());
        assert!(tunnel_exit_matches(Ok(other), slot, true).is_ok());
        let no_address = || Err(echo_failed(EchoFailure::NoAddress));
        assert!(tunnel_exit_matches(no_address(), slot, true).is_ok());
        assert!(tunnel_exit_matches(no_address(), slot, false).is_err());
        let silent = Err(echo_failed(EchoFailure::NoReply));
        assert!(tunnel_exit_matches(silent, slot, true).is_err());
    }
}

#[cfg(test)]
mod exit_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;
    use vpnte_base::types::EnginePref;

    use super::super::tests::{World, XRAY_KEY, XRAY_KEY_2, deps, vpn_req};
    use crate::api::{OwnerCheck, Runtime};
    use crate::runtime::TunnelHandle;

    /// Lab L10-7 (p-wire5): a committed switch publishes the exit its new slot's proof saw; the
    /// start's address does not stay behind.
    #[tokio::test]
    async fn a_committed_switch_reports_the_new_slots_exit() {
        let w = World::new();
        let h = TunnelHandle::spawn(deps(&w));
        h.start(
            vpn_req(XRAY_KEY, EnginePref::Xray),
            CancellationToken::new(),
        )
        .await
        .expect("start");
        let start = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        assert_eq!(h.status().borrow().proven_exit, Some(start));
        let owner: OwnerCheck = Arc::new(|| true);
        let next = vpn_req(XRAY_KEY_2, EnginePref::Xray);
        let sw = h
            .switch_upstream(next, CancellationToken::new(), owner)
            .await
            .expect("in place");
        assert!(sw.committed, "{sw:?}");
        let exit = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43));
        assert_eq!(h.status().borrow().proven_exit, Some(exit));
    }
}
