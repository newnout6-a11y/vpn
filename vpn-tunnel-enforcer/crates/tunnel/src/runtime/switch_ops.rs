//! In-place upstream switch (tunnel-core §3.8): admission (`None` = "use the protected
//! restart") and the runtime's [`SwitchOps`] over the two Xray slots. The coordinator itself
//! is `crate::switch`.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::{UdpPolicy, Upstream, select_mtu};
use vpnte_engine::slot::Slot as EngineSlot;
use vpnte_engine::xray_config::{self, ResolvePath, Resolved};
use vpnte_engine::xray_process::SlotLaunch;
use vpnte_winnet::adapters::{TUN_V4, TUN_V6};

use super::actor::{Actor, Phase, SlotSession};
use super::capture::{Capture, CaptureProof, EngineParts};
use super::engines::{CoreProc, EchoFailure, Engines, echo_failure};
use super::{Timings, config};
use crate::api::{
    Mode, NameHint, Origin, OwnerCheck, Slot, StartRequest, SwitchOutcome, SwitchPhase,
    SwitchReceipt, TunnelEvent, VpnProfile,
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
    settle: Option<std::time::Duration>,
    /// The candidate's proof waits for the traffic it carries after the select (the handshake
    /// budget of its server name is spent for now: speed audit F4).
    by_traffic: bool,
    /// speed3 S3-07 (owner default 1): a user's switch to a server with fresh evidence selects
    /// first and proves once after it ([`RuntimeSwitch::confirm_fresh`]); every other switch
    /// keeps its probe.
    fresh: bool,
    /// speed3 S3-10 (b): the app's addresses for the candidate's names (this switch only).
    hints: Vec<NameHint>,
}

/// How long a candidate proven by its own traffic may take to show it.
const TRAFFIC_PROOF: std::time::Duration = std::time::Duration::from_secs(3);
const TRAFFIC_POLL: std::time::Duration = std::time::Duration::from_millis(250);
/// How often a fresh candidate's own downloads are read during its one proof (loopback reads).
const FRESH_POLL: std::time::Duration = std::time::Duration::from_millis(50);

impl RuntimeSwitch<'_> {
    /// Answers came back through `slot` (its own connections downloaded something).
    async fn carries(&self, slot: EngineSlot) -> bool {
        let carried = self.engines.slot_downloads(self.clash, slot).await;
        carried.is_ok_and(|c| c.iter().any(|(_, down)| *down > 0))
    }

    /// speed3 S3-07, the one proof of a fresh candidate selected without a probe: the selector
    /// read `slot` back at the select; data must now come back through it within
    /// `confirm_candidate`, with no hedge: its own downloads (the user's traffic) count first,
    /// else the one echo through the capture. Any exit counts: no probe named one, and servers
    /// of one provider share exits.
    async fn confirm_fresh(&mut self, slot: EngineSlot) -> AppResult<()> {
        let (engines, port, cancel) = (self.engines, self.proof.port, self.cancel);
        let budget = self.timings.confirm_candidate;
        let echo_token = cancel.child_token();
        // The echo's own hedge would start after twice the budget: never reached.
        let echo = engines.egress(port, budget.saturating_mul(2), &echo_token);
        tokio::pin!(echo);
        let deadline = tokio::time::sleep(budget);
        tokio::pin!(deadline);
        let mut echoed = false;
        let proven = loop {
            if self.carries(slot).await {
                tracing::info!(?slot, "switch: the fresh candidate carries traffic");
                break Ok(());
            }
            tokio::select! {
                () = &mut deadline => break Err(unconfirmed("no answer through the fresh candidate")),
                () = cancel.cancelled() => break Err(AppError::cancelled()),
                seen = &mut echo, if !echoed => {
                    echoed = true;
                    match seen {
                        Ok(ip) => {
                            self.slots.egress[slot.index()] = Some(ip);
                            break Ok(());
                        }
                        Err(e) if echo_failure(&e) == Some(EchoFailure::NoAddress) => break Ok(()),
                        // Its own traffic may still prove it until the deadline.
                        Err(e) => tracing::info!(error = %e, "switch: the fresh candidate's echo failed"),
                    }
                }
                () = tokio::time::sleep(FRESH_POLL) => {}
            }
        };
        echo_token.cancel();
        proven
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

/// The app's hints for `hosts` (S3-09's rules, as the start takes them): per hinted name the
/// first address a lookup could have answered (`may_be_server`, never our TUN's networks), IPv4
/// first; the other names are asked. A hint names its host: it never stands in for another.
fn hinted(hosts: &[String], hints: &[NameHint]) -> (HashMap<String, IpAddr>, Vec<String>) {
    let usable = |ip: &&IpAddr| {
        let ours = match ip {
            IpAddr::V4(v4) => TUN_V4.contains(v4),
            IpAddr::V6(v6) => TUN_V6.contains(v6),
        };
        vpnte_core::resolve::may_be_server(**ip) && !ours
    };
    let (mut found, mut ask) = (HashMap::new(), Vec::new());
    for host in hosts {
        let hint = hints.iter().find(|h| h.name.eq_ignore_ascii_case(host));
        match hint.and_then(|h| h.addrs.iter().filter(usable).min_by_key(|ip| ip.is_ipv6())) {
            Some(ip) => {
                found.insert(host.clone(), *ip);
            }
            None => ask.push(host.clone()),
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
        // speed3 S3-10 (b): a name the app's hint answers skips the bootstrap's cold direct DoH.
        let (hinted, ask) = hinted(&graph.hosts(), &self.hints);
        let mut resolved = Resolved::default();
        if !ask.is_empty() {
            let path = ResolvePath::ViaSingBox(dns);
            resolved = self.engines.resolve(&ask, path, cancel).await?;
        }
        resolved.addrs.extend(hinted);
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
        self.slots.slots.start(slot, ep, launch, cancel).await?;
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
        // The retained upstream gets its own short, fresh proof the caller cannot cancel.
        let (budget, token) = if slot == self.previous {
            (self.timings.confirm_previous, CancellationToken::new())
        } else {
            (self.timings.confirm_candidate, self.cancel.clone())
        };
        let seen = self.engines.egress(self.proof.port, budget, &token).await;
        tunnel_exit_matches(seen, expected, balanced)?;
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
        if receipt.committed {
            s.req = next.clone();
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
            self.publish(|st| {
                st.profile_name = Some(name);
                st.protocol = Some(protocol);
                st.engine = engine.or(st.engine);
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

    use super::super::engines::echo_failed;
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
