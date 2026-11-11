//! In-place upstream switch (tunnel-core §3.8): admission (`None` = "use the protected
//! restart") and the runtime's [`SwitchOps`] over the two Xray slots. The coordinator itself
//! is `crate::switch`.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::{UdpPolicy, Upstream, select_mtu};
use vpnte_engine::slot::Slot as EngineSlot;
use vpnte_engine::xray_config::{self, ResolvePath};
use vpnte_engine::xray_process::SlotLaunch;

use super::actor::{Actor, Phase, SlotSession};
use super::capture::{Capture, CaptureProof, EngineParts};
use super::engines::{CoreProc, Engines};
use super::{Timings, config};
use crate::api::{
    Mode, OwnerCheck, Slot, StartRequest, SwitchOutcome, SwitchPhase, SwitchReceipt, TunnelEvent,
    VpnProfile,
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
        let resolved = self
            .engines
            .resolve(&graph.hosts(), ResolvePath::ViaSingBox(dns), cancel)
            .await?;
        graph.substitute(&resolved.addrs);
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
        self.slots.slots.start(slot, ep, launch, cancel).await?;
        Ok(())
    }

    async fn probe(&mut self, slot: Slot, cancel: &CancellationToken) -> AppResult<()> {
        let i = engine_slot(slot).index();
        let ep = self.slots.endpoints[i].clone();
        let ip = self
            .engines
            .egress_via(ep.port(), ep.creds(), cancel)
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
        let expected = self.slots.egress[slot.index()]
            .ok_or_else(|| unconfirmed("upstream egress identity unavailable"))?;
        // The retained upstream gets its own short, fresh proof the caller cannot cancel.
        let (budget, token) = if slot == self.previous {
            (self.timings.confirm_previous, CancellationToken::new())
        } else {
            (self.timings.confirm_candidate, self.cancel.clone())
        };
        let seen = self.engines.egress(budget, &token).await?;
        if seen != expected {
            return Err(unconfirmed("tunnel egress differs from the slot's"));
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
        if !self.switch_admitted(&next).await {
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
        let xray = xray_config::select_engine(&profile.profile, next.engine).engine();
        if slots.suspect || xray.ok() != Some(Engine::Xray) || !slots.slots.running(slots.active) {
            return false;
        }
        let Ok(user) = self.deps.inputs.snapshot().await else {
            return false;
        };
        let phys_dns = self.deps.engines.physical_dns().await;
        let hostname = config::endpoint_is_hostname(&profile.profile);
        let engines = [self.deps.engines.xray_exe()];
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
        self.capture
            .config(&plan, &parts)
            .is_ok_and(|(_, key)| key == s.compat)
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
            next: profile,
            previous,
            cancel: op,
            is_owner,
            stops,
            stops_at,
            timings: &deps.timings,
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
        }
        tracing::info!(outcome = ?receipt.outcome, committed = receipt.committed,
            verified = receipt.verified(), "upstream switch finished");
        debug_assert!(receipt.outcome != SwitchOutcome::Success || receipt.committed);
        if receipt.committed {
            self.last = Some(next.clone());
            let name = profile.profile.name.clone();
            let protocol = profile.profile.kind.label().to_owned();
            self.publish(|st| {
                st.profile_name = Some(name);
                st.protocol = Some(protocol);
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
