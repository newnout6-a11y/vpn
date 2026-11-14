//! The registry of slots: per-slot state (spec 3.1), the status projection (3.26) and slot and
//! port allocation (2.13, 3.23). Plain data; the manager mutates it under its lock.
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{Engine as EngineKind, UnixMs};

use super::launch::Engine;
use super::run::LoopCmd;
use crate::health::Route;
use crate::model::{InstanceStatus, Lifecycle, derive_readiness};
use crate::slot::{self, CONTROL_HOST, Slot};

/// Rotation keys remembered per slot, and how long one suppresses a repeated rotation (B-14:
/// the old map kept every key forever, so a key reused hours later silently skipped a rotation).
const ROTATION_KEYS: usize = 64;
const ROTATION_KEY_TTL: Duration = Duration::from_secs(600);

/// The profile a slot runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Assigned {
    pub id: String,
    pub name: String,
    pub country: Option<String>,
}

/// The live engine of a slot and the handles of the tasks watching it.
pub(super) struct Live {
    pub engine: Arc<dyn Engine>,
    /// Which engine carries the server (an Xray child = Xray).
    pub kind: EngineKind,
    pub pid: u32,
    /// Ends the slot's health loop, exit watcher and output pump.
    pub cancel: CancellationToken,
    pub probes: mpsc::UnboundedSender<LoopCmd>,
    /// What this engine runs without (shown on the slot's row while it runs).
    pub notice: Option<Msg>,
}

/// One slot (old `stateForSlot`); created on first use, kept after a stop for its counters.
#[derive(Default)]
pub(super) struct SlotState {
    /// A route was asked for (a failed start stays configured until an explicit stop).
    pub configured: bool,
    pub port: Option<u16>,
    pub profile: Option<Assigned>,
    pub started_at: Option<UnixMs>,
    /// Country filter of the last start; sticky across rotations until an explicit stop (B-17).
    pub country_query: Option<String>,
    /// Bumped by every start / rotate; continuations of an older generation are dropped.
    pub generation: u64,
    pub updated_at: Option<UnixMs>,
    pub last_rotate_reason: Option<String>,
    /// Stopped after its failure budget; keeps showing which profile died.
    pub auto_disabled: bool,
    pub route: Route,
    pub live: Option<Live>,
    rotations: VecDeque<(String, Instant)>,
}

impl SlotState {
    /// The wire status of this slot; `ready` / `running` are derived over all slots later.
    pub fn instance(&self, slot: Slot) -> InstanceStatus {
        let running = self.live.is_some();
        let expose = self.configured || self.auto_disabled;
        let port = self.port.filter(|_| self.configured);
        let profile = self.profile.as_ref().filter(|_| expose);
        let r = &self.route;
        InstanceStatus {
            slot,
            running: false,
            process_running: running,
            ready: false,
            health: r.health,
            state: r.lifecycle,
            generation: self.generation,
            egress_ip: r.egress_ip,
            latency_ms: r.latency_ms,
            last_checked_at: r.last_checked_at,
            last_success_at: r.last_success_at,
            egress_checked_at: r.last_success_at,
            updated_at: self.updated_at,
            last_error: r.last_error.clone(),
            last_error_at: r.last_error_at,
            degradation_reason: r.degradation,
            consecutive_failures: r.consecutive_failures,
            next_check_at: r.next_check_at,
            last_rotate_reason: self.last_rotate_reason.clone(),
            auto_disabled: self.auto_disabled,
            host: CONTROL_HOST.into(),
            port,
            proxy_url: port.map(slot::loopback_url),
            profile_id: profile.map(|p| p.id.clone()),
            profile_name: profile.map(|p| p.name.clone()),
            country: profile.and_then(|p| p.country.clone()),
            pid: self.live.as_ref().map(|l| l.pid),
            started_at: self.started_at.filter(|_| running),
            engine: self.live.as_ref().map(|l| l.kind),
            notice: self.live.as_ref().and_then(|l| l.notice.clone()),
        }
    }

    /// Shown in statuses and the snapshot: configured, auto-disabled (it keeps showing which
    /// profile died) or still running.
    pub fn is_listed(&self) -> bool {
        self.configured || self.auto_disabled || self.live.is_some()
    }

    /// The engine runs or is being (re)started: the profile is in use (B-8: a crashed slot
    /// does not hold its profile in the picker).
    pub fn is_active(&self) -> bool {
        self.live.is_some()
            || matches!(
                self.route.lifecycle,
                Lifecycle::Starting | Lifecycle::Rotating
            )
    }

    /// Whether a rotation with `key` already ran within the key TTL.
    pub fn rotated_with(&mut self, key: &str) -> bool {
        self.rotations
            .retain(|(_, at)| at.elapsed() < ROTATION_KEY_TTL);
        self.rotations.iter().any(|(k, _)| k == key)
    }

    /// Remembers a completed rotation key (the oldest goes first).
    pub fn remember_rotation(&mut self, key: String) {
        if self.rotations.len() >= ROTATION_KEYS {
            self.rotations.pop_front();
        }
        self.rotations.push_back((key, Instant::now()));
    }

    /// Forgets the rotation keys (explicit stop).
    pub fn forget_rotations(&mut self) {
        self.rotations.clear();
    }

    /// The engine of `generation`, unless a stop is already taking it down: the stop cancels the
    /// slot's tasks under the registry lock, so a probe result or an exit that lands in the
    /// meantime is dropped instead of overwriting the stopped state.
    pub fn live_of(&self, generation: u64) -> Option<&Live> {
        self.live
            .as_ref()
            .filter(|live| self.generation == generation && !live.cancel.is_cancelled())
    }

    /// Takes the live engine out and ends its tasks.
    pub fn take_live(&mut self) -> Option<Live> {
        let live = self.live.take();
        if let Some(live) = &live {
            live.cancel.cancel();
        }
        self.started_at = None;
        live
    }
}

/// Every slot.
#[derive(Default)]
pub(super) struct Registry {
    pub slots: BTreeMap<Slot, SlotState>,
    /// Set by `shutdown`: no new start.
    pub closed: bool,
}

impl Registry {
    /// The listed slots (see [`SlotState::is_listed`]) in slot order, readiness derived at `now`.
    pub fn instances(&self, now: UnixMs) -> Vec<InstanceStatus> {
        let mut list: Vec<InstanceStatus> = self
            .slots
            .iter()
            .filter(|(_, s)| s.is_listed())
            .map(|(slot, s)| s.instance(*slot))
            .collect();
        derive_readiness(&mut list, now);
        list
    }

    /// The status of `slot` given the derived `instances` (a slot not listed runs nothing, so
    /// it is never ready).
    pub fn instance(&self, slot: Slot, instances: &[InstanceStatus]) -> InstanceStatus {
        instances
            .iter()
            .find(|i| i.slot == slot)
            .cloned()
            .or_else(|| self.slots.get(&slot).map(|s| s.instance(slot)))
            .unwrap_or_else(|| InstanceStatus::stopped(slot))
    }

    /// Profiles of the configured slots other than `except`.
    pub fn used_profiles(&self, except: Option<Slot>) -> HashSet<String> {
        self.slots
            .iter()
            .filter(|(slot, s)| Some(**slot) != except && s.configured)
            .filter_map(|(_, s)| s.profile.as_ref().map(|p| p.id.clone()))
            .collect()
    }

    /// The configured slot other than `except` that listens on `port`.
    pub fn port_owner(&self, port: u16, except: Slot) -> Option<Slot> {
        self.slots
            .iter()
            .find(|(slot, s)| **slot != except && s.configured && s.port == Some(port))
            .map(|(slot, _)| *slot)
    }

    /// The lowest other slot that is a healthy route on `ip` at `now`: it keeps the IP and the
    /// slot whose probe found the duplicate is quarantined (spec 3.17).
    pub fn duplicate_keeper(&self, slot: Slot, ip: IpAddr, now: UnixMs) -> Option<Slot> {
        self.slots
            .iter()
            .find(|(other, s)| {
                **other != slot
                    && s.route.egress_ip == Some(ip)
                    && s.route.is_healthy(s.live.is_some(), now)
            })
            .map(|(other, _)| *other)
    }

    /// Whether a new route may be allocated on `slot` (3.23): nothing configured or running
    /// there, and its default port not taken by another slot's custom port.
    pub fn is_free(&self, slot: Slot) -> bool {
        let taken = self.slots.get(&slot).is_some_and(|s| {
            (s.configured && s.port.is_some() && s.profile.is_some()) || s.live.is_some()
        });
        !taken && self.port_owner(slot.default_port(), slot).is_none()
    }

    /// The lowest free slot not in `excluded`.
    pub fn first_free(&self, excluded: &HashSet<Slot>) -> Option<Slot> {
        Slot::all().find(|slot| !excluded.contains(slot) && self.is_free(*slot))
    }

    /// Whether a configured slot runs (or starts) `profile_id`, and the first configured slot of
    /// it whose engine is dead (a crashed or failed start).
    pub fn slots_of_profile(&self, profile_id: &str) -> (bool, Option<Slot>) {
        let mut dead = None;
        for (slot, state) in &self.slots {
            if !state.configured || state.profile.as_ref().is_none_or(|p| p.id != profile_id) {
                continue;
            }
            if state.is_active() {
                return (true, None);
            }
            dead.get_or_insert(*slot);
        }
        (false, dead)
    }
}
