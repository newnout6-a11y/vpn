//! The mascot's inbox: what the rest of the UI tells him (tunnel facts, hovers, leak results, proxy
//! actions, notices). A cheap clonable handle around a broadcast channel; it also remembers the
//! latest tunnel facts so a host that mounts later (or remounts) starts from the truth instead of
//! "celebrating" a tunnel that was already up.
use std::sync::{Arc, Mutex, PoisonError};

use dioxus::prelude::*;
use tokio::sync::broadcast;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_view::fmt::elapsed;
use vpnte_view::mascot::{MascotEvent, MascotPhase};

/// Room for bursts (a page action plus a few pointer reports) between two host wake-ups.
const CAPACITY: usize = 64;

/// The latest tunnel and page facts, replayed into a freshly created brain.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Facts {
    pub phase: Option<MascotPhase>,
    pub band: f32,
    pub session_started: Option<UnixMs>,
    pub page_active: bool,
}

/// Handle to the mascot's event channel. Clone it freely; provide one per app with
/// [`use_mascot_bus_provider`] above both the [`MascotHost`](super::MascotHost) and the senders.
#[derive(Clone)]
pub struct MascotBus {
    tx: broadcast::Sender<MascotEvent>,
    facts: Arc<Mutex<Facts>>,
}

impl PartialEq for MascotBus {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.facts, &other.facts)
    }
}

impl Default for MascotBus {
    fn default() -> Self {
        Self::new()
    }
}

impl MascotBus {
    /// A new bus with nobody listening yet.
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(CAPACITY).0,
            facts: Arc::new(Mutex::new(Facts {
                phase: None,
                band: 0.0,
                session_started: None,
                page_active: true,
            })),
        }
    }

    /// Delivers any event to the mounted host (dropped when none is mounted). `Phase`, `SpeedBand`
    /// and `PageActive` are also remembered for a host that starts later.
    pub fn send(&self, ev: MascotEvent) {
        self.update(|f| match ev {
            MascotEvent::Phase(p) => f.phase = Some(p),
            MascotEvent::SpeedBand(b) => f.band = b,
            MascotEvent::PageActive(a) => f.page_active = a,
            _ => {}
        });
        // An error only means no host is listening right now.
        let _ = self.tx.send(ev);
    }

    /// The dashboard's derived phase (`swiss::swiss_phase`). Idempotent: cheap to call on every
    /// render, only a change is delivered.
    pub fn phase(&self, phase: MascotPhase) {
        if self.update(|f| f.phase.replace(phase) != Some(phase)) {
            let _ = self.tx.send(MascotEvent::Phase(phase));
        }
    }

    /// Download speed band (`traffic::speed_band`). Idempotent.
    pub fn speed_band(&self, band: f32) {
        if self.update(|f| std::mem::replace(&mut f.band, band) != band) {
            let _ = self.tx.send(MascotEvent::SpeedBand(band));
        }
    }

    /// Start of the running tunnel session (`conn.started_at`), `None` without one. Idempotent;
    /// a change is delivered as the session's age now.
    pub fn session_started(&self, at: Option<UnixMs>) {
        if self.update(|f| std::mem::replace(&mut f.session_started, at) != at) {
            let _ = self.tx.send(MascotEvent::SessionAge(session_age(at)));
        }
    }

    /// The dashboard is / is not the active page (`use_page_active`). Idempotent.
    pub fn page_active(&self, active: bool) {
        if self.update(|f| std::mem::replace(&mut f.page_active, active) != active) {
            let _ = self.tx.send(MascotEvent::PageActive(active));
        }
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<MascotEvent> {
        self.tx.subscribe()
    }

    pub(super) fn facts(&self) -> Facts {
        *self.facts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn update<R>(&self, f: impl FnOnce(&mut Facts) -> R) -> R {
        f(&mut self.facts.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Age of a session started at `at`, measured now.
pub(super) fn session_age(at: Option<UnixMs>) -> Option<std::time::Duration> {
    at.map(|t| elapsed(t, now_ms()))
}

/// Creates a bus and provides it to the calling component's descendants: call it in the app root
/// (or in the dashboard root when the host is rendered inside the dashboard).
pub fn use_mascot_bus_provider() -> MascotBus {
    use_context_provider(MascotBus::new)
}

/// The bus provided above the caller. Without a provider the caller gets a detached bus (its
/// events go nowhere) and a warning in the log.
pub fn use_mascot_bus() -> MascotBus {
    use_hook(|| {
        try_consume_context::<MascotBus>().unwrap_or_else(|| {
            tracing::warn!("no MascotBus provider above this component; mascot events are dropped");
            MascotBus::new()
        })
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::broadcast::error::TryRecvError;

    use super::*;

    fn drain(rx: &mut broadcast::Receiver<MascotEvent>) -> Vec<MascotEvent> {
        let mut out = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(ev) => out.push(ev),
                Err(TryRecvError::Empty | TryRecvError::Closed) => return out,
                Err(TryRecvError::Lagged(_)) => {}
            }
        }
    }

    #[test]
    fn state_helpers_deliver_only_changes_and_remember_them() {
        let bus = MascotBus::new();
        let mut rx = bus.subscribe();
        bus.phase(MascotPhase::On);
        bus.phase(MascotPhase::On);
        bus.speed_band(80.0);
        bus.speed_band(80.0);
        bus.page_active(true); // the default: no change
        bus.page_active(false);
        let got = drain(&mut rx);
        let want = [
            MascotEvent::Phase(MascotPhase::On),
            MascotEvent::SpeedBand(80.0),
            MascotEvent::PageActive(false),
        ];
        assert_eq!(got, want);
        let facts = bus.facts();
        assert_eq!(facts.phase, Some(MascotPhase::On));
        assert_eq!(facts.band, 80.0);
        assert!(!facts.page_active);
    }

    #[test]
    fn raw_events_are_delivered_and_state_ones_recorded() {
        let bus = MascotBus::new();
        let mut rx = bus.subscribe();
        bus.send(MascotEvent::Phase(MascotPhase::Alert));
        bus.send(MascotEvent::Poke);
        bus.send(MascotEvent::Poke);
        assert_eq!(
            drain(&mut rx).len(),
            3,
            "discrete events are never deduplicated"
        );
        assert_eq!(bus.facts().phase, Some(MascotPhase::Alert));
        // A later state call with the recorded value is a no-op.
        bus.phase(MascotPhase::Alert);
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn session_start_is_delivered_as_its_age() {
        let bus = MascotBus::new();
        let mut rx = bus.subscribe();
        let start = now_ms() - 5_000;
        bus.session_started(Some(start));
        bus.session_started(Some(start));
        bus.session_started(None);
        let got = drain(&mut rx);
        assert_eq!(got.len(), 2);
        match got[0] {
            MascotEvent::SessionAge(Some(age)) => {
                assert!(
                    age >= Duration::from_secs(5) && age < Duration::from_secs(60),
                    "{age:?}"
                );
            }
            ref other => panic!("unexpected {other:?}"),
        }
        assert_eq!(got[1], MascotEvent::SessionAge(None));
        assert_eq!(bus.facts().session_started, None);
    }

    #[test]
    fn sending_without_a_host_is_harmless_and_clones_share_state() {
        let bus = MascotBus::new();
        let other = bus.clone();
        bus.send(MascotEvent::LeakStart);
        other.phase(MascotPhase::Connecting);
        assert_eq!(bus.facts().phase, Some(MascotPhase::Connecting));
        assert!(bus == other);
        assert!(bus != MascotBus::new());
    }
}
