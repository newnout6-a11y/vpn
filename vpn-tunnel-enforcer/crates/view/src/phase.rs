//! The dashboard's four-state phase: derived by `swiss::swiss_phase` from the slab state and fed
//! to the mascot as `MascotEvent::Phase` (one type for both sides).

/// Phase derived by the dashboard: `On` = SECURE or VERIFY, `Alert` = a hazard word (LEAK, ALERT,
/// BLOCKED, DEGRADED; a faulted tunnel alerts even when it is not up), `Connecting` = anything in
/// flight, `Off` = EXPOSED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MascotPhase {
    On,
    Off,
    Connecting,
    Alert,
}
