//! One stored schedule: when it runs, and what it turns on. What it turns on is two separate
//! choices (NOADMIN §2): how the traffic is taken ([`Capture`]) and where it goes ([`Upstream`]).
use serde::{Deserialize, Serialize};

use super::HhMm;

/// How a schedule takes the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capture {
    /// The TUN adapter (Hard): needs the app started as administrator.
    Tun,
    /// The per-user system proxy in front of a loopback engine (Soft): no rights needed.
    Proxy,
}

/// Where a schedule's traffic goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Upstream {
    /// The local proxy a manual connect would use (settings override, else detection).
    LocalProxy,
    /// The server `profile_id` of the list.
    Server,
}

/// The old one-word mode: records written before capture and upstream were stored apart, and
/// the old app's `scheduler.json`. It maps 1:1 onto the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleMode {
    /// TUN through the local proxy.
    Hard,
    /// System proxy through the local proxy.
    Soft,
    /// TUN through `profile_id`.
    Direct,
}

impl ScheduleMode {
    /// The capture and upstream this mode meant.
    pub fn split(self) -> (Capture, Upstream) {
        match self {
            ScheduleMode::Hard => (Capture::Tun, Upstream::LocalProxy),
            ScheduleMode::Soft => (Capture::Proxy, Upstream::LocalProxy),
            ScheduleMode::Direct => (Capture::Tun, Upstream::Server),
        }
    }
}

/// One weekly window: on each of `days` from `start_time` to `end_time` (overnight when
/// `end_time < start_time`, 24 hours when they are equal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "Stored")]
pub struct ScheduleEntry {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Weekdays of the window's START, 0 = Sunday … 6 = Saturday; sorted, no duplicates.
    pub days: Vec<u8>,
    pub start_time: HhMm,
    pub end_time: HhMm,
    /// Server profile; used only with [`Upstream::Server`] (fix S6).
    #[serde(default)]
    pub profile_id: String,
    pub capture: Capture,
    pub upstream: Upstream,
}

/// The stored shape as read: `capture` + `upstream`, or only the old `mode`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    id: String,
    name: String,
    enabled: bool,
    days: Vec<u8>,
    start_time: HhMm,
    end_time: HhMm,
    #[serde(default)]
    profile_id: String,
    #[serde(default)]
    capture: Option<Capture>,
    #[serde(default)]
    upstream: Option<Upstream>,
    #[serde(default)]
    mode: Option<ScheduleMode>,
}

impl TryFrom<Stored> for ScheduleEntry {
    type Error = &'static str;

    fn try_from(s: Stored) -> Result<Self, Self::Error> {
        let (capture, upstream) = match (s.capture, s.upstream, s.mode) {
            (Some(capture), Some(upstream), _) => (capture, upstream),
            (None, None, Some(mode)) => mode.split(),
            _ => return Err("a schedule needs capture and upstream (or the old mode)"),
        };
        Ok(ScheduleEntry {
            id: s.id,
            name: s.name,
            enabled: s.enabled,
            days: s.days,
            start_time: s.start_time,
            end_time: s.end_time,
            profile_id: s.profile_id,
            capture,
            upstream,
        })
    }
}
