//! The public-IP monitor: one evidence store (adopted VPN exit, the user's home IP, the latest
//! sample, the verdict) and the periodic task that keeps it current.
//!
//! Field lessons kept from the old monitor:
//! - a different exit than the baseline is NOT a leak (rotation, anycast, split routes): it is
//!   `Indeterminate` and gets verified independently (leak self-test + family-pinned rebaseline);
//! - the one thing a public-IP read can prove is the user's real ISP address showing up while
//!   connected: that is `Failed` (B-IP-1), and such a sample is never adopted as baseline (B-IP-2);
//! - a read that fails is `NotChecked`, never a reused cached verdict (B-IP-7);
//! - during a protected transition (stop, profile swap) reads are aborted and the monitor stays
//!   silent, otherwise the user's real IP read while tearing down would raise a false alarm;
//!   only the tunnel suspends it, through an RAII guard (B-IP-8);
//! - rebaselines are serialised: two concurrent adopters would race on the baseline.
mod monitor;

use std::net::IpAddr;
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Verdict;
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::public_ip::{Family, IpReader, IpRoute, IpSample, WAVE_BUDGET};

pub use monitor::{IpMonitor, SuspendGuard, VerifyEnv, VerifyOutcome};

/// Identifies one tunnel connection (any value the tunnel never reuses).
pub type ConnId = u64;

/// Default period of the background read.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
/// Allowed period range (settings field in seconds, 5–300).
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);
/// See [`MIN_INTERVAL`].
pub const MAX_INTERVAL: Duration = Duration::from_secs(300);

/// What the latest public-IP read says about the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpVerdict {
    /// The read through the tunnel shows the adopted VPN exit.
    Passed,
    /// Another exit than the adopted one: not proof of a leak, to be verified.
    Indeterminate,
    /// No baseline yet, the read failed, or the monitor is stopped.
    #[default]
    NotChecked,
    /// The read shows the user's real (pre-connect) public IP.
    Failed,
}

impl IpVerdict {
    /// The app-wide verdict scale (`Indeterminate` is a warning, never `Ok`).
    pub fn verdict(self) -> Verdict {
        match self {
            IpVerdict::Passed => Verdict::Ok,
            IpVerdict::Indeterminate => Verdict::Warn,
            IpVerdict::NotChecked => Verdict::NotChecked,
            IpVerdict::Failed => Verdict::Fail,
        }
    }

    /// Short user-facing label.
    pub fn label(self) -> Msg {
        Msg::new(match self {
            IpVerdict::Passed => "probes.ip.verdict.passed",
            IpVerdict::Indeterminate => "probes.ip.verdict.indeterminate",
            IpVerdict::NotChecked => "probes.ip.verdict.notChecked",
            IpVerdict::Failed => "probes.ip.verdict.failed",
        })
    }
}

/// Verdict of one sample: equal to the baseline → `Passed`; equal to the user's real IP (and
/// not the baseline) → `Failed`; no baseline → `NotChecked`; any other exit → `Indeterminate`.
pub fn verdict(sample: IpAddr, baseline: Option<IpAddr>, real_ip: Option<IpAddr>) -> IpVerdict {
    if baseline == Some(sample) {
        IpVerdict::Passed
    } else if real_ip == Some(sample) {
        IpVerdict::Failed
    } else if baseline.is_none() {
        IpVerdict::NotChecked
    } else {
        IpVerdict::Indeterminate
    }
}

/// Snapshot of the monitor for the UI, the tray and the tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEvidence {
    /// Adopted VPN exit of the current connection.
    pub baseline: Option<IpAddr>,
    /// The user's public IP measured before the tunnel came up (home IP).
    pub real_ip: Option<IpAddr>,
    /// Latest successful read; may be older than the latest attempt (see `fresh`).
    pub last: Option<IpSample>,
    /// True when the latest attempt produced `last`.
    pub fresh: bool,
    pub verdict: IpVerdict,
}

impl IpEvidence {
    /// Equal for subscribers: everything but the time and provider of the same address.
    fn same_view(&self, other: &IpEvidence) -> bool {
        self.baseline == other.baseline
            && self.real_ip == other.real_ip
            && self.last.map(|s| s.ip) == other.last.map(|s| s.ip)
            && self.fresh == other.fresh
            && self.verdict == other.verdict
    }
}

/// Source of public-IP samples: the provider race in production, a script in tests.
pub trait Sampler: Send + Sync + 'static {
    /// One read of `family` over `route` (see [`IpReader::wave`]).
    fn sample<'a>(
        &'a self,
        route: &'a IpRoute,
        family: Family,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>>;
}

impl Sampler for IpReader {
    fn sample<'a>(
        &'a self,
        route: &'a IpRoute,
        family: Family,
        cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>> {
        self.wave(route, family, WAVE_BUDGET, cancel).boxed()
    }
}

/// Why a baseline was not adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdoptError {
    #[error("no provider answered")]
    NoSample,
    #[error("the sample differs from the expected exit")]
    Mismatch { seen: IpAddr },
    #[error("the sample is the user's real IP")]
    RealIp,
    #[error("cancelled")]
    Cancelled,
    #[error("the connection or the read went stale")]
    Stale,
}

impl From<AdoptError> for AppError {
    fn from(err: AdoptError) -> Self {
        match err {
            AdoptError::Cancelled => AppError::cancelled(),
            AdoptError::NoSample => {
                AppError::msg(ErrorKind::Network, Msg::new("probes.ip.adopt.noSample"))
            }
            AdoptError::Mismatch { .. } => AppError::conflict(Msg::new("probes.ip.adopt.mismatch")),
            AdoptError::RealIp => AppError::conflict(Msg::new("probes.ip.adopt.realIp")),
            AdoptError::Stale => AppError::conflict(Msg::new("probes.ip.adopt.stale")),
        }
    }
}

#[cfg(test)]
mod tests;
