//! The capability view: what the helper service and this process's rights allow right now.

/// The helper service as the app finds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Service {
    /// Not installed: proxy mode works, the privileged features come with the service.
    #[default]
    Missing,
    /// Installed and as new as the app (or its version is not known yet: no link so far).
    Installed,
    /// Installed but older than the app: what it does not do yet. It updates itself.
    Older { lacks: Vec<Lack> },
}

/// What an older helper service does not do yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lack {
    /// «Только выбранные приложения» in Tunnel mode: it routes every app through the VPN.
    AppScope,
}

/// How a privileged feature runs here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ability {
    /// Through the helper service.
    Service,
    /// In this process: the app was started as administrator (development, CI).
    InProcess,
    /// Comes with the helper service, which is not installed.
    #[default]
    NeedsService,
    /// Not in this version: neither the app nor the service carries it here.
    NotInVersion,
}

impl Ability {
    /// The feature runs now (through the service or in this process).
    pub const fn works(self) -> bool {
        matches!(self, Self::Service | Self::InProcess)
    }
}

/// A privileged feature a page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Tunnel mode (TUN capture of every program).
    Tunnel,
    /// The WFP kill switch: its filters, leak protection and exceptions («Всегда» included).
    KillSwitch,
    /// Machine-wide browser policies (WebRTC hardening under HKLM).
    Policies,
    /// Packet capture (pktmon / ETW).
    Capture,
}

/// One capability view, pushed by the app at start, after an install from the app and when the
/// service's version becomes known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capability {
    pub service: Service,
    /// The app process runs elevated (development, CI; the shipped app never elevates).
    pub elevated: bool,
    pub tunnel: Ability,
    pub kill_switch: Ability,
    pub policies: Ability,
    pub capture: Ability,
}

impl Capability {
    /// How `feature` runs here.
    pub const fn ability(&self, feature: Feature) -> Ability {
        match feature {
            Feature::Tunnel => self.tunnel,
            Feature::KillSwitch => self.kill_switch,
            Feature::Policies => self.policies,
            Feature::Capture => self.capture,
        }
    }

    /// What the installed service does not do yet (empty unless it is older than the app).
    pub fn lacks(&self) -> &[Lack] {
        match &self.service {
            Service::Older { lacks } => lacks,
            Service::Missing | Service::Installed => &[],
        }
    }
}

impl Feature {
    /// Stable id for markup and tests.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Tunnel => "tunnel",
            Self::KillSwitch => "kill-switch",
            Self::Policies => "policies",
            Self::Capture => "capture",
        }
    }
}

impl Lack {
    /// Stable id for markup and tests.
    pub const fn id(self) -> &'static str {
        match self {
            Self::AppScope => "app-scope",
        }
    }
}
