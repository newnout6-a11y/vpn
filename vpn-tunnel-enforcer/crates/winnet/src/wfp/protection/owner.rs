//! Who keeps our filters, and so how long each set lives (research killswitch §3.1, §5.4, §5.7).
use vpnte_base::types::KillSwitchLevel;

use crate::wfp::engine::Lifetime;

/// The process that owns our WFP objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// The app run as administrator: everything lives in a dynamic session (an app crash gives
    /// the internet back; its engines die with it anyway), and "Always" is not offered: nothing
    /// could hold it at boot without leaving filters nobody owns.
    App,
    /// The helper service of this Windows service name: "If the VPN drops" is static (a crashed
    /// service is restarted by Windows within seconds and finds its block; a reboot clears it),
    /// "Always" is persistent under a provider registered with the name, so BFE enforces it at
    /// boot only while the service starts automatically.
    Service(String),
}

impl Owner {
    /// "Always" can be kept safe: only the service holds it across exits and reboots.
    pub fn keeps_always(&self) -> bool {
        matches!(self, Self::Service(_))
    }

    /// The Windows service our provider is registered with (`FWPM_PROVIDER0.serviceName`).
    pub fn service_name(&self) -> Option<&str> {
        match self {
            Self::App => None,
            Self::Service(name) => Some(name),
        }
    }

    /// The lifetime of the per-session set (permits, DNS block, "If the VPN drops" block).
    pub fn session_lifetime(&self) -> Lifetime {
        match self {
            Self::App => Lifetime::Dynamic,
            Self::Service(_) => Lifetime::Static,
        }
    }

    /// The lifetime of the block-all set the stored `level` gets here; `None` = nothing blocks.
    pub fn block_lifetime(&self, level: KillSwitchLevel) -> Option<Lifetime> {
        match level.effective(self.keeps_always()) {
            KillSwitchLevel::Off => None,
            KillSwitchLevel::Standard => Some(self.session_lifetime()),
            KillSwitchLevel::Strict => Some(Lifetime::Persistent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ks-d (research killswitch §5.4, §5.7): one row per level and owner. An app run as
    /// administrator never leaves anything behind its process; the service's "If the VPN drops"
    /// outlives a service crash but not a reboot; "Always" exists only in the service.
    #[test]
    fn lifetime_per_level_and_owner() {
        use KillSwitchLevel::{Off, Standard, Strict};
        let app = Owner::App;
        let service = Owner::Service("VpnTunnelEnforcerService".into());
        assert_eq!(app.block_lifetime(Off), None);
        assert_eq!(app.block_lifetime(Standard), Some(Lifetime::Dynamic));
        assert_eq!(
            app.block_lifetime(Strict),
            Some(Lifetime::Dynamic),
            "no Always in the app"
        );
        assert_eq!(service.block_lifetime(Off), None);
        assert_eq!(service.block_lifetime(Standard), Some(Lifetime::Static));
        assert_eq!(service.block_lifetime(Strict), Some(Lifetime::Persistent));
        assert_eq!(app.session_lifetime(), Lifetime::Dynamic);
        assert_eq!(service.session_lifetime(), Lifetime::Static);
        assert_eq!(app.service_name(), None);
        assert_eq!(service.service_name(), Some("VpnTunnelEnforcerService"));
        assert!(service.keeps_always() && !app.keeps_always());
    }
}
