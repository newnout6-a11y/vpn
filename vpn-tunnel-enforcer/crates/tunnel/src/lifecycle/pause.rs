//! The kill switch of the running session and its paused state (ks-a, research killswitch
//! §5.2-5.5): «Интернет на паузе: VPN переподключается…». The actor keeps them current; the app
//! shows them on the start page and in the tray.
use vpnte_base::types::{KillSwitchLevel, UnixMs};

/// What a drop does to the current session, decided when it connects.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionGuard {
    /// `Off`: programs go online directly when the VPN stops.
    pub level: KillSwitchLevel,
    /// Another VPN carries the default route (its label): this session never pauses.
    pub foreign_vpn: Option<String>,
}

impl SessionGuard {
    /// The guard of a new session at `level` (already [`KillSwitchLevel::effective`]): proxy
    /// mode holds only through the system proxy, so "Always" acts there as "If the VPN drops";
    /// against another full-tunnel VPN nothing pauses (two kill switches = no internet at all).
    pub fn new(level: KillSwitchLevel, soft: bool, foreign_vpn: Option<String>) -> Self {
        let level = match (level, &foreign_vpn) {
            (_, Some(_)) => KillSwitchLevel::Off,
            (KillSwitchLevel::Strict, None) if soft => KillSwitchLevel::Standard,
            (level, None) => level,
        };
        Self { level, foreign_vpn }
    }

    /// A drop of this session pauses the internet.
    pub fn pauses(&self) -> bool {
        self.level != KillSwitchLevel::Off
    }
}

/// The internet is paused: the VPN dropped by itself and the kill switch holds. Ends with a
/// reconnect, «Продолжить без VPN» (a disconnect), quit, or a change of the level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pause {
    pub since: UnixMs,
    /// The next automatic attempt; `None` while one runs, or when none is scheduled
    /// (auto-restart off: only «Подключить» retries).
    pub next_attempt: Option<UnixMs>,
    /// The server rejected the key: reconnecting will not help until the user acts.
    pub key_rejected: bool,
}

/// What the start page and the tray show about the kill switch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KillSwitchView {
    pub pause: Option<Pause>,
    /// The connected session does not pause because of this other VPN (one calm line).
    pub foreign_vpn: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ks-a (research 5.3 "another full-tunnel VPN"): no pause against it; proxy mode never
    /// holds "Always"; the tunnel keeps the level as it is in force.
    #[test]
    fn guard_of_a_new_session() {
        use KillSwitchLevel::{Off, Standard, Strict};
        let other = Some("Happ (10.10.0.2)".to_owned());
        assert_eq!(SessionGuard::new(Standard, true, other.clone()).level, Off);
        assert_eq!(SessionGuard::new(Strict, false, other).level, Off);
        assert_eq!(SessionGuard::new(Strict, true, None).level, Standard);
        assert_eq!(SessionGuard::new(Strict, false, None).level, Strict);
        assert!(SessionGuard::new(Standard, false, None).pauses());
        assert!(!SessionGuard::default().pauses());
    }
}
